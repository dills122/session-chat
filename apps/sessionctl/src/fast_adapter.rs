//! Explicit two-computer evidence harness for the connected Iroh Fast adapter.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use session_transport::{DispatchControl, OperationBudget};
use transport_conformance::{
    CONNECTED_DELIVERY_CONFORMANCE_REQUESTS_V1, run_connected_delivery_conformance_v1,
};
use transport_iroh::{
    FastMailboxAuthorities, FastMailboxPolicy, FastPathClass, FastPathSnapshot, IrohFastDelivery,
    IrohFastEndpoint, IrohFastMailboxService, MAX_FAST_ENVELOPES_PER_MAILBOX, MAX_FAST_FRAME_BYTES,
    MAX_FAST_LIVE_MAILBOXES, MAX_FAST_MAILBOX_LIFETIME_SECONDS, MAX_FAST_OPERATOR_HANDOFF_BYTES,
    MAX_FAST_RETAINED_BYTES_PER_MAILBOX,
};
use zeroize::Zeroizing;

use crate::{SessionCtlError, stage};

const NETWORK_OPERATION_WAIT: Duration = Duration::from_secs(30);
const OPERATOR_HANDOFF_WAIT: Duration = Duration::from_secs(5 * 60);
const MAILBOX_LIFETIME_SECONDS: u64 = 10 * 60;
const OPERATION_NETWORK_BYTES: u64 = 512 * 1024;

/// Explicit path policy for a public Fast adapter evidence run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FastAdapterPathMode {
    /// Permit Iroh to select a direct or relay path.
    Auto,
    /// Remove direct IP transports so application data can use only an N0 relay.
    RelayOnly,
}

impl FastAdapterPathMode {
    /// Parses the exact CLI label.
    pub fn parse(value: &str) -> Result<Self, SessionCtlError> {
        match value {
            "auto" => Ok(Self::Auto),
            "relay-only" => Ok(Self::RelayOnly),
            _ => Err(stage("Fast adapter path mode")),
        }
    }

    /// Returns the stable evidence label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::RelayOnly => "relay-only",
        }
    }

    async fn bind(self) -> Result<IrohFastEndpoint, SessionCtlError> {
        map_stage(
            match self {
                Self::Auto => IrohFastEndpoint::bind_public().await,
                Self::RelayOnly => IrohFastEndpoint::bind_public_relay_only().await,
            },
            "Fast adapter endpoint",
        )
    }

    fn require(self, snapshot: FastPathSnapshot) -> Result<(), SessionCtlError> {
        if self.accepts(snapshot.selected(), snapshot.direct_available()) {
            Ok(())
        } else {
            Err(stage("Fast adapter selected path"))
        }
    }

    fn accepts(self, selected: FastPathClass, direct_available: bool) -> bool {
        match self {
            Self::Auto => matches!(selected, FastPathClass::Direct | FastPathClass::Relay),
            Self::RelayOnly => selected == FastPathClass::Relay && !direct_available,
        }
    }
}

/// Address-free outcome from one common-contract adapter run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FastAdapterRunReport {
    initial_path: FastPathSnapshot,
    final_path: FastPathSnapshot,
}

impl FastAdapterRunReport {
    /// Returns the path snapshot immediately after connection setup.
    #[must_use]
    pub const fn initial_path(self) -> FastPathSnapshot {
        self.initial_path
    }

    /// Returns the path snapshot after all common-contract operations.
    #[must_use]
    pub const fn final_path(self) -> FastPathSnapshot {
        self.final_path
    }
}

struct LiveDispatchControl {
    wall_now_unix_seconds: u64,
}

impl DispatchControl for LiveDispatchControl {
    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        Some(self.wall_now_unix_seconds)
    }

    fn is_cancelled(&self) -> bool {
        false
    }
}

struct AuthorityFileGuard {
    published: Option<PathBuf>,
    temporary: Option<PathBuf>,
}

impl AuthorityFileGuard {
    fn create(path: PathBuf, bytes: &[u8]) -> Result<Self, SessionCtlError> {
        validate_new_handoff_path(&path)?;
        let temporary = path.with_extension("partial");
        validate_new_handoff_path(&temporary)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = map_stage(options.open(&temporary), "Fast adapter handoff create")?;
        let mut guard = Self {
            published: None,
            temporary: Some(temporary.clone()),
        };
        map_stage(file.write_all(bytes), "Fast adapter handoff write")?;
        map_stage(file.sync_all(), "Fast adapter handoff sync")?;
        drop(file);
        map_stage(
            fs::hard_link(&temporary, &path),
            "Fast adapter handoff publish",
        )?;
        guard.published = Some(path);
        map_stage(fs::remove_file(&temporary), "Fast adapter handoff finalize")?;
        guard.temporary = None;
        Ok(guard)
    }

    fn remove(&mut self) -> Result<(), SessionCtlError> {
        remove_guarded_path(&mut self.published)?;
        remove_guarded_path(&mut self.temporary)?;
        Ok(())
    }
}

impl Drop for AuthorityFileGuard {
    fn drop(&mut self) {
        let _ = remove_guarded_path(&mut self.published);
        let _ = remove_guarded_path(&mut self.temporary);
    }
}

/// Hosts one volatile mailbox and serves the shared connected-delivery case.
pub async fn run_fast_adapter_host(
    mode: FastAdapterPathMode,
    authority_path: PathBuf,
) -> Result<(), SessionCtlError> {
    validate_new_handoff_path(&authority_path)?;
    let endpoint = mode.bind().await?;
    map_stage(
        endpoint.wait_online(NETWORK_OPERATION_WAIT).await,
        "Fast adapter host online",
    )?;
    run_fast_adapter_host_with_endpoint(mode, authority_path, endpoint).await
}

async fn run_fast_adapter_host_with_endpoint(
    mode: FastAdapterPathMode,
    authority_path: PathBuf,
    endpoint: IrohFastEndpoint,
) -> Result<(), SessionCtlError> {
    let now = unix_now()?;
    let expires_at = now
        .checked_add(MAILBOX_LIFETIME_SECONDS)
        .ok_or_else(|| stage("Fast adapter mailbox expiry"))?;
    let mut service = IrohFastMailboxService::new(mailbox_policy()?);
    let authorities = map_stage(
        service.issue_mailbox(endpoint.id(), expires_at, now),
        "Fast adapter mailbox issue",
    )?;
    let encoded = map_stage(
        authorities.encode_operator_handoff_v1(),
        "Fast adapter handoff encode",
    )?;
    let mut authority_file = AuthorityFileGuard::create(authority_path.clone(), &encoded)?;
    drop(authorities);
    println!(
        "mode=fast-adapter-host\nprofile=fast-v1\nrequested_path={}\nmetadata=peer-or-relay-addresses-timing-volume\nendpoint={}\nauthority_handoff=ready",
        mode.as_str(),
        endpoint.id().as_text()
    );

    let link = map_stage(
        endpoint
            .accept(None, OPERATOR_HANDOFF_WAIT, MAX_FAST_FRAME_BYTES)
            .await,
        "Fast adapter host accept",
    )?;
    let initial = link.path_snapshot();
    mode.require(initial)?;
    print_path("initial", initial);
    map_stage(
        service
            .serve_requests(
                link,
                CONNECTED_DELIVERY_CONFORMANCE_REQUESTS_V1,
                NETWORK_OPERATION_WAIT,
            )
            .await,
        "Fast adapter mailbox service",
    )?;
    authority_file.remove()?;
    println!("mode=fast-adapter-host\nstatus=complete");
    Ok(())
}

/// Joins a public host and runs the shared common delivery contract remotely.
pub async fn run_fast_adapter_join(
    mode: FastAdapterPathMode,
    authority_path: PathBuf,
) -> Result<FastAdapterRunReport, SessionCtlError> {
    let now = unix_now()?;
    let authorities = load_authorities(&authority_path, now)?;
    let server = authorities.server_id();
    let endpoint = mode.bind().await?;
    map_stage(
        endpoint.wait_online(NETWORK_OPERATION_WAIT).await,
        "Fast adapter join online",
    )?;
    let link = map_stage(
        endpoint
            .connect_public(server, NETWORK_OPERATION_WAIT, MAX_FAST_FRAME_BYTES)
            .await,
        "Fast adapter connect",
    )?;
    run_fast_adapter_client_with_link(mode, authorities, link, now).await
}

async fn run_fast_adapter_client_with_link(
    mode: FastAdapterPathMode,
    authorities: FastMailboxAuthorities,
    link: transport_iroh::IrohFastLink,
    now: u64,
) -> Result<FastAdapterRunReport, SessionCtlError> {
    let initial_path = link.path_snapshot();
    mode.require(initial_path)?;
    print_path("initial", initial_path);
    let mut delivery = map_stage(IrohFastDelivery::new(link), "Fast adapter binding")?;
    let (deposit, receive, acknowledgement) = authorities.into_dispatch_parts();
    let control = LiveDispatchControl {
        wall_now_unix_seconds: now,
    };
    map_stage(
        run_connected_delivery_conformance_v1(
            &mut delivery,
            &deposit,
            &receive,
            &acknowledgement,
            now,
            &control,
            operation_budget,
        )
        .await,
        "Fast adapter common contract",
    )?;
    let final_path = delivery.path_snapshot();
    mode.require(final_path)?;
    print_path("final", final_path);
    map_stage(
        delivery.close(NETWORK_OPERATION_WAIT).await,
        "Fast adapter join close",
    )?;
    println!(
        "mode=fast-adapter-join\nprofile=fast-v1\nrequested_path={}\ncontract=connected-delivery-v1\nbyte_identity=pass\nstatus=complete",
        mode.as_str()
    );
    Ok(FastAdapterRunReport {
        initial_path,
        final_path,
    })
}

/// Runs the same harness over a relay-free local Iroh connection.
pub async fn run_fast_adapter_loopback_demo() -> Result<FastAdapterRunReport, SessionCtlError> {
    let now = unix_now()?;
    let authority_path = fresh_handoff_path()?;
    let host = map_stage(
        IrohFastEndpoint::bind_loopback().await,
        "Fast adapter loopback host",
    )?;
    let host_address = host.address();
    let host_authority_path = authority_path.clone();
    let service_task = tokio::spawn(async move {
        run_fast_adapter_host_with_endpoint(FastAdapterPathMode::Auto, host_authority_path, host)
            .await
    });
    wait_for_handoff(&authority_path).await?;
    let authorities = load_authorities(&authority_path, now)?;
    let client = map_stage(
        IrohFastEndpoint::bind_loopback().await,
        "Fast adapter loopback client",
    )?;
    let link = map_stage(
        client
            .connect_address(host_address, NETWORK_OPERATION_WAIT, MAX_FAST_FRAME_BYTES)
            .await,
        "Fast adapter loopback connect",
    )?;
    let report =
        run_fast_adapter_client_with_link(FastAdapterPathMode::Auto, authorities, link, now)
            .await?;
    map_stage(service_task.await, "Fast adapter loopback service task")??;
    if authority_path.exists() {
        return Err(stage("Fast adapter loopback handoff cleanup"));
    }
    Ok(report)
}

fn mailbox_policy() -> Result<FastMailboxPolicy, SessionCtlError> {
    map_stage(
        FastMailboxPolicy::new(
            MAX_FAST_MAILBOX_LIFETIME_SECONDS,
            MAX_FAST_LIVE_MAILBOXES,
            MAX_FAST_ENVELOPES_PER_MAILBOX,
            MAX_FAST_RETAINED_BYTES_PER_MAILBOX,
        ),
        "Fast adapter mailbox policy",
    )
}

fn operation_budget() -> OperationBudget {
    OperationBudget::new(
        Instant::now() + NETWORK_OPERATION_WAIT,
        OPERATION_NETWORK_BYTES,
        1,
    )
    .expect("fixed Fast adapter evidence budget is valid")
}

fn unix_now() -> Result<u64, SessionCtlError> {
    map_stage(
        SystemTime::now().duration_since(UNIX_EPOCH),
        "Fast adapter system clock",
    )
    .map(|duration| duration.as_secs())
}

fn print_path(point: &str, snapshot: FastPathSnapshot) {
    println!(
        "path_observation={point}\nselected_path={}\ndirect_available={}\nrelay_available={}\ncustom_available={}",
        snapshot.selected().as_str(),
        snapshot.direct_available(),
        snapshot.relay_available(),
        snapshot.custom_available()
    );
}

fn validate_new_handoff_path(path: &Path) -> Result<(), SessionCtlError> {
    if !path.is_absolute()
        || path.as_os_str().len() > 4_096
        || path.exists()
        || path.parent().is_none_or(|parent| !parent.is_dir())
    {
        return Err(stage("Fast adapter handoff path"));
    }
    Ok(())
}

fn read_handoff(path: &Path) -> Result<Zeroizing<Vec<u8>>, SessionCtlError> {
    if !path.is_absolute() || path.as_os_str().len() > 4_096 {
        return Err(stage("Fast adapter handoff path"));
    }
    let before = map_stage(fs::symlink_metadata(path), "Fast adapter handoff metadata")?;
    if !before.file_type().is_file()
        || before.len() == 0
        || before.len() > MAX_FAST_OPERATOR_HANDOFF_BYTES as u64
    {
        return Err(stage("Fast adapter handoff file"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = map_stage(options.open(path), "Fast adapter handoff read")?;
    let after = map_stage(file.metadata(), "Fast adapter handoff metadata")?;
    if !after.file_type().is_file() || after.len() != before.len() {
        return Err(stage("Fast adapter handoff file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(stage("Fast adapter handoff file"));
        }
    }
    read_bounded(file)
}

fn load_authorities(
    path: &Path,
    now_unix_seconds: u64,
) -> Result<FastMailboxAuthorities, SessionCtlError> {
    let encoded = read_handoff(path)?;
    map_stage(
        FastMailboxAuthorities::decode_operator_handoff_v1(&encoded, now_unix_seconds),
        "Fast adapter handoff decode",
    )
}

async fn wait_for_handoff(path: &Path) -> Result<(), SessionCtlError> {
    let deadline = Instant::now()
        .checked_add(NETWORK_OPERATION_WAIT)
        .ok_or_else(|| stage("Fast adapter handoff wait"))?;
    loop {
        if path.is_file() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(stage("Fast adapter handoff wait"));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn fresh_handoff_path() -> Result<PathBuf, SessionCtlError> {
    let nonce = map_stage(
        SystemTime::now().duration_since(UNIX_EPOCH),
        "Fast adapter handoff clock",
    )?
    .as_nanos();
    Ok(std::env::temp_dir().join(format!(
        "session-chat-fast-{}-{nonce}.v1",
        std::process::id()
    )))
}

fn read_bounded(file: File) -> Result<Zeroizing<Vec<u8>>, SessionCtlError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_FAST_OPERATOR_HANDOFF_BYTES));
    map_stage(
        file.take((MAX_FAST_OPERATOR_HANDOFF_BYTES + 1) as u64)
            .read_to_end(&mut bytes),
        "Fast adapter handoff read",
    )?;
    if bytes.is_empty() || bytes.len() > MAX_FAST_OPERATOR_HANDOFF_BYTES {
        return Err(stage("Fast adapter handoff bound"));
    }
    Ok(bytes)
}

fn map_stage<T, E>(result: Result<T, E>, name: &'static str) -> Result<T, SessionCtlError> {
    match result {
        Ok(value) => Ok(value),
        Err(_) => Err(stage(name)),
    }
}

fn remove_guarded_path(path: &mut Option<PathBuf>) -> Result<(), SessionCtlError> {
    let Some(owned) = path.as_deref() else {
        return Ok(());
    };
    map_stage(fs::remove_file(owned), "Fast adapter handoff removal")?;
    *path = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = fresh_handoff_path()
                .expect("fresh path")
                .with_extension("tests");
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn path_modes_have_stable_labels_and_fail_closed_selection_rules() {
        assert_eq!(FastAdapterPathMode::Auto.as_str(), "auto");
        assert_eq!(FastAdapterPathMode::RelayOnly.as_str(), "relay-only");

        assert!(FastAdapterPathMode::Auto.accepts(FastPathClass::Direct, true));
        assert!(FastAdapterPathMode::Auto.accepts(FastPathClass::Relay, false));
        assert!(!FastAdapterPathMode::Auto.accepts(FastPathClass::Undetermined, false));
        assert!(!FastAdapterPathMode::Auto.accepts(FastPathClass::Custom, false));
        assert!(FastAdapterPathMode::RelayOnly.accepts(FastPathClass::Relay, false));
        assert!(!FastAdapterPathMode::RelayOnly.accepts(FastPathClass::Relay, true));
        assert!(!FastAdapterPathMode::RelayOnly.accepts(FastPathClass::Direct, true));
    }

    #[test]
    fn authority_file_guard_round_trips_and_removes_sensitive_bytes() {
        let directory = TestDirectory::new();
        let path = directory.join("authority.v1");
        let mut guard = AuthorityFileGuard::create(path.clone(), b"bounded-authority")
            .expect("create authority file");

        assert_eq!(
            read_handoff(&path).expect("read authority").as_slice(),
            b"bounded-authority"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
                0o600
            );
        }

        guard.remove().expect("remove authority file");
        guard.remove().expect("repeat removal is inert");
        assert!(!path.exists());

        let dropped_path = directory.join("dropped.v1");
        let dropped_guard = AuthorityFileGuard::create(dropped_path.clone(), b"drop-secret")
            .expect("create dropped authority file");
        drop(dropped_guard);
        assert!(!dropped_path.exists());
    }

    #[test]
    fn handoff_files_reject_unsafe_paths_and_invalid_shapes() {
        let directory = TestDirectory::new();
        assert!(validate_new_handoff_path(Path::new("relative.v1")).is_err());
        assert!(
            validate_new_handoff_path(&PathBuf::from(format!("/{}", "x".repeat(4_097)))).is_err()
        );
        assert!(validate_new_handoff_path(&directory.join("missing/authority.v1")).is_err());

        let empty = directory.join("empty.v1");
        fs::write(&empty, []).expect("write empty fixture");
        assert!(validate_new_handoff_path(&empty).is_err());
        assert!(read_handoff(&empty).is_err());

        let oversized = directory.join("oversized.v1");
        fs::write(&oversized, vec![0_u8; MAX_FAST_OPERATOR_HANDOFF_BYTES + 1])
            .expect("write oversized fixture");
        assert!(read_handoff(&oversized).is_err());

        assert!(read_handoff(&directory.0).is_err());
        assert!(read_handoff(Path::new("relative.v1")).is_err());

        let malformed = directory.join("malformed.v1");
        fs::write(&malformed, b"not-canonical-cbor").expect("write malformed fixture");
        assert!(load_authorities(&malformed, 1).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = directory.join("link.v1");
            symlink(&malformed, &link).expect("create symlink fixture");
            assert!(read_handoff(&link).is_err());
        }
    }
}
