//! Checked-build L2 process supervision and fresh verification foundation.
//!
//! This module is test infrastructure. It is compiled only under the
//! workspace-declared storage fault-testing cfg and has no runtime activation
//! path in an ordinary `sessionctl` build.

use std::{
    ffi::OsStr,
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use aws_lc_rs::digest::{SHA256, digest};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use storage_sqlcipher::{SqlCipherStorage, VaultKey, fault_testing};
use zeroize::{Zeroize, Zeroizing};

use self::fault_testing::{
    BarrierFailure, BarrierTransport, CONTROL_FRAME_BYTES, CaseId, Checkpoint, ControlFrame,
    FaultObserver, FrameKind, OracleState, Role, Scenario,
};
use super::{SessionCtlError, random_nonzero, resolve_l1_process_git_commit, stage};

const ROOT_MARKER_NAME: &str = ".sessionctl-l2-root";
const ROOT_MARKER: &[u8] = b"sessionctl-l2-v1\n";
const CASE_CONFIG_NAME: &str = "case.config";
const DATABASE_NAME: &str = "case.sqlite3";
const WRITER_KEY_NAME: &str = "writer.key";
const VERIFIER_KEY_NAME: &str = "verifier.key";
const CASE_CONFIG_BYTES: usize = CONTROL_FRAME_BYTES + 2;
const KEY_BYTES: usize = 32;
const MAX_CASE_ENTRIES: usize = 32;
const MAX_CHILD_OUTPUT_BYTES: usize = 512;
const MAX_EVIDENCE_BYTES: usize = 2_048;
const MAX_LOCKFILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOOLCHAIN_BYTES: usize = 4_096;
const FRAME_WAIT: Duration = Duration::from_secs(1);
const CHILD_WAIT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const INVITATION_ID: [u8; 16] = [0x11; 16];
const INVITATION_GENERATION: [u8; 64] = [0x12; 64];
const JOIN_REQUEST_ID: [u8; 16] = [0x13; 16];
const GROUP_ID: [u8; 32] = [0x15; 32];
const BASELINE_NOW: u64 = 1_900_000_000;

/// Checked harness cases used to prove the reusable controller boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L2HarnessProbe {
    /// A non-target checkpoint receives one exact continue acknowledgement.
    GracefulContinue,
    /// The target remains unacknowledged until the writer is killed and reaped.
    KillWhileBlocked,
    /// A defective writer emits the next checkpoint without acknowledgement.
    AdvanceWithoutAcknowledgement,
    /// A defective writer exceeds the exact control-frame bound.
    OversizedOutput,
    /// A defective writer emits a seeded secret-bearing diagnostic.
    SecretDiagnostic,
    /// A defective writer never reaches its checkpoint.
    Stall,
    /// A structurally valid database contains a semantically mixed state.
    MixedFixture,
}

impl L2HarnessProbe {
    const fn code(self) -> u8 {
        match self {
            Self::GracefulContinue => 1,
            Self::KillWhileBlocked => 2,
            Self::AdvanceWithoutAcknowledgement => 3,
            Self::OversizedOutput => 4,
            Self::SecretDiagnostic => 5,
            Self::Stall => 6,
            Self::MixedFixture => 7,
        }
    }

    const fn control_label(self) -> &'static str {
        match self {
            Self::GracefulContinue => "continue",
            Self::KillWhileBlocked => "kill-while-unacknowledged",
            Self::AdvanceWithoutAcknowledgement
            | Self::OversizedOutput
            | Self::SecretDiagnostic
            | Self::Stall
            | Self::MixedFixture => "negative-probe",
        }
    }
}

impl TryFrom<u8> for L2HarnessProbe {
    type Error = SessionCtlError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::GracefulContinue),
            2 => Ok(Self::KillWhileBlocked),
            3 => Ok(Self::AdvanceWithoutAcknowledgement),
            4 => Ok(Self::OversizedOutput),
            5 => Ok(Self::SecretDiagnostic),
            6 => Ok(Self::Stall),
            7 => Ok(Self::MixedFixture),
            _ => Err(stage("L2 probe")),
        }
    }
}

/// Secret-free evidence from one successful L2 controller probe.
#[derive(Clone, Eq, PartialEq)]
pub struct L2ProcessReport {
    case_id: CaseId,
    probe: L2HarnessProbe,
    commit: String,
    dirty: bool,
    toolchain: String,
    lock_digest: String,
}

impl L2ProcessReport {
    /// Encodes one bounded `l2-evidence-v1` harness manifest.
    #[must_use]
    pub fn encode_v1(&self) -> String {
        let evidence = format!(
            concat!(
                "version=1\n",
                "protocol=l2-evidence-v1\n",
                "scenario=L2-HARNESS-001\n",
                "result=pass\n",
                "fault_build=true\n",
                "case_id={}\n",
                "schedule_seed=1\n",
                "checkpoint=INVITER_BEFORE_BEGIN\n",
                "occurrence=0\n",
                "control={}\n",
                "expected=I0\n",
                "observed=I0\n",
                "platform={}-{}\n",
                "commit={}\n",
                "dirty={}\n",
                "toolchain={}\n",
                "lock_sha256={}\n",
                "frame_bytes={}\n",
                "frame_wait_ms={}\n",
                "child_wait_ms={}\n",
                "integrity=pass\n",
                "schema=pass\n",
                "semantic_oracle=pass\n",
                "writer_termination=confirmed\n",
                "fresh_verifier=pass\n",
                "redaction=pass\n",
                "handle_cleanup=pass\n",
                "child_cleanup=pass\n",
                "directory_cleanup=pass\n"
            ),
            hex(self.case_id.as_bytes()),
            self.probe.control_label(),
            std::env::consts::OS,
            std::env::consts::ARCH,
            self.commit,
            if self.dirty { "true" } else { "false" },
            self.toolchain,
            self.lock_digest,
            CONTROL_FRAME_BYTES,
            FRAME_WAIT.as_millis(),
            CHILD_WAIT.as_millis(),
        );
        debug_assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
        evidence
    }
}

/// Runs one bounded controller probe through the checked hidden binary.
pub fn run_l2_process_probe(
    executable: &Path,
    probe: L2HarnessProbe,
) -> Result<L2ProcessReport, SessionCtlError> {
    if !executable.is_absolute() || !executable.is_file() {
        return Err(stage("L2 executable"));
    }
    let case_id = CaseId::new(random_nonzero()?).map_err(|_| stage("L2 case"))?;
    let target = ControlFrame::new_checkpoint(case_id, Checkpoint::InviterBeforeBegin, 0)
        .map_err(|_| stage("L2 case"))?;
    let config = CaseConfig {
        target,
        expected: OracleState::InviterOld,
        probe,
    };
    let mut root = ProcessRoot::new()?;
    let scenario_result = run_controller(executable, root.path(), config);
    let cleanup_result = root.cleanup();
    scenario_result?;
    cleanup_result?;
    let repository_root = repository_root();
    let report = L2ProcessReport {
        case_id,
        probe,
        commit: resolve_l1_process_git_commit(&repository_root)
            .unwrap_or_else(|| String::from("unavailable")),
        dirty: git_dirty_at(&repository_root).unwrap_or(true),
        toolchain: pinned_toolchain_at(&repository_root)
            .unwrap_or_else(|| String::from("unavailable")),
        lock_digest: lock_digest_at(&repository_root)
            .unwrap_or_else(|| String::from("unavailable")),
    };
    if report.encode_v1().len() > MAX_EVIDENCE_BYTES {
        return Err(stage("L2 evidence"));
    }
    Ok(report)
}

/// Runs one hidden role selected only by the checked parent controller.
pub fn run_l2_process_internal_role(role: &str, root: PathBuf) -> Result<(), SessionCtlError> {
    validate_root(&root)?;
    match role {
        "writer" => run_writer(&root),
        "verifier" => run_verifier(&root),
        _ => Err(stage("L2 role")),
    }
}

#[derive(Clone, Copy)]
struct CaseConfig {
    target: ControlFrame,
    expected: OracleState,
    probe: L2HarnessProbe,
}

impl CaseConfig {
    fn encode(self) -> [u8; CASE_CONFIG_BYTES] {
        let mut encoded = [0_u8; CASE_CONFIG_BYTES];
        encoded[..CONTROL_FRAME_BYTES].copy_from_slice(&self.target.encode());
        encoded[CONTROL_FRAME_BYTES] = self.expected.code();
        encoded[CONTROL_FRAME_BYTES + 1] = self.probe.code();
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, SessionCtlError> {
        if encoded.len() != CASE_CONFIG_BYTES {
            return Err(stage("L2 case config"));
        }
        let target = ControlFrame::decode(&encoded[..CONTROL_FRAME_BYTES])
            .map_err(|_| stage("L2 case config"))?;
        let expected = OracleState::try_from(encoded[CONTROL_FRAME_BYTES])
            .map_err(|_| stage("L2 case config"))?;
        let probe = L2HarnessProbe::try_from(encoded[CONTROL_FRAME_BYTES + 1])?;
        if target.kind() != FrameKind::Checkpoint
            || target.role() != Role::Writer
            || target.scenario() != Scenario::InviterTransaction
            || target.checkpoint() != Checkpoint::InviterBeforeBegin
            || target.occurrence() != 0
            || expected != OracleState::InviterOld
        {
            return Err(stage("L2 case config"));
        }
        Ok(Self {
            target,
            expected,
            probe,
        })
    }
}

fn run_controller(
    executable: &Path,
    root: &Path,
    config: CaseConfig,
) -> Result<(), SessionCtlError> {
    let key = Zeroizing::new(random_nonzero::<KEY_BYTES>()?);
    write_owned_file(&root.join(CASE_CONFIG_NAME), &config.encode(), false)?;
    prepare_inviter_old_baseline(root, &key)?;
    if config.probe == L2HarnessProbe::MixedFixture {
        inject_mixed_group(root, &key)?;
    }
    write_owned_file(&root.join(WRITER_KEY_NAME), key.as_slice(), true)?;

    let mut writer = ManagedChild::spawn(executable, "writer", root, true)?;
    let encoded = writer
        .stdout
        .read_exact_frame(CONTROL_FRAME_BYTES, FRAME_WAIT)?;
    let observed = ControlFrame::decode(&encoded).map_err(|_| stage("L2 checkpoint"))?;
    if observed != config.target {
        return Err(stage("L2 checkpoint"));
    }

    match config.probe {
        L2HarnessProbe::GracefulContinue => {
            writer.write_stdin(&observed.acknowledgement().encode())?;
            writer.close_stdin();
            let status = writer.wait(CHILD_WAIT)?;
            if !status.success() {
                return Err(stage("L2 writer"));
            }
        }
        L2HarnessProbe::KillWhileBlocked
        | L2HarnessProbe::AdvanceWithoutAcknowledgement
        | L2HarnessProbe::OversizedOutput
        | L2HarnessProbe::SecretDiagnostic
        | L2HarnessProbe::MixedFixture => {
            writer.terminate_and_reap()?;
        }
        L2HarnessProbe::Stall => return Err(stage("L2 checkpoint timeout")),
    }
    writer.stdout.require_empty(CHILD_WAIT)?;
    writer.stderr.require_empty(CHILD_WAIT)?;
    if root.join(WRITER_KEY_NAME).exists() {
        return Err(stage("L2 writer key cleanup"));
    }

    write_owned_file(&root.join(VERIFIER_KEY_NAME), key.as_slice(), true)?;
    let mut verifier = ManagedChild::spawn(executable, "verifier", root, false)?;
    let status = verifier.wait(CHILD_WAIT)?;
    if !status.success() {
        return Err(stage("L2 verifier"));
    }
    let stdout = verifier.stdout.collect(CHILD_WAIT)?;
    let stderr = verifier.stderr.collect(CHILD_WAIT)?;
    if stdout != b"role=verifier\nresult=pass\noracle=I0\n" || !stderr.is_empty() {
        return Err(stage("L2 verifier output"));
    }
    if root.join(VERIFIER_KEY_NAME).exists() {
        return Err(stage("L2 verifier key cleanup"));
    }
    Ok(())
}

fn prepare_inviter_old_baseline(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
) -> Result<(), SessionCtlError> {
    let storage = SqlCipherStorage::create(
        &root.join(DATABASE_NAME),
        VaultKey::new(**key).map_err(|_| stage("L2 baseline"))?,
    )
    .map_err(|_| stage("L2 baseline"))?;
    storage
        .seed_reservation(
            INVITATION_ID,
            INVITATION_GENERATION,
            JOIN_REQUEST_ID,
            BASELINE_NOW + 60,
            BASELINE_NOW,
        )
        .map_err(|_| stage("L2 baseline"))?;
    drop(storage);
    Ok(())
}

fn inject_mixed_group(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
) -> Result<(), SessionCtlError> {
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;
    connection
        .execute(
            "INSERT INTO mls_groups(group_id, state) VALUES (?1, ?2)",
            params![GROUP_ID, [0x41_u8]],
        )
        .map_err(|_| stage("L2 mixed fixture"))?;
    Ok(())
}

fn run_writer(root: &Path) -> Result<(), SessionCtlError> {
    let config = read_case_config(root)?;
    let key = read_key(root, WRITER_KEY_NAME)?;
    let transport = std::sync::Arc::new(StdioBarrier::default());
    let observer = FaultObserver::new(config.target.case_id(), config.target.scenario(), transport);
    let _storage = fault_testing::open(
        &root.join(DATABASE_NAME),
        VaultKey::new(*key).map_err(|_| stage("L2 writer"))?,
        observer.clone(),
    )
    .map_err(|_| stage("L2 writer"))?;

    match config.probe {
        L2HarnessProbe::GracefulContinue
        | L2HarnessProbe::KillWhileBlocked
        | L2HarnessProbe::MixedFixture => observer
            .checkpoint(config.target.checkpoint(), config.target.occurrence())
            .map_err(|_| stage("L2 writer barrier")),
        L2HarnessProbe::SecretDiagnostic => {
            eprintln!("seeded-secret-diagnostic");
            observer
                .checkpoint(config.target.checkpoint(), config.target.occurrence())
                .map_err(|_| stage("L2 writer barrier"))
        }
        L2HarnessProbe::AdvanceWithoutAcknowledgement => {
            let next = ControlFrame::new_checkpoint(
                config.target.case_id(),
                Checkpoint::InviterAfterGroupUpsert,
                0,
            )
            .map_err(|_| stage("L2 writer frame"))?;
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(&config.target.encode())
                .and_then(|()| stdout.write_all(&next.encode()))
                .and_then(|()| stdout.flush())
                .map_err(|_| stage("L2 writer output"))?;
            thread::sleep(Duration::from_secs(10));
            Ok(())
        }
        L2HarnessProbe::OversizedOutput => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(&config.target.encode())
                .and_then(|()| stdout.write_all(&[0; MAX_CHILD_OUTPUT_BYTES + 1]))
                .and_then(|()| stdout.flush())
                .map_err(|_| stage("L2 writer output"))?;
            thread::sleep(Duration::from_secs(10));
            Ok(())
        }
        L2HarnessProbe::Stall => {
            thread::sleep(Duration::from_secs(10));
            Ok(())
        }
    }
}

fn run_verifier(root: &Path) -> Result<(), SessionCtlError> {
    let config = read_case_config(root)?;
    let key = read_key(root, VERIFIER_KEY_NAME)?;
    verify_inviter_old(root, &key, config.expected)?;
    print!("role=verifier\nresult=pass\noracle=I0\n");
    Ok(())
}

fn verify_inviter_old(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    expected: OracleState,
) -> Result<(), SessionCtlError> {
    if expected != OracleState::InviterOld {
        return Err(stage("L2 semantic oracle"));
    }
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;

    let mut cipher = connection
        .prepare("PRAGMA cipher_integrity_check;")
        .map_err(|_| stage("L2 cipher integrity"))?;
    let cipher_failure = {
        let mut rows = cipher.query([]).map_err(|_| stage("L2 cipher integrity"))?;
        rows.next()
            .map_err(|_| stage("L2 cipher integrity"))?
            .is_some()
    };
    if cipher_failure {
        return Err(stage("L2 cipher integrity"));
    }

    let quick: String = connection
        .query_row("PRAGMA quick_check;", [], |row| row.get(0))
        .map_err(|_| stage("L2 quick check"))?;
    if quick != "ok" {
        return Err(stage("L2 quick check"));
    }
    let mut foreign = connection
        .prepare("PRAGMA foreign_key_check;")
        .map_err(|_| stage("L2 foreign key check"))?;
    let foreign_key_failure = {
        let mut rows = foreign
            .query([])
            .map_err(|_| stage("L2 foreign key check"))?;
        rows.next()
            .map_err(|_| stage("L2 foreign key check"))?
            .is_some()
    };
    if foreign_key_failure {
        return Err(stage("L2 foreign key check"));
    }

    let user_version: i64 = connection
        .query_row("PRAGMA user_version;", [], |row| row.get(0))
        .map_err(|_| stage("L2 schema"))?;
    let metadata: (i64, i64, i64) = connection
        .query_row(
            "SELECT count(*), min(schema_version), max(schema_version) FROM storage_metadata",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| stage("L2 schema"))?;
    if user_version != 4 || metadata != (1, 4, 4) {
        return Err(stage("L2 schema"));
    }

    let reservation_state: Option<i64> = connection
        .query_row(
            "SELECT state FROM reservations WHERE invitation_id = ?1",
            params![INVITATION_ID],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| stage("L2 semantic oracle"))?;
    let counts = [
        table_count(&connection, "reservations")?,
        table_count(&connection, "inviter_joins")?,
        table_count(&connection, "mls_groups")?,
        table_count(&connection, "mls_epochs")?,
        table_count(&connection, "key_packages")?,
        table_count(&connection, "joiner_commits")?,
        table_count(&connection, "mls_client_identity")?,
    ];
    if reservation_state != Some(1) || counts != [1, 0, 0, 0, 0, 0, 0] {
        return Err(stage("L2 semantic oracle"));
    }
    Ok(())
}

fn table_count(connection: &Connection, table: &str) -> Result<i64, SessionCtlError> {
    let sql = match table {
        "reservations" => "SELECT count(*) FROM reservations",
        "inviter_joins" => "SELECT count(*) FROM inviter_joins",
        "mls_groups" => "SELECT count(*) FROM mls_groups",
        "mls_epochs" => "SELECT count(*) FROM mls_epochs",
        "key_packages" => "SELECT count(*) FROM key_packages",
        "joiner_commits" => "SELECT count(*) FROM joiner_commits",
        "mls_client_identity" => "SELECT count(*) FROM mls_client_identity",
        _ => return Err(stage("L2 semantic table")),
    };
    connection
        .query_row(sql, [], |row| row.get(0))
        .map_err(|_| stage("L2 semantic oracle"))
}

fn open_keyed_connection(
    path: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
) -> Result<Connection, SessionCtlError> {
    validate_owned_file(path, None)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| stage("L2 verifier open"))?;
    let mut pragma = Zeroizing::new(String::from("PRAGMA key = \"x'"));
    for byte in key.iter() {
        write!(&mut pragma, "{byte:02X}").map_err(|_| stage("L2 verifier key"))?;
    }
    pragma.push_str("'\";");
    connection
        .execute_batch(&pragma)
        .map_err(|_| stage("L2 verifier key"))?;
    pragma.zeroize();
    let _: i64 = connection
        .query_row("SELECT count(*) FROM sqlite_master;", [], |row| row.get(0))
        .map_err(|_| stage("L2 verifier key"))?;
    let cipher_version: String = connection
        .query_row("PRAGMA cipher_version;", [], |row| row.get(0))
        .map_err(|_| stage("L2 verifier cipher"))?;
    if cipher_version.is_empty() {
        return Err(stage("L2 verifier cipher"));
    }
    connection
        .execute_batch("PRAGMA trusted_schema = OFF; PRAGMA foreign_keys = ON;")
        .map_err(|_| stage("L2 verifier configuration"))?;
    Ok(connection)
}

#[derive(Default)]
struct StdioBarrier(std::sync::Mutex<()>);

impl BarrierTransport for StdioBarrier {
    fn exchange(
        &self,
        encoded: [u8; CONTROL_FRAME_BYTES],
    ) -> Result<[u8; CONTROL_FRAME_BYTES], BarrierFailure> {
        let _guard = self.0.lock().map_err(|_| BarrierFailure::Rejected)?;
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(&encoded)
            .and_then(|()| stdout.flush())
            .map_err(|_| BarrierFailure::Rejected)?;
        let mut acknowledgement = [0_u8; CONTROL_FRAME_BYTES];
        std::io::stdin()
            .lock()
            .read_exact(&mut acknowledgement)
            .map_err(|_| BarrierFailure::Rejected)?;
        Ok(acknowledgement)
    }
}

struct ProcessRoot(Option<PathBuf>);

impl ProcessRoot {
    fn new() -> Result<Self, SessionCtlError> {
        for _ in 0..8 {
            let identifier: [u8; 16] = random_nonzero()?;
            let root = std::env::temp_dir().join(format!("session-chat-l2-{}", hex(&identifier)));
            match fs::create_dir(&root) {
                Ok(()) => {
                    set_private_directory_permissions(&root)?;
                    write_owned_file(&root.join(ROOT_MARKER_NAME), ROOT_MARKER, false)?;
                    return Ok(Self(Some(root)));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(stage("L2 root")),
            }
        }
        Err(stage("L2 root"))
    }

    fn path(&self) -> &Path {
        self.0
            .as_deref()
            .expect("L2 root unavailable after cleanup")
    }

    fn cleanup(&mut self) -> Result<(), SessionCtlError> {
        self.cleanup_with(|path| fs::remove_dir_all(path))
    }

    fn cleanup_with(
        &mut self,
        remove: impl FnOnce(&Path) -> std::io::Result<()>,
    ) -> Result<(), SessionCtlError> {
        let Some(path) = self.0.as_deref() else {
            return Ok(());
        };
        validate_root_tree(path)?;
        remove(path).map_err(|_| stage("L2 root cleanup"))?;
        self.0 = None;
        Ok(())
    }
}

impl Drop for ProcessRoot {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn validate_root(root: &Path) -> Result<(), SessionCtlError> {
    if !root.is_absolute() || root.as_os_str().len() > 4_096 {
        return Err(stage("L2 root validation"));
    }
    let metadata = fs::symlink_metadata(root).map_err(|_| stage("L2 root validation"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(stage("L2 root validation"));
    }
    let marker = root.join(ROOT_MARKER_NAME);
    if read_owned_file(&marker, ROOT_MARKER.len())?.as_slice() != ROOT_MARKER {
        return Err(stage("L2 root validation"));
    }
    Ok(())
}

fn validate_root_tree(root: &Path) -> Result<(), SessionCtlError> {
    validate_root(root)?;
    let canonical_root = root
        .canonicalize()
        .map_err(|_| stage("L2 root validation"))?;
    let entries: Vec<_> = fs::read_dir(root)
        .map_err(|_| stage("L2 root validation"))?
        .collect::<Result<_, _>>()
        .map_err(|_| stage("L2 root validation"))?;
    if entries.len() > MAX_CASE_ENTRIES {
        return Err(stage("L2 root validation"));
    }
    for entry in entries {
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| stage("L2 root validation"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(stage("L2 root validation"));
        }
        let canonical = entry
            .path()
            .canonicalize()
            .map_err(|_| stage("L2 root validation"))?;
        if !canonical.starts_with(&canonical_root) {
            return Err(stage("L2 root validation"));
        }
    }
    Ok(())
}

fn write_owned_file(path: &Path, bytes: &[u8], secret: bool) -> Result<(), SessionCtlError> {
    if bytes.len() > 4_096 || path.parent().is_none() {
        return Err(stage("L2 file"));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| stage("L2 file"))?;
    if secret {
        set_private_file_permissions(path)?;
    }
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| stage("L2 file"))
}

fn read_owned_file(path: &Path, expected: usize) -> Result<Vec<u8>, SessionCtlError> {
    validate_owned_file(path, Some(expected))?;
    let file = File::open(path).map_err(|_| stage("L2 file"))?;
    let mut bytes = Vec::with_capacity(expected);
    file.take(u64::try_from(expected + 1).map_err(|_| stage("L2 file"))?)
        .read_to_end(&mut bytes)
        .map_err(|_| stage("L2 file"))?;
    if bytes.len() != expected {
        return Err(stage("L2 file"));
    }
    Ok(bytes)
}

fn validate_owned_file(path: &Path, expected: Option<usize>) -> Result<(), SessionCtlError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| stage("L2 file"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(stage("L2 file"));
    }
    if expected.is_some_and(|expected| metadata.len() != expected as u64) {
        return Err(stage("L2 file"));
    }
    Ok(())
}

fn read_case_config(root: &Path) -> Result<CaseConfig, SessionCtlError> {
    CaseConfig::decode(&read_owned_file(
        &root.join(CASE_CONFIG_NAME),
        CASE_CONFIG_BYTES,
    )?)
}

fn read_key(root: &Path, name: &str) -> Result<Zeroizing<[u8; KEY_BYTES]>, SessionCtlError> {
    let path = root.join(name);
    let mut bytes = Zeroizing::new(read_owned_file(&path, KEY_BYTES)?);
    fs::remove_file(&path).map_err(|_| stage("L2 key cleanup"))?;
    let key = Zeroizing::new(bytes.as_slice().try_into().map_err(|_| stage("L2 key"))?);
    bytes.zeroize();
    Ok(key)
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), SessionCtlError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| stage("L2 root permissions"))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), SessionCtlError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), SessionCtlError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| stage("L2 file permissions"))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), SessionCtlError> {
    Ok(())
}

struct ManagedChild {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: PipeReader,
    stderr: PipeReader,
}

impl ManagedChild {
    fn spawn(
        executable: &Path,
        role: &str,
        root: &Path,
        interactive: bool,
    ) -> Result<Self, SessionCtlError> {
        let mut command = Command::new(executable);
        command
            .args([OsStr::new("--internal-role"), OsStr::new(role)])
            .arg(root)
            .stdin(if interactive {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        sanitize_environment(&mut command);
        Self::spawn_command(command)
    }

    fn spawn_command(mut command: Command) -> Result<Self, SessionCtlError> {
        let mut child = command.spawn().map_err(|_| stage("L2 spawn"))?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().ok_or_else(|| stage("L2 stdout"))?;
        let stderr = child.stderr.take().ok_or_else(|| stage("L2 stderr"))?;
        Ok(Self {
            child: Some(child),
            stdin,
            stdout: PipeReader::new(stdout),
            stderr: PipeReader::new(stderr),
        })
    }

    fn write_stdin(&mut self, bytes: &[u8]) -> Result<(), SessionCtlError> {
        self.stdin
            .as_mut()
            .ok_or_else(|| stage("L2 stdin"))?
            .write_all(bytes)
            .and_then(|()| self.stdin.as_mut().expect("stdin checked").flush())
            .map_err(|_| stage("L2 stdin"))
    }

    fn close_stdin(&mut self) {
        self.stdin.take();
    }

    fn wait(&mut self, timeout: Duration) -> Result<ExitStatus, SessionCtlError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| stage("L2 child deadline"))?;
        loop {
            let child = self.child.as_mut().ok_or_else(|| stage("L2 child"))?;
            if let Some(status) = child.try_wait().map_err(|_| stage("L2 child wait"))? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(stage("L2 child timeout"));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn terminate_and_reap(&mut self) -> Result<(), SessionCtlError> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        self.stdin.take();
        if child
            .try_wait()
            .map_err(|_| stage("L2 child termination"))?
            .is_some()
        {
            return Err(stage("L2 child escaped barrier"));
        }
        child.kill().map_err(|_| stage("L2 child termination"))?;
        child.wait().map_err(|_| stage("L2 child reap"))?;
        Ok(())
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        self.stdin.take();
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

enum PipeMessage {
    Bytes(Vec<u8>),
    Eof,
    Rejected,
}

struct PipeReader {
    receiver: Receiver<PipeMessage>,
    join: Option<JoinHandle<()>>,
    buffered: Vec<u8>,
    eof: bool,
}

impl PipeReader {
    fn new(mut reader: impl Read + Send + 'static) -> Self {
        let (sender, receiver) = mpsc::channel();
        let join = thread::spawn(move || {
            let mut total = 0_usize;
            loop {
                let mut chunk = [0_u8; 64];
                match reader.read(&mut chunk) {
                    Ok(0) => {
                        let _ = sender.send(PipeMessage::Eof);
                        return;
                    }
                    Ok(read) if total.saturating_add(read) <= MAX_CHILD_OUTPUT_BYTES => {
                        total += read;
                        if sender
                            .send(PipeMessage::Bytes(chunk[..read].to_vec()))
                            .is_err()
                        {
                            return;
                        }
                    }
                    Ok(_) | Err(_) => {
                        let _ = sender.send(PipeMessage::Rejected);
                        return;
                    }
                }
            }
        });
        Self {
            receiver,
            join: Some(join),
            buffered: Vec::new(),
            eof: false,
        }
    }

    fn read_exact_frame(
        &mut self,
        expected: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, SessionCtlError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| stage("L2 output deadline"))?;
        while self.buffered.len() < expected && !self.eof {
            self.receive(deadline)?;
            if self.buffered.len() > expected {
                return Err(stage("L2 output bound"));
            }
        }
        if self.buffered.len() != expected {
            return Err(stage("L2 output frame"));
        }
        Ok(std::mem::take(&mut self.buffered))
    }

    fn require_empty(&mut self, timeout: Duration) -> Result<(), SessionCtlError> {
        if self.collect(timeout)?.is_empty() {
            Ok(())
        } else {
            Err(stage("L2 unexpected child output"))
        }
    }

    fn collect(&mut self, timeout: Duration) -> Result<Vec<u8>, SessionCtlError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| stage("L2 output deadline"))?;
        while !self.eof {
            self.receive(deadline)?;
        }
        Ok(std::mem::take(&mut self.buffered))
    }

    fn receive(&mut self, deadline: Instant) -> Result<(), SessionCtlError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| stage("L2 output timeout"))?;
        match self.receiver.recv_timeout(remaining) {
            Ok(PipeMessage::Bytes(bytes)) => {
                if self.buffered.len().saturating_add(bytes.len()) > MAX_CHILD_OUTPUT_BYTES {
                    return Err(stage("L2 output bound"));
                }
                self.buffered.extend_from_slice(&bytes);
                Ok(())
            }
            Ok(PipeMessage::Eof) => {
                self.eof = true;
                Ok(())
            }
            Ok(PipeMessage::Rejected)
            | Err(RecvTimeoutError::Disconnected)
            | Err(RecvTimeoutError::Timeout) => Err(stage("L2 child output")),
        }
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn sanitize_environment(command: &mut Command) {
    command.env_clear();
    for name in ["PATH", "SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(name).filter(|value| value.len() <= 4_096) {
            command.env(name, value);
        }
    }
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}

fn git_dirty_at(root: &Path) -> Option<bool> {
    let mut command = Command::new("git");
    command
        .args(["-C", root.to_str()?, "status", "--porcelain=v1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    sanitize_environment(&mut command);
    let mut child = ManagedChild::spawn_command(command).ok()?;
    let status = child.wait(CHILD_WAIT).ok()?;
    let stdout = child.stdout.collect(CHILD_WAIT).ok()?;
    let stderr = child.stderr.collect(CHILD_WAIT).ok()?;
    (status.success() && stderr.is_empty()).then_some(!stdout.is_empty())
}

fn pinned_toolchain_at(root: &Path) -> Option<String> {
    let bytes =
        read_bounded_repository_file(&root.join("rust-toolchain.toml"), MAX_TOOLCHAIN_BYTES)?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let channel = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("channel = \"")?.strip_suffix('"'))?;
    (!channel.is_empty()
        && channel.len() <= 64
        && channel
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')))
    .then(|| channel.to_owned())
}

fn lock_digest_at(root: &Path) -> Option<String> {
    let bytes = read_bounded_repository_file(&root.join("Cargo.lock"), MAX_LOCKFILE_BYTES)?;
    Some(hex(digest(&SHA256, &bytes).as_ref()))
}

fn read_bounded_repository_file(path: &Path, maximum: usize) -> Option<Vec<u8>> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return None;
    }
    let file = File::open(path).ok()?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).ok()?);
    file.take(u64::try_from(maximum).ok()?.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= maximum).then_some(bytes)
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_root_cleanup_failure_is_reported_and_drop_retries() {
        let mut root = ProcessRoot::new().expect("L2 root");
        let path = root.path().to_owned();

        assert!(
            root.cleanup_with(|_| Err(std::io::Error::other("injected cleanup failure")))
                .is_err()
        );
        assert!(path.exists());

        drop(root);
        assert!(!path.exists());
    }
}
