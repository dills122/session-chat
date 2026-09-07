use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use sessionctl::{
    FastAdapterAuthorityFileGuard, FastAdapterPathMode, fast_adapter_profile_disclosure_v1,
    prepare_fast_adapter_host_v1, prepare_fast_adapter_join_v1, run_fast_adapter_host,
    run_fast_adapter_join, run_fast_adapter_loopback_demo,
    write_fast_adapter_profile_disclosure_v1,
};
use transport_iroh::{
    FastMailboxPolicy, FastOperatorPathModeV1, FastPathClass, IrohFastEndpoint,
    IrohFastMailboxService, MAX_FAST_ENVELOPES_PER_MAILBOX, MAX_FAST_LIVE_MAILBOXES,
    MAX_FAST_MAILBOX_LIFETIME_SECONDS, MAX_FAST_OPERATOR_HANDOFF_BYTES,
    MAX_FAST_RETAINED_BYTES_PER_MAILBOX,
};

const USAGE: &str = concat!(
    "usage: sessionctl-fast-adapter host <auto|relay-only> ",
    "<absolute-new-authority-file> | join <auto|relay-only> ",
    "<absolute-authority-file>\n"
);

#[test]
fn common_adapter_harness_passes_over_a_classified_direct_loopback_path() {
    let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime");
    let report = runtime
        .block_on(run_fast_adapter_loopback_demo())
        .expect("Fast adapter loopback harness");
    assert_eq!(report.initial_path().selected(), FastPathClass::Direct);
    assert_eq!(report.final_path().selected(), FastPathClass::Direct);
    assert!(report.final_path().direct_available());
    assert!(!report.final_path().relay_available());
}

#[test]
fn path_mode_parser_accepts_only_closed_evidence_modes() {
    assert_eq!(
        FastAdapterPathMode::parse("auto"),
        Ok(FastAdapterPathMode::Auto)
    );
    assert_eq!(
        FastAdapterPathMode::parse("relay-only"),
        Ok(FastAdapterPathMode::RelayOnly)
    );
    assert!(FastAdapterPathMode::parse("direct-only").is_err());
    assert!(FastAdapterPathMode::parse("private").is_err());
    assert_eq!(FastAdapterPathMode::Auto.as_str(), "auto");
    assert_eq!(FastAdapterPathMode::RelayOnly.as_str(), "relay-only");
    assert!(FastAdapterPathMode::Auto.permits_direct_paths());
    assert!(!FastAdapterPathMode::RelayOnly.permits_direct_paths());
    assert_eq!(FastAdapterPathMode::Auto.to_string(), "auto");
    assert_eq!(
        "relay-only".parse::<FastAdapterPathMode>(),
        Ok(FastAdapterPathMode::RelayOnly)
    );

    assert!(
        FastAdapterPathMode::Auto
            .validate_observation(FastPathClass::Direct, true)
            .is_ok()
    );
    assert!(
        FastAdapterPathMode::Auto
            .validate_observation(FastPathClass::Relay, false)
            .is_ok()
    );
    assert!(
        FastAdapterPathMode::Auto
            .validate_observation(FastPathClass::Undetermined, false)
            .is_err()
    );
    assert!(
        FastAdapterPathMode::Auto
            .validate_observation(FastPathClass::Custom, false)
            .is_err()
    );
    assert!(
        FastAdapterPathMode::RelayOnly
            .validate_observation(FastPathClass::Relay, false)
            .is_ok()
    );
    assert!(
        FastAdapterPathMode::RelayOnly
            .validate_observation(FastPathClass::Relay, true)
            .is_err()
    );
    assert!(
        FastAdapterPathMode::RelayOnly
            .validate_observation(FastPathClass::Direct, false)
            .is_err()
    );
}

#[test]
fn public_disclosure_renderer_is_complete_and_fails_closed() {
    let rendered = fast_adapter_profile_disclosure_v1(FastAdapterPathMode::RelayOnly);
    for expected in [
        "requested_path=relay-only",
        "transport_disclosure=Fast",
        "content_security=Opaque content this transport does not verify as encrypted",
        "direct_exposure=A direct peer can learn your network address.",
        "relay_exposure=An Iroh relay can observe endpoint identifiers, network addresses, timing, and traffic volume.",
        "discovery_exposure=Iroh address lookup, DNS, and NAT traversal services can observe connection metadata.",
        "availability=Both participants must be online for this experimental adapter.",
        "anonymous=false",
        "offline_delivery=false",
    ] {
        assert!(rendered.contains(expected));
    }

    let mut output = Vec::new();
    write_fast_adapter_profile_disclosure_v1(&mut output, FastAdapterPathMode::RelayOnly)
        .expect("write and flush disclosure");
    assert_eq!(output, format!("{rendered}\n").as_bytes());

    for mut writer in [
        TestDisclosureWriter {
            fail_write: true,
            fail_flush: false,
        },
        TestDisclosureWriter {
            fail_write: false,
            fail_flush: true,
        },
    ] {
        assert!(
            write_fast_adapter_profile_disclosure_v1(&mut writer, FastAdapterPathMode::Auto)
                .is_err()
        );
    }
}

#[test]
fn public_run_preflight_validates_then_flushes_the_complete_disclosure() {
    let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime");
    let root = temporary_directory();
    let host_path = root.join("new-authority.v2");
    let mut host_output = Vec::new();
    prepare_fast_adapter_host_v1(&mut host_output, FastAdapterPathMode::RelayOnly, &host_path)
        .expect("host preflight");
    assert!(!host_path.exists());
    assert_eq!(
        host_output,
        format!(
            "{}\n",
            fast_adapter_profile_disclosure_v1(FastAdapterPathMode::RelayOnly)
        )
        .as_bytes()
    );
    let mut failed_host_output = TestDisclosureWriter {
        fail_write: true,
        fail_flush: false,
    };
    assert!(
        prepare_fast_adapter_host_v1(
            &mut failed_host_output,
            FastAdapterPathMode::Auto,
            &host_path,
        )
        .is_err()
    );

    let handoff_path = root.join("authority.v2");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    runtime.block_on(async {
        let endpoint = IrohFastEndpoint::bind_loopback()
            .await
            .expect("bind local endpoint");
        let server = endpoint.id();
        let encoded = issue_handoff(&endpoint, now, FastOperatorPathModeV1::Auto);
        fs::write(&handoff_path, encoded).expect("write handoff");
        let mut join_output = Vec::new();
        let authorities = prepare_fast_adapter_join_v1(
            &mut join_output,
            FastAdapterPathMode::Auto,
            &handoff_path,
            now,
        )
        .expect("join preflight");
        assert!(authorities.server_id() == server);
        assert_eq!(
            join_output,
            format!(
                "{}\n",
                fast_adapter_profile_disclosure_v1(FastAdapterPathMode::Auto)
            )
            .as_bytes()
        );
        let mut failed_join_output = TestDisclosureWriter {
            fail_write: false,
            fail_flush: true,
        };
        assert!(
            prepare_fast_adapter_join_v1(
                &mut failed_join_output,
                FastAdapterPathMode::Auto,
                &handoff_path,
                now,
            )
            .is_err()
        );
        endpoint
            .close(std::time::Duration::from_secs(5))
            .await
            .expect("close local endpoint");
    });

    let mut rejected_output = Vec::new();
    assert!(
        prepare_fast_adapter_join_v1(
            &mut rejected_output,
            FastAdapterPathMode::RelayOnly,
            &handoff_path,
            now,
        )
        .is_err()
    );
    assert!(rejected_output.is_empty());
    fs::remove_dir_all(root).expect("remove fixtures");
}

struct TestDisclosureWriter {
    fail_write: bool,
    fail_flush: bool,
}

impl Write for TestDisclosureWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.fail_write {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "write failed"))
        } else {
            Ok(bytes.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.fail_flush {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "flush failed"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn authority_file_guard_round_trips_removes_and_bounds_handoffs() {
    let root = temporary_directory();
    let path = root.join("authority.v2");
    let mut guard = FastAdapterAuthorityFileGuard::create(path.clone(), b"bounded-authority")
        .expect("create authority file");

    assert_eq!(
        fs::read(&path).expect("read authority"),
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
    guard.remove().expect("remove authority");
    guard.remove().expect("repeat removal is inert");
    assert!(!path.exists());

    assert!(FastAdapterAuthorityFileGuard::create(root.join("empty.v2"), b"").is_err());
    assert!(
        FastAdapterAuthorityFileGuard::create(
            root.join("oversized.v2"),
            &vec![0_u8; MAX_FAST_OPERATOR_HANDOFF_BYTES + 1],
        )
        .is_err()
    );

    let dropped_path = root.join("dropped.v2");
    let dropped = FastAdapterAuthorityFileGuard::create(dropped_path.clone(), b"drop-secret")
        .expect("create dropped authority");
    drop(dropped);
    assert!(!dropped_path.exists());
    fs::remove_dir_all(root).expect("remove fixtures");
}

#[test]
fn authority_file_guard_rejects_path_collisions_and_tolerates_external_removal() {
    let root = temporary_directory();
    let destination = root.join("authority.v2");
    fs::write(&destination, b"existing").expect("write destination collision");
    assert!(FastAdapterAuthorityFileGuard::create(destination, b"authority").is_err());

    let destination = root.join("other.v2");
    fs::write(temporary_handoff_path(&destination), b"existing")
        .expect("write temporary collision");
    assert!(FastAdapterAuthorityFileGuard::create(destination, b"authority").is_err());

    let removed_path = root.join("removed.v2");
    let mut guard = FastAdapterAuthorityFileGuard::create(removed_path.clone(), b"authority")
        .expect("create removable authority");
    fs::remove_file(&removed_path).expect("remove externally");
    guard.remove().expect("missing path is inert");
    fs::remove_dir_all(root).expect("remove fixtures");
}

#[cfg(unix)]
#[test]
fn authority_file_guard_leaves_a_replacement_path_untouched() {
    let root = temporary_directory();
    let path = root.join("authority.v2");
    let displaced = root.join("displaced.v2");
    let mut guard = FastAdapterAuthorityFileGuard::create(path.clone(), b"original-authority")
        .expect("create authority file");

    fs::rename(&path, &displaced).expect("move guarded authority");
    fs::write(&path, b"replacement").expect("write replacement");
    guard.remove().expect("guard handles replacement");

    assert_eq!(fs::read(&path).expect("read replacement"), b"replacement");
    assert_eq!(
        fs::read(&displaced).expect("read displaced authority"),
        b"original-authority"
    );
    fs::remove_dir_all(root).expect("remove fixtures");
}

#[cfg(unix)]
#[test]
fn authority_file_guard_fails_closed_on_a_dangling_destination_symlink() {
    use std::os::unix::fs::symlink;

    let root = temporary_directory();
    let path = root.join("authority.v2");
    let missing_target = root.join("missing-target");
    symlink(&missing_target, &path).expect("create dangling destination symlink");
    assert!(!path.exists());

    assert!(FastAdapterAuthorityFileGuard::create(path.clone(), b"authority").is_err());

    assert_eq!(
        fs::read_link(&path).expect("read preserved symlink"),
        missing_target
    );
    assert!(!temporary_handoff_path(&path).exists());

    let second_path = root.join("second-authority.v2");
    let second_partial = temporary_handoff_path(&second_path);
    symlink(&missing_target, &second_partial).expect("create dangling temporary symlink");
    assert!(FastAdapterAuthorityFileGuard::create(second_path.clone(), b"authority").is_err());
    assert!(!second_path.exists());
    assert_eq!(
        fs::read_link(&second_partial).expect("read preserved temporary symlink"),
        missing_target
    );
    fs::remove_dir_all(root).expect("remove fixtures");
}

#[cfg(unix)]
#[test]
fn authority_file_guard_reports_a_removal_failure() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = temporary_directory();
    let path = root.join("authority.v2");
    let mut guard = FastAdapterAuthorityFileGuard::create(path.clone(), b"authority")
        .expect("create authority file");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o500))
        .expect("make fixture directory read only");

    let removal = guard.remove();

    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("restore fixture directory permissions");
    assert!(removal.is_err());
    assert!(path.exists());
    guard.remove().expect("retry authority removal");
    assert!(!path.exists());
    fs::remove_dir_all(root).expect("remove fixtures");
}

#[cfg(unix)]
#[test]
fn authority_file_guard_reports_an_identity_lookup_failure() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = temporary_directory();
    let path = root.join("authority.v2");
    let mut guard = FastAdapterAuthorityFileGuard::create(path.clone(), b"authority")
        .expect("create authority file");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o000))
        .expect("make fixture directory inaccessible");

    let removal = guard.remove();

    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("restore fixture directory permissions");
    assert!(removal.is_err());
    assert!(path.exists());
    guard.remove().expect("retry authority removal");
    assert!(!path.exists());
    fs::remove_dir_all(root).expect("remove fixtures");
}

#[cfg(unix)]
#[test]
fn host_preflight_rejects_dangling_destination_and_temporary_symlinks() {
    use std::os::unix::fs::symlink;

    let root = temporary_directory();
    let missing_target = root.join("missing-target");

    let destination = root.join("destination.v2");
    symlink(&missing_target, &destination).expect("create dangling destination symlink");
    let mut output = Vec::new();
    assert!(
        prepare_fast_adapter_host_v1(&mut output, FastAdapterPathMode::Auto, &destination).is_err()
    );
    assert!(output.is_empty());

    let destination = root.join("temporary.v2");
    let temporary = temporary_handoff_path(&destination);
    symlink(&missing_target, &temporary).expect("create dangling temporary symlink");
    let mut output = Vec::new();
    assert!(
        prepare_fast_adapter_host_v1(&mut output, FastAdapterPathMode::Auto, &destination).is_err()
    );
    assert!(output.is_empty());

    fs::remove_dir_all(root).expect("remove fixtures");
}

#[test]
fn destination_named_partial_still_uses_a_distinct_temporary_path() {
    let root = temporary_directory();
    let destination = root.join("authority.PARTIAL");
    let mut output = Vec::new();
    prepare_fast_adapter_host_v1(&mut output, FastAdapterPathMode::RelayOnly, &destination)
        .expect("preflight destination whose extension differs only by case");
    assert!(!output.is_empty());

    let mut guard = FastAdapterAuthorityFileGuard::create(destination.clone(), b"authority")
        .expect("publish with a distinct appended temporary path");
    assert_eq!(
        fs::read(&destination).expect("read authority"),
        b"authority"
    );
    guard.remove().expect("remove authority");
    fs::remove_dir_all(root).expect("remove fixtures");
}

#[test]
fn public_entry_points_reject_hostile_handoff_files_before_network_work() {
    let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime");
    let root = temporary_directory();

    let empty = root.join("empty.v2");
    fs::write(&empty, []).expect("empty fixture");
    assert!(
        runtime
            .block_on(run_fast_adapter_join(
                FastAdapterPathMode::Auto,
                empty.clone()
            ))
            .is_err()
    );
    assert!(
        runtime
            .block_on(run_fast_adapter_host(FastAdapterPathMode::Auto, empty))
            .is_err()
    );

    let oversized = root.join("oversized.v2");
    fs::write(&oversized, vec![0_u8; MAX_FAST_OPERATOR_HANDOFF_BYTES + 1])
        .expect("oversized fixture");
    assert!(
        runtime
            .block_on(run_fast_adapter_join(FastAdapterPathMode::Auto, oversized))
            .is_err()
    );

    let malformed = root.join("malformed.v2");
    fs::write(&malformed, b"not-canonical-cbor").expect("malformed fixture");
    assert!(
        runtime
            .block_on(run_fast_adapter_join(
                FastAdapterPathMode::Auto,
                malformed.clone()
            ))
            .is_err()
    );

    assert!(
        runtime
            .block_on(run_fast_adapter_join(
                FastAdapterPathMode::Auto,
                root.clone()
            ))
            .is_err()
    );
    assert!(
        runtime
            .block_on(run_fast_adapter_host(
                FastAdapterPathMode::RelayOnly,
                root.join("missing/authority.v2"),
            ))
            .is_err()
    );
    assert!(
        runtime
            .block_on(run_fast_adapter_join(
                FastAdapterPathMode::Auto,
                root.join("missing.v2"),
            ))
            .is_err()
    );

    let overlong = PathBuf::from(format!("/{}", "x".repeat(4_097)));
    assert!(
        runtime
            .block_on(run_fast_adapter_host(
                FastAdapterPathMode::Auto,
                overlong.clone(),
            ))
            .is_err()
    );
    assert!(
        runtime
            .block_on(run_fast_adapter_join(
                FastAdapterPathMode::RelayOnly,
                overlong,
            ))
            .is_err()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let link = root.join("link.v2");
        symlink(&malformed, &link).expect("symlink fixture");
        assert!(
            runtime
                .block_on(run_fast_adapter_join(FastAdapterPathMode::Auto, link))
                .is_err()
        );

        let unreadable = root.join("unreadable.v2");
        fs::write(&unreadable, b"bounded-but-unreadable").expect("unreadable fixture");
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000))
            .expect("make fixture unreadable");
        assert!(
            runtime
                .block_on(run_fast_adapter_join(
                    FastAdapterPathMode::Auto,
                    unreadable.clone(),
                ))
                .is_err()
        );
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600))
            .expect("restore fixture permissions");
    }

    fs::remove_dir_all(root).expect("remove fixtures");
}

#[test]
fn join_rejects_a_handoff_path_mode_mismatch_before_public_network_work() {
    let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime");
    let root = temporary_directory();
    let handoff_path = root.join("authority.v2");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs();

    runtime.block_on(async {
        let endpoint = IrohFastEndpoint::bind_loopback()
            .await
            .expect("bind local endpoint");
        let encoded = issue_handoff(&endpoint, now, FastOperatorPathModeV1::Auto);
        fs::write(&handoff_path, encoded).expect("write handoff");

        assert!(
            run_fast_adapter_join(FastAdapterPathMode::RelayOnly, handoff_path.clone())
                .await
                .is_err()
        );
        endpoint
            .close(std::time::Duration::from_secs(5))
            .await
            .expect("close local endpoint");
    });

    fs::remove_dir_all(root).expect("remove fixtures");
}

fn issue_handoff(
    endpoint: &IrohFastEndpoint,
    now_unix_seconds: u64,
    mode: FastOperatorPathModeV1,
) -> Vec<u8> {
    let policy = FastMailboxPolicy::new(
        MAX_FAST_MAILBOX_LIFETIME_SECONDS,
        MAX_FAST_LIVE_MAILBOXES,
        MAX_FAST_ENVELOPES_PER_MAILBOX,
        MAX_FAST_RETAINED_BYTES_PER_MAILBOX,
    )
    .expect("valid mailbox policy");
    let mut service = IrohFastMailboxService::new(policy);
    service
        .issue_mailbox(endpoint.id(), now_unix_seconds + 300, now_unix_seconds)
        .expect("issue mailbox")
        .encode_operator_handoff_v2(mode)
        .expect("encode handoff")
        .to_vec()
}

#[test]
fn command_rejects_unknown_invocations_without_network_work() {
    for arguments in [
        vec!["host"],
        vec!["unknown", "auto", "/tmp/session-chat-unused"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_sessionctl-fast-adapter"))
            .args(arguments)
            .output()
            .expect("run rejected invocation");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(String::from_utf8(output.stderr).expect("UTF-8"), USAGE);
    }
}

#[cfg(unix)]
#[test]
fn command_rejects_non_utf8_modes_without_network_work() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt as _};

    for command in ["host", "join"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_sessionctl-fast-adapter"))
            .arg(command)
            .arg(OsString::from_vec(vec![0xff]))
            .arg("/tmp/session-chat-unused")
            .output()
            .expect("run rejected invocation");
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(String::from_utf8(output.stderr).expect("UTF-8"), USAGE);
    }
}

#[test]
fn command_rejects_bad_modes_and_paths_before_public_network_work() {
    for arguments in [
        vec!["host", "private", "/tmp/session-chat-unused"],
        vec!["join", "private", "/tmp/session-chat-unused"],
        vec!["host", "auto", "relative-authority"],
        vec!["join", "auto", "relative-authority"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_sessionctl-fast-adapter"))
            .args(arguments)
            .output()
            .expect("run rejected invocation");
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).expect("UTF-8"),
            "sessionctl-fast-adapter: Fast adapter evidence run failed\n"
        );
    }

    assert!(!Path::new("relative-authority").exists());
}

fn temporary_directory() -> PathBuf {
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "session-chat-fast-adapter-test-{}-{nonce}-{sequence}",
        std::process::id(),
    ));
    fs::create_dir(&path).expect("temporary directory");
    path
}

fn temporary_handoff_path(path: &Path) -> PathBuf {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".partial");
    PathBuf::from(temporary)
}
