//! Checked-build L2 process supervision and fresh verification foundation.
//!
//! This module is test infrastructure. It is compiled only under the
//! workspace-declared storage fault-testing cfg and has no runtime activation
//! path in an ordinary `sessionctl` build.
//!
//! Public consumers can name validated bundles:
//! ```
//! use sessionctl::l2_process::L2EvidenceBundle;
//! ```
//! Low-level evidence construction stays unavailable. Each import is checked
//! separately against the built library, without a second Cargo workspace.
//! ```compile_fail
//! use sessionctl::l2_process::L2EvidenceMetadata;
//! ```
//! ```compile_fail
//! use sessionctl::l2_process::L2EvidenceSweep;
//! ```
//! ```compile_fail
//! use sessionctl::l2_process::L2EvidenceChannels;
//! ```
//! ```compile_fail
//! use sessionctl::l2_process::promote_l2_evidence;
//! ```

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
use mls_rs_core::{
    group::{GroupState, GroupStateStorage},
    key_package::KeyPackageStorage,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use session_crypto_mls::{
    SessionGroupId, WelcomeMessage, create_client, create_durable_client_with_storage,
    create_key_package_validator, load_durable_client_with_storage,
};
use session_protocol::{DepositCapability, LocalWelcomeDepositEndpoint, OpaqueEnvelope};
use storage_sqlcipher::{
    InvitationState, InviterJoinTransaction, JoinerTransaction, MAXIMUM_WELCOME_DELIVERY_ATTEMPTS,
    PersistenceFault, SqlCipherStorage, StoreError, VaultKey, WelcomeOutboxState, fault_testing,
};
use zeroize::{Zeroize, Zeroizing};

use self::fault_testing::{
    BarrierFailure, BarrierTransport, CONTROL_FRAME_BYTES, CaseId, Checkpoint, ControlFrame,
    FaultObserver, FrameKind, OracleState, Role, Scenario,
};
use super::{
    SessionCtlError, provenance::repository_dirty_at, random_nonzero,
    resolve_l1_process_git_commit, stage,
};

mod controller;
mod database;
mod execution;
use database::{
    L2ArtifactSnapshot, collect_evidence_binding, encrypted_artifact_snapshot,
    open_keyed_connection, prove_database_handle_cleanup, schema_fingerprint, table_count,
    verify_connection_configuration,
};
mod fixtures;
mod resources;
mod verifier;
mod writer;
use controller::{CaseConfig, canonical_evidence_cases, pass_fail};
pub use controller::{
    L2IoPauseKillCase, prepare_l2_io_pause_kill_case, run_l2_io_baseline, run_l2_io_fault_case,
    run_l2_io_pause_writer, run_l2_process_baseline, run_l2_process_case,
    run_l2_process_internal_role, run_l2_process_probe,
};
use fixtures::{
    CaseFixture, inject_defective_schema, inject_identity_loss, inject_inviter_lifecycle_defect,
    inject_joiner_retained_key_package, inject_mixed_group, inject_reservation_substitution,
    prepare_baseline, read_fixture, read_optional_welcome_canary,
};
#[cfg(test)]
use resources::PipeReader;
use resources::{
    AutoContinueBarrier, ManagedChild, ProcessRoot, StdioBarrier, git_dirty_at, hex,
    lock_digest_at, pinned_toolchain_at, read_bounded_owned_file, read_bounded_owned_file_once,
    read_bounded_repository_file, read_case_config, read_key, read_owned_file, repository_root,
    sanitize_environment, validate_owned_file, validate_root, write_bounded_owned_file,
    write_owned_file,
};
#[cfg(test)]
use verifier::CheckpointTraversal;
use verifier::{advance_writer_to_target, database_digest, inject_retry_mutation, run_verifier};
use writer::{fixture_endpoint, run_real_storage_transaction, run_writer};
mod io_model;
mod model;
use execution::{ExecutableSnapshot, ExecutionIdentity};
pub use io_model::{
    L2IoBaselineObservation, L2IoBaselineReport, L2IoDriverObservation, L2IoFaultDriver,
    L2IoFaultMode, L2IoFaultObservation, L2IoFaultReport, L2IoFileRole, L2IoOperation,
    L2IoPauseDriver, L2IoPauseKillReport, L2IoPauseObservation, L2IoPauseSweepReport,
    L2IoSweepReport, L2IoSweepTarget,
};
use io_model::{L2IoPauseSweepCase, l2_io_pause_supported};
use model::{L2EvidenceBinding, L2EvidenceCase, L2EvidenceCaseTarget, oracle_label};
pub use model::{
    L2HarnessProbe, L2ProcessBaseline, L2ProcessCase, L2ProcessReport, L2ProcessSweepReport,
};
mod evidence;
pub mod welcome;
pub mod welcome_io;
pub use evidence::{L2EvidenceBundle, L2EvidenceManifest};

const ROOT_MARKER_NAME: &str = ".sessionctl-l2-root";
const ROOT_MARKER: &[u8] = b"sessionctl-l2-v1\n";
const CASE_CONFIG_NAME: &str = "case.config";
const WRITER_CASE_FIXTURE_NAME: &str = "writer.fixture";
const VERIFIER_CASE_FIXTURE_NAME: &str = "verifier.fixture";
const WELCOME_FIXTURE_NAME: &str = "welcome.fixture";
const DATABASE_NAME: &str = "case.sqlite3";
const WRITER_KEY_NAME: &str = "writer.key";
const VERIFIER_KEY_NAME: &str = "verifier.key";
const CASE_CONFIG_BYTES: usize = CONTROL_FRAME_BYTES + 1;
const CASE_FIXTURE_MAGIC: &[u8; 8] = b"SCL2FIX1";
const CASE_FIXTURE_BYTES: usize = 8 + 16 + 64 + 16 + 32 + 16 + 32 + 32 + 32;
const KEY_BYTES: usize = 32;
const MAX_CASE_ENTRIES: usize = 32;
const MAX_CHILD_OUTPUT_BYTES: usize = 512;
const MAX_EVIDENCE_BYTES: usize = 2_048;
const MAX_LOCKFILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOOLCHAIN_BYTES: usize = 4_096;
const MAX_DATABASE_BYTES: usize = 64 * 1024 * 1024;
const MAX_APPLICATION_CHECKPOINTS: usize = 192;
const FRAME_WAIT: Duration = Duration::from_secs(1);
const CHILD_WAIT: Duration = Duration::from_secs(2);
const CASE_WAIT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const BASELINE_NOW: u64 = 1_900_000_000;
const RESERVATION_EXPIRES_AT: u64 = BASELINE_NOW + 300;
const OUTBOX_EXPIRES_AT: u64 = BASELINE_NOW + 180;
const APPROVAL_RECORD: &[u8] = b"l2-approved";
const EXPECTED_SCHEMA_VERSION: u32 = 6;
const SCHEMA_FINGERPRINT_SHA256: &str =
    "2ea478c22099a3aeae70bd21788a1292879f217db3b73b30b4cfa7289642eb36";

#[cfg(test)]
mod tests {
    use super::*;

    fn test_evidence_binding() -> L2EvidenceBinding {
        L2EvidenceBinding {
            executables: Some(ExecutionIdentity::fixture()),
            sqlcipher_version: String::from("4.14.0"),
            sqlite_version: String::from("3.50.4"),
            baseline_artifact_digest: [0x11; 32],
            post_recovery_artifact_digest: [0x22; 32],
            redaction: true,
        }
    }

    fn test_evidence_case(key: &str, ordinal: u16) -> L2EvidenceCase {
        L2EvidenceCase {
            key: key.to_owned(),
            target: L2EvidenceCaseTarget::ApplicationCheckpoint {
                checkpoint: "INVITER_BEFORE_BEGIN",
                ordinal,
                expected: "I0",
                observed: "I0",
            },
            binding: test_evidence_binding(),
        }
    }

    #[test]
    fn evidence_case_index_is_canonical_across_input_permutations() {
        let first = test_evidence_case("checkpoint-a-0", 0);
        let second = test_evidence_case("checkpoint-b-1", 1);
        let forward = canonical_evidence_cases(vec![first.clone(), second.clone()])
            .expect("forward case index");
        let reversed = canonical_evidence_cases(vec![second, first]).expect("reversed case index");
        assert!(forward == reversed);

        let duplicate = test_evidence_case("checkpoint-a-0", 2);
        assert!(canonical_evidence_cases(vec![forward[0].clone(), duplicate]).is_err());
    }

    #[test]
    fn mixed_verifier_producer_or_fault_driver_reports_cannot_form_an_aggregate() {
        let first = test_evidence_case("checkpoint-a-0", 0);
        for role in 0..3 {
            let mut second = test_evidence_case("checkpoint-b-1", 1);
            let identity = second.binding.executables.as_mut().unwrap();
            match role {
                0 => identity.verifier = [1; 32],
                1 => identity.producer = [2; 32],
                _ => identity.fault_driver = Some([3; 32]),
            }
            assert!(canonical_evidence_cases(vec![first.clone(), second]).is_err());
        }
    }

    #[test]
    fn canonical_checkpoint_traversal_accepts_the_maximum_depth_legal_trace() {
        let case_id = CaseId::new([0xA5; 16]).expect("case ID");
        let target =
            ControlFrame::new_checkpoint(case_id, Checkpoint::InviterBeforeShadowFinalize, 0)
                .expect("target");
        let mut traversal = CheckpointTraversal::new(target).expect("traversal");
        let mut frames = vec![
            ControlFrame::new_checkpoint(case_id, Checkpoint::InviterBeforeBegin, 0)
                .expect("before begin"),
            ControlFrame::new_checkpoint(case_id, Checkpoint::InviterAfterGroupUpsert, 0)
                .expect("group upsert"),
        ];
        for occurrence in 0..64 {
            frames.push(
                ControlFrame::new_checkpoint(
                    case_id,
                    Checkpoint::InviterAfterEpochInsert,
                    occurrence,
                )
                .expect("epoch insert"),
            );
        }
        for occurrence in 0..64 {
            frames.push(
                ControlFrame::new_checkpoint(
                    case_id,
                    Checkpoint::InviterAfterEpochUpdate,
                    occurrence,
                )
                .expect("epoch update"),
            );
        }
        for checkpoint in [
            Checkpoint::InviterAfterJoinInsert,
            Checkpoint::InviterAfterReservationConsumed,
            Checkpoint::InviterBeforeCommit,
            Checkpoint::InviterAfterCommitReturn,
            Checkpoint::InviterBeforeShadowFinalize,
        ] {
            frames.push(
                ControlFrame::new_checkpoint(case_id, checkpoint, 0).expect("later checkpoint"),
            );
        }

        assert!(frames.len() > 64);
        assert!(frames.len() <= MAX_APPLICATION_CHECKPOINTS);
        for frame in &frames[..frames.len() - 1] {
            assert!(!traversal.observe(*frame).expect("ordered checkpoint"));
        }
        assert!(
            traversal
                .observe(*frames.last().expect("target frame"))
                .expect("target checkpoint")
        );
    }

    #[test]
    fn pipe_failures_keep_distinct_secret_free_causes() {
        struct FailedRead;
        impl Read for FailedRead {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("must never appear in diagnostics"))
            }
        }
        let mut reader = PipeReader::new(FailedRead);
        assert!(matches!(
            reader.collect(CHILD_WAIT),
            Err(SessionCtlError::Stage("L2 output read"))
        ));

        let mut reader = PipeReader::new(std::io::Cursor::new(vec![0; MAX_CHILD_OUTPUT_BYTES + 1]));
        assert!(matches!(
            reader.collect(CHILD_WAIT),
            Err(SessionCtlError::Stage("L2 output bound"))
        ));

        let (sender, receiver) = mpsc::channel();
        let mut reader = PipeReader {
            receiver,
            join: None,
            buffered: Vec::new(),
            eof: false,
        };
        assert!(matches!(
            reader.collect(Duration::from_millis(1)),
            Err(SessionCtlError::Stage("L2 output timeout"))
        ));
        drop(sender);
        assert!(matches!(
            reader.collect(CHILD_WAIT),
            Err(SessionCtlError::Stage("L2 output disconnected"))
        ));
    }

    #[test]
    fn pipe_interrupted_read_preserves_the_exact_frame() {
        struct InterruptedOnce(bool);
        impl Read for InterruptedOnce {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                if !std::mem::replace(&mut self.0, true) {
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                bytes[..3].copy_from_slice(b"abc");
                Ok(3)
            }
        }
        let mut reader = PipeReader::new(InterruptedOnce(false).take(3));
        assert_eq!(reader.read_exact_frame(3, CHILD_WAIT).unwrap(), b"abc");
        reader
            .require_empty(CHILD_WAIT)
            .expect("EOF after exact frame");
    }

    #[test]
    fn inherited_child_output_cannot_block_pipe_reader_drop() {
        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command
            .args([
                "--exact",
                "l2_process::tests::inherited_output_parent",
                "--nocapture",
            ])
            .env("SESSIONCTL_L2_INHERITED_OUTPUT_PARENT", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let started = Instant::now();
        let mut child = ManagedChild::spawn_command(command).expect("spawn output parent");
        assert!(
            child
                .wait(Duration::from_secs(1))
                .expect("parent exit")
                .success()
        );
        assert!(child.stdout.collect(Duration::from_millis(25)).is_err());
        drop(child);
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn inherited_output_parent() {
        if std::env::var_os("SESSIONCTL_L2_INHERITED_OUTPUT_PARENT").is_some() {
            let mut descendant =
                Command::new(std::env::current_exe().expect("current test executable"))
                    .args([
                        "--exact",
                        "l2_process::tests::inherited_output_descendant",
                        "--nocapture",
                    ])
                    .env("SESSIONCTL_L2_INHERITED_OUTPUT_DESCENDANT", "1")
                    .spawn()
                    .expect("spawn output descendant");
            thread::spawn(move || {
                let _ = descendant.wait();
            });
        }
    }

    #[test]
    fn inherited_output_descendant() {
        if std::env::var_os("SESSIONCTL_L2_INHERITED_OUTPUT_DESCENDANT").is_some() {
            thread::sleep(Duration::from_secs(2));
        }
    }

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

    #[test]
    fn production_schema_fingerprint_is_frozen() {
        let mut root = ProcessRoot::new().expect("L2 root");
        let key = Zeroizing::new([0x55; KEY_BYTES]);
        let storage = SqlCipherStorage::create(
            &root.path().join(DATABASE_NAME),
            VaultKey::new(*key).expect("key"),
        )
        .expect("storage");
        drop(storage);
        let connection = open_keyed_connection(&root.path().join(DATABASE_NAME), &key)
            .expect("keyed connection");
        assert_eq!(
            schema_fingerprint(&connection).expect("schema fingerprint"),
            SCHEMA_FINGERPRINT_SHA256
        );
        drop(connection);
        root.cleanup().expect("cleanup");
    }

    #[test]
    fn sanitized_git_metadata_reports_a_dirty_state_instead_of_becoming_unavailable() {
        assert!(
            git_dirty_at(&repository_root()).is_some(),
            "sanitized Git metadata must tolerate the platform temporary-directory environment",
        );
    }

    #[test]
    fn clean_baseline_and_pause_aggregate_reject_old_state() {
        let target = L2IoSweepTarget::new(L2IoFileRole::RollbackJournal, L2IoOperation::Write, 1)
            .expect("baseline target");
        let observation =
            L2IoBaselineObservation::new(vec![target], 0, 1).expect("baseline observation");
        assert!(
            L2IoBaselineReport::new(
                Scenario::InviterTransaction,
                OracleState::InviterOld,
                observation,
                true,
                true,
                true,
                true,
                test_evidence_binding(),
            )
            .is_err()
        );

        let old_baseline = L2IoBaselineReport {
            scenario: Scenario::InviterTransaction,
            observed: OracleState::InviterOld,
            baseline: L2IoBaselineObservation::new(vec![target], 0, 1)
                .expect("old baseline observation"),
            fixture_cleanup: true,
            handle_cleanup: true,
            child_cleanup: true,
            directory_cleanup: true,
            _evidence_binding: test_evidence_binding(),
        };
        let old_pause_case = L2IoPauseKillReport {
            scenario: Scenario::InviterTransaction,
            observed: OracleState::InviterOld,
            pause: L2IoPauseObservation::new(
                L2IoFileRole::RollbackJournal,
                L2IoOperation::Write,
                0,
                0,
                1,
            )
            .expect("pause observation"),
            fixture_cleanup: true,
            handle_cleanup: true,
            child_cleanup: true,
            directory_cleanup: true,
            evidence_binding: test_evidence_binding(),
        };
        assert!(
            L2IoPauseSweepReport::new(
                Scenario::InviterTransaction,
                &old_baseline,
                &[old_pause_case],
            )
            .is_err()
        );
    }
}
