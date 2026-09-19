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
mod execution;
mod fixtures;
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

fn run_writer(root: &Path) -> Result<(), SessionCtlError> {
    let config = read_case_config(root)?;
    let fixture = read_fixture(root, WRITER_CASE_FIXTURE_NAME)?;
    let key = read_key(root, WRITER_KEY_NAME)?;
    let transport = std::sync::Arc::new(StdioBarrier::default());
    let observer = FaultObserver::new(config.target.case_id(), config.target.scenario(), transport);
    let storage = fault_testing::open(
        &root.join(DATABASE_NAME),
        VaultKey::new(*key).map_err(|_| stage("L2 writer"))?,
        observer.clone(),
    )
    .map_err(|_| stage("L2 writer"))?;

    match config.probe {
        L2HarnessProbe::GracefulContinue
        | L2HarnessProbe::KillWhileBlocked
        | L2HarnessProbe::MixedFixture
        | L2HarnessProbe::IdentityLoss
        | L2HarnessProbe::ReservationSubstitution
        | L2HarnessProbe::DefectiveSchema
        | L2HarnessProbe::LingeringHandle
        | L2HarnessProbe::NonzeroLeaseGeneration
        | L2HarnessProbe::ChangedAttemptCeiling
        | L2HarnessProbe::InviterRetryMutation
        | L2HarnessProbe::JoinerRetryMutation
        | L2HarnessProbe::JoinerRetainedKeyPackage
        | L2HarnessProbe::MissingAcknowledgement => run_real_storage_transaction(
            &storage,
            observer,
            config.target.scenario(),
            &fixture,
            root,
        ),
        L2HarnessProbe::IoFault => Err(stage("L2 writer mode")),
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

fn run_real_storage_transaction(
    storage: &SqlCipherStorage,
    observer: FaultObserver,
    scenario: Scenario,
    fixture: &CaseFixture,
    root: &Path,
) -> Result<(), SessionCtlError> {
    let group_id = SessionGroupId::new(fixture.group_id).map_err(|_| stage("L2 writer group"))?;
    match scenario {
        Scenario::InviterTransaction => {
            let alice = load_durable_client_with_storage(
                group_id,
                storage.clone(),
                storage.clone(),
                storage.clone(),
            )
            .map_err(|_| stage("L2 writer identity"))?;
            let mut group = alice
                .create_group(group_id, BASELINE_NOW)
                .map_err(|_| stage("L2 writer group"))?;
            let bob = create_client().map_err(|_| stage("L2 writer peer"))?;
            let key_package = bob
                .generate_key_package(BASELINE_NOW)
                .map_err(|_| stage("L2 writer KeyPackage"))?;
            let validated = create_key_package_validator()
                .validate_key_package(key_package.as_bytes(), BASELINE_NOW)
                .map_err(|_| stage("L2 writer KeyPackage"))?;
            let addition = group
                .prepare_add(validated, BASELINE_NOW)
                .map_err(|_| stage("L2 writer Add"))?
                .apply()
                .map_err(|_| stage("L2 writer Add"))?;
            let endpoint = fixture_endpoint()?;
            let persisted = addition
                .stage_and_write_to_storage(&mut group, |binding| {
                    let transaction = InviterJoinTransaction::new_bound(
                        fixture.transaction_id,
                        fixture.invitation_id,
                        fixture.invitation_generation,
                        fixture.join_request_id,
                        fixture.request_fingerprint,
                        fixture.group_id,
                        0,
                        1,
                        APPROVAL_RECORD.to_vec(),
                        [0x81; 16],
                        OUTBOX_EXPIRES_AT,
                        endpoint,
                        OUTBOX_EXPIRES_AT,
                    )
                    .map_err(|_| StoreError::Rejected)?;
                    storage.stage_bound_inviter(
                        binding,
                        transaction,
                        BASELINE_NOW,
                        PersistenceFault::None,
                    )
                })
                .map_err(|_| stage("L2 writer transaction"))?;
            let envelope = OpaqueEnvelope::new(
                [0x81; 16],
                OUTBOX_EXPIRES_AT,
                persisted.welcome().as_bytes().to_vec(),
            )
            .map_err(|_| stage("L2 writer Welcome"))?
            .encode_canonical()
            .map_err(|_| stage("L2 writer Welcome"))?;
            write_bounded_owned_file(&root.join(WELCOME_FIXTURE_NAME), &envelope, true, 65_536)?;
            observer
                .checkpoint(Checkpoint::InviterBeforeShadowFinalize, 0)
                .map_err(|_| stage("L2 writer barrier"))?;
        }
        Scenario::JoinerTransaction => {
            let bob = load_durable_client_with_storage(
                group_id,
                storage.clone(),
                storage.clone(),
                storage.clone(),
            )
            .map_err(|_| stage("L2 writer identity"))?;
            let welcome_bytes = read_bounded_owned_file_once(
                &root.join(WELCOME_FIXTURE_NAME),
                65_536,
                "L2 Welcome fixture cleanup",
            )?;
            let welcome = WelcomeMessage::from_bytes(&welcome_bytes)
                .map_err(|_| stage("L2 writer Welcome"))?;
            let mut group = bob
                .join_group(welcome, BASELINE_NOW)
                .map_err(|_| stage("L2 writer join"))?;
            storage
                .stage_joiner(
                    JoinerTransaction::new(
                        fixture.transaction_id,
                        fixture.group_id,
                        fixture.key_package_reference,
                    )
                    .map_err(|_| stage("L2 writer transaction"))?,
                    PersistenceFault::None,
                )
                .map_err(|_| stage("L2 writer transaction"))?;
            group
                .write_to_storage()
                .map_err(|_| stage("L2 writer transaction"))?;
        }
    }
    Ok(())
}

fn fixture_endpoint() -> Result<Vec<u8>, SessionCtlError> {
    LocalWelcomeDepositEndpoint::new(
        [0x82; 16],
        [0x83; 16],
        DepositCapability::new([0x84; 32]).map_err(|_| stage("L2 endpoint"))?,
        OUTBOX_EXPIRES_AT,
    )
    .map_err(|_| stage("L2 endpoint"))?
    .encode_canonical()
    .map_err(|_| stage("L2 endpoint"))
}

fn run_verifier(root: &Path) -> Result<(), SessionCtlError> {
    let config = read_case_config(root)?;
    let fixture = read_fixture(root, VERIFIER_CASE_FIXTURE_NAME)?;
    let key = read_key(root, VERIFIER_KEY_NAME)?;
    let expected = if config.probe == L2HarnessProbe::IoFault {
        classify_io_oracle_state(root, &key, config.target.scenario(), &fixture)?
    } else {
        config.case()?.expected()
    };
    let outcome = verify_complete_state(
        root,
        &key,
        expected,
        config.target.checkpoint(),
        &fixture,
        config.probe,
    )?;
    if config.probe == L2HarnessProbe::LingeringHandle {
        let _connection = open_keyed_connection(&root.join(DATABASE_NAME), &key)?;
        thread::sleep(Duration::from_secs(10));
        return Err(stage("L2 lingering verifier"));
    }
    match outcome {
        VerificationOutcome::Complete => print!(
            "role=verifier\nresult=pass\noracle={}\nintegrity=pass\nschema=pass\nsemantic_oracle=pass\nexclusive_lock=pass\nexact_retry=pass\n",
            oracle_label(expected)
        ),
        VerificationOutcome::RetryConflict => print!(
            "role=verifier\nresult=retry-conflict-rejected\noracle={}\nconflict=exact\nmutation_free=pass\n",
            oracle_label(expected)
        ),
    }
    Ok(())
}

fn classify_io_oracle_state(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    scenario: Scenario,
    fixture: &CaseFixture,
) -> Result<OracleState, SessionCtlError> {
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;
    let table = match scenario {
        Scenario::InviterTransaction => "inviter_joins",
        Scenario::JoinerTransaction => "joiner_commits",
    };
    let sql = format!("SELECT count(*) FROM {table} WHERE transaction_id = ?1");
    let count: i64 = connection
        .query_row(&sql, params![fixture.transaction_id], |row| row.get(0))
        .map_err(|_| stage("L2 I/O oracle classification"))?;
    match (scenario, count) {
        (Scenario::InviterTransaction, 0) => Ok(OracleState::InviterOld),
        (Scenario::InviterTransaction, 1) => Ok(OracleState::InviterNew),
        (Scenario::JoinerTransaction, 0) => Ok(OracleState::JoinerOld),
        (Scenario::JoinerTransaction, 1) => Ok(OracleState::JoinerNew),
        _ => Err(stage("L2 I/O oracle classification")),
    }
}

enum VerificationOutcome {
    Complete,
    RetryConflict,
}

fn verify_complete_state(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    expected: OracleState,
    checkpoint: Checkpoint,
    fixture: &CaseFixture,
    probe: L2HarnessProbe,
) -> Result<VerificationOutcome, SessionCtlError> {
    let storage = SqlCipherStorage::open(
        &root.join(DATABASE_NAME),
        VaultKey::new(**key).map_err(|_| stage("L2 production reopen"))?,
    )
    .map_err(|_| stage("L2 production reopen"))?;
    if storage.schema_version().map_err(|_| stage("L2 schema"))? != EXPECTED_SCHEMA_VERSION
        || storage
            .cipher_version()
            .map_err(|_| stage("L2 cipher"))?
            .is_empty()
        || !storage
            .integrity_check()
            .map_err(|_| stage("L2 cipher integrity"))?
    {
        return Err(stage("L2 production reopen"));
    }
    verify_production_semantics(&storage, expected, fixture)?;
    drop(storage);

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

    verify_connection_configuration(&connection)?;
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
    let expected_schema_version = i64::from(EXPECTED_SCHEMA_VERSION);
    if user_version != expected_schema_version
        || metadata != (1, expected_schema_version, expected_schema_version)
        || schema_fingerprint(&connection)? != SCHEMA_FINGERPRINT_SHA256
    {
        return Err(stage("L2 schema"));
    }
    let welcome_path = root.join(WELCOME_FIXTURE_NAME);
    let expected_welcome = if expected == OracleState::InviterNew {
        let bytes = if welcome_path.exists() {
            read_bounded_owned_file_once(&welcome_path, 65_536, "L2 Welcome fixture cleanup")?
        } else if checkpoint == Checkpoint::InviterAfterCommitReturn
            || probe == L2HarnessProbe::IoFault
        {
            committed_welcome(&connection, fixture)?
        } else {
            return Err(stage("L2 Welcome fixture"));
        };
        validate_committed_welcome(&bytes)?;
        Some(bytes)
    } else {
        if welcome_path.exists() {
            drop(read_bounded_owned_file_once(
                &welcome_path,
                65_536,
                "L2 Welcome fixture cleanup",
            )?);
        }
        None
    };
    let expected_welcome_bytes = expected_welcome.as_ref().map(|bytes| bytes.as_slice());
    verify_exact_sql_state(&connection, expected, fixture, expected_welcome_bytes)?;
    connection
        .execute_batch("BEGIN EXCLUSIVE; ROLLBACK;")
        .map_err(|_| stage("L2 exclusive lock"))?;
    drop(foreign);
    drop(cipher);
    drop(connection);

    let before_retry = database_digest(root)?;
    let retry_mutation = match probe {
        L2HarnessProbe::InviterRetryMutation => {
            inject_retry_mutation(root, key, fixture, Scenario::InviterTransaction)?;
            Some(Scenario::InviterTransaction)
        }
        L2HarnessProbe::JoinerRetryMutation => {
            inject_retry_mutation(root, key, fixture, Scenario::JoinerTransaction)?;
            Some(Scenario::JoinerTransaction)
        }
        _ => None,
    };
    if let Some(scenario) = retry_mutation {
        let injected_digest = database_digest(root)?;
        require_exact_retry_conflict(root, key, expected, fixture, expected_welcome_bytes)?;
        if database_digest(root)? != injected_digest {
            return Err(stage("L2 retry conflict mutation"));
        }
        verify_retry_mutation(root, key, fixture, scenario)?;
        return Ok(VerificationOutcome::RetryConflict);
    }
    perform_exact_retry(root, key, expected, fixture, expected_welcome_bytes)?;
    if database_digest(root)? != before_retry {
        return Err(stage("L2 exact retry digest"));
    }
    Ok(VerificationOutcome::Complete)
}

fn committed_welcome(
    connection: &Connection,
    fixture: &CaseFixture,
) -> Result<Zeroizing<Vec<u8>>, SessionCtlError> {
    let welcome = connection
        .query_row(
            "SELECT welcome FROM inviter_joins WHERE transaction_id = ?1",
            params![fixture.transaction_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|_| stage("L2 inviter Welcome oracle"))?
        .ok_or_else(|| stage("L2 inviter Welcome oracle"))?;
    if welcome.len() > 65_536 {
        return Err(stage("L2 inviter Welcome oracle"));
    }
    Ok(Zeroizing::new(welcome))
}

fn validate_committed_welcome(welcome: &[u8]) -> Result<(), SessionCtlError> {
    let envelope = OpaqueEnvelope::decode_canonical(welcome)
        .map_err(|_| stage("L2 inviter Welcome oracle"))?;
    if envelope.envelope_id() != &[0x81; 16]
        || envelope.expires_at_unix_seconds() != OUTBOX_EXPIRES_AT
        || WelcomeMessage::from_bytes(envelope.ciphertext()).is_err()
    {
        return Err(stage("L2 inviter Welcome oracle"));
    }
    Ok(())
}

fn database_digest(root: &Path) -> Result<[u8; 32], SessionCtlError> {
    let bytes = Zeroizing::new(read_bounded_owned_file(
        &root.join(DATABASE_NAME),
        MAX_DATABASE_BYTES,
    )?);
    digest(&SHA256, &bytes)
        .as_ref()
        .try_into()
        .map_err(|_| stage("L2 database digest"))
}

fn inject_retry_mutation(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    fixture: &CaseFixture,
    scenario: Scenario,
) -> Result<(), SessionCtlError> {
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;
    let (sql, value): (&str, &[u8]) = match scenario {
        Scenario::InviterTransaction => (
            "UPDATE inviter_joins SET approval_record = ?1 WHERE transaction_id = ?2",
            b"l2-retry-defect",
        ),
        Scenario::JoinerTransaction => (
            "UPDATE joiner_commits SET key_package_ref = ?1 WHERE transaction_id = ?2",
            &[0xD1; 32],
        ),
    };
    if connection
        .execute(sql, params![value, fixture.transaction_id])
        .map_err(|_| stage("L2 retry defect"))?
        != 1
    {
        return Err(stage("L2 retry defect"));
    }
    Ok(())
}

fn perform_exact_retry(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    expected: OracleState,
    fixture: &CaseFixture,
    expected_welcome: Option<&[u8]>,
) -> Result<(), SessionCtlError> {
    if matches!(expected, OracleState::InviterOld | OracleState::JoinerOld) {
        return Ok(());
    }
    let (mut storage, state) = prepare_exact_retry(root, key, expected, fixture, expected_welcome)?;
    GroupStateStorage::write(&mut storage, state, Vec::new(), Vec::new())
        .map_err(|_| stage("L2 exact retry"))?;
    if expected == OracleState::JoinerNew {
        KeyPackageStorage::delete(&mut storage, &fixture.key_package_reference)
            .map_err(|_| stage("L2 exact retry"))?;
    }
    verify_production_semantics(&storage, expected, fixture)
}

fn require_exact_retry_conflict(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    expected: OracleState,
    fixture: &CaseFixture,
    expected_welcome: Option<&[u8]>,
) -> Result<(), SessionCtlError> {
    let (mut storage, state) = prepare_exact_retry(root, key, expected, fixture, expected_welcome)?;
    if GroupStateStorage::write(&mut storage, state, Vec::new(), Vec::new())
        != Err(StoreError::Conflict)
    {
        return Err(stage("L2 retry conflict outcome"));
    }
    drop(storage);
    Ok(())
}

fn prepare_exact_retry(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    expected: OracleState,
    fixture: &CaseFixture,
    expected_welcome: Option<&[u8]>,
) -> Result<(SqlCipherStorage, GroupState), SessionCtlError> {
    let storage = SqlCipherStorage::open(
        &root.join(DATABASE_NAME),
        VaultKey::new(**key).map_err(|_| stage("L2 exact retry"))?,
    )
    .map_err(|_| stage("L2 exact retry"))?;
    let state = GroupState {
        id: fixture.group_id.to_vec(),
        data: GroupStateStorage::state(&storage, &fixture.group_id)
            .map_err(|_| stage("L2 exact retry"))?
            .ok_or_else(|| stage("L2 exact retry"))?,
    };
    match expected {
        OracleState::InviterNew => {
            let welcome = expected_welcome.ok_or_else(|| stage("L2 exact retry"))?;
            storage
                .stage_inviter(
                    InviterJoinTransaction::new(
                        fixture.transaction_id,
                        fixture.invitation_id,
                        fixture.invitation_generation,
                        fixture.join_request_id,
                        fixture.request_fingerprint,
                        fixture.group_id,
                        0,
                        1,
                        APPROVAL_RECORD.to_vec(),
                        welcome.to_vec(),
                        fixture_endpoint()?,
                        OUTBOX_EXPIRES_AT,
                    )
                    .map_err(|_| stage("L2 exact retry"))?,
                    BASELINE_NOW,
                    PersistenceFault::None,
                )
                .map_err(|_| stage("L2 exact retry"))?;
        }
        OracleState::JoinerNew => {
            storage
                .stage_joiner(
                    JoinerTransaction::new(
                        fixture.transaction_id,
                        fixture.group_id,
                        fixture.key_package_reference,
                    )
                    .map_err(|_| stage("L2 exact retry"))?,
                    PersistenceFault::None,
                )
                .map_err(|_| stage("L2 exact retry"))?;
        }
        OracleState::InviterOld | OracleState::JoinerOld => {
            return Err(stage("L2 exact retry oracle"));
        }
    }
    Ok((storage, state))
}

fn verify_retry_mutation(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    fixture: &CaseFixture,
    scenario: Scenario,
) -> Result<(), SessionCtlError> {
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;
    let retained = match scenario {
        Scenario::InviterTransaction => connection
            .query_row(
                "SELECT approval_record FROM inviter_joins WHERE transaction_id = ?1",
                params![fixture.transaction_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map(|value| value == b"l2-retry-defect")
            .map_err(|_| stage("L2 retry conflict state"))?,
        Scenario::JoinerTransaction => connection
            .query_row(
                "SELECT key_package_ref FROM joiner_commits WHERE transaction_id = ?1",
                params![fixture.transaction_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map(|value| value == [0xD1; 32])
            .map_err(|_| stage("L2 retry conflict state"))?,
    };
    if !retained {
        return Err(stage("L2 retry conflict state"));
    }
    Ok(())
}

struct CheckpointTrace {
    target: ControlFrame,
    cases: Vec<L2ProcessCase>,
}

fn advance_writer_to_target(
    writer: &mut ManagedChild,
    target: ControlFrame,
) -> Result<CheckpointTrace, SessionCtlError> {
    let mut traversal = CheckpointTraversal::new(target)?;
    let mut cases = Vec::new();
    let deadline = Instant::now()
        .checked_add(CASE_WAIT)
        .ok_or_else(|| stage("L2 case timeout"))?;
    for _ in 0..MAX_APPLICATION_CHECKPOINTS {
        let wait = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| stage("L2 case timeout"))?
            .min(FRAME_WAIT);
        let encoded = writer.stdout.read_exact_frame(CONTROL_FRAME_BYTES, wait)?;
        let observed = ControlFrame::decode(&encoded).map_err(|_| stage("L2 checkpoint"))?;
        let case = L2ProcessCase::new(observed.checkpoint(), observed.occurrence())?;
        if traversal.observe(observed)? {
            cases.push(case);
            return Ok(CheckpointTrace {
                target: observed,
                cases,
            });
        }
        cases.push(case);
        writer.write_stdin(&observed.acknowledgement().encode())?;
    }
    Err(stage("L2 checkpoint bound"))
}

struct CheckpointTraversal {
    target: ControlFrame,
    checkpoints: &'static [Checkpoint],
    target_position: usize,
    previous: Option<(usize, u8)>,
}

impl CheckpointTraversal {
    fn new(target: ControlFrame) -> Result<Self, SessionCtlError> {
        let checkpoints = scenario_checkpoints(target.scenario());
        let target_position = checkpoints
            .iter()
            .position(|checkpoint| *checkpoint == target.checkpoint())
            .ok_or_else(|| stage("L2 checkpoint"))?;
        Ok(Self {
            target,
            checkpoints,
            target_position,
            previous: None,
        })
    }

    fn observe(&mut self, observed: ControlFrame) -> Result<bool, SessionCtlError> {
        if observed.case_id() != self.target.case_id()
            || observed.scenario() != self.target.scenario()
            || observed.role() != Role::Writer
        {
            return Err(stage("L2 checkpoint"));
        }
        let position = self
            .checkpoints
            .iter()
            .position(|checkpoint| *checkpoint == observed.checkpoint())
            .ok_or_else(|| stage("L2 checkpoint"))?;
        if let Some((previous_position, previous_occurrence)) = self.previous {
            let ordered = if position == previous_position {
                observed.occurrence() == previous_occurrence.saturating_add(1)
            } else {
                position > previous_position && observed.occurrence() == 0
            };
            if !ordered {
                return Err(stage("L2 checkpoint"));
            }
        } else if observed.occurrence() != 0 {
            return Err(stage("L2 checkpoint"));
        }
        self.previous = Some((position, observed.occurrence()));
        if observed == self.target {
            return Ok(true);
        }
        if position > self.target_position
            || (position == self.target_position
                && observed.occurrence() >= self.target.occurrence())
        {
            return Err(stage("L2 checkpoint"));
        }
        Ok(false)
    }
}

fn scenario_checkpoints(scenario: Scenario) -> &'static [Checkpoint] {
    match scenario {
        Scenario::InviterTransaction => &[
            Checkpoint::InviterBeforeBegin,
            Checkpoint::InviterAfterGroupUpsert,
            Checkpoint::InviterAfterEpochInsert,
            Checkpoint::InviterAfterEpochUpdate,
            Checkpoint::InviterAfterJoinInsert,
            Checkpoint::InviterAfterReservationConsumed,
            Checkpoint::InviterBeforeCommit,
            Checkpoint::InviterAfterCommitReturn,
            Checkpoint::InviterBeforeShadowFinalize,
        ],
        Scenario::JoinerTransaction => &[
            Checkpoint::JoinerBeforeBegin,
            Checkpoint::JoinerAfterGroupUpsert,
            Checkpoint::JoinerAfterEpochInsert,
            Checkpoint::JoinerAfterEpochUpdate,
            Checkpoint::JoinerAfterCommitInsert,
            Checkpoint::JoinerBeforeKeyPackageDelete,
            Checkpoint::JoinerAfterKeyPackageDelete,
            Checkpoint::JoinerBeforeCommit,
            Checkpoint::JoinerAfterCommitReturn,
        ],
    }
}

fn verify_production_semantics(
    storage: &SqlCipherStorage,
    expected: OracleState,
    fixture: &CaseFixture,
) -> Result<(), SessionCtlError> {
    let group_id = SessionGroupId::new(fixture.group_id).map_err(|_| stage("L2 oracle group"))?;
    match expected {
        OracleState::InviterOld => {
            if storage
                .invitation_state(&fixture.invitation_id)
                .map_err(|_| stage("L2 invitation oracle"))?
                != Some(InvitationState::Reserved)
                || storage
                    .recover_inviter(&fixture.transaction_id)
                    .map_err(|_| stage("L2 inviter oracle"))?
                    .is_some()
            {
                return Err(stage("L2 inviter oracle"));
            }
            let client = load_durable_client_with_storage(
                group_id,
                storage.clone(),
                storage.clone(),
                storage.clone(),
            )
            .map_err(|_| stage("L2 identity oracle"))?;
            if client.credential_identity().as_bytes() != &fixture.credential_identity {
                return Err(stage("L2 identity oracle"));
            }
        }
        OracleState::InviterNew => {
            let recovery = storage
                .recover_inviter(&fixture.transaction_id)
                .map_err(|_| stage("L2 inviter oracle"))?
                .ok_or_else(|| stage("L2 inviter oracle"))?;
            if recovery.epoch_after != 1
                || recovery.outbox_state != WelcomeOutboxState::Pending
                || recovery.delivery_attempts != 0
                || storage
                    .invitation_state(&fixture.invitation_id)
                    .map_err(|_| stage("L2 invitation oracle"))?
                    != Some(InvitationState::Consumed)
            {
                return Err(stage("L2 inviter oracle"));
            }
            let client = load_durable_client_with_storage(
                group_id,
                storage.clone(),
                storage.clone(),
                storage.clone(),
            )
            .map_err(|_| stage("L2 identity oracle"))?;
            if client.credential_identity().as_bytes() != &fixture.credential_identity {
                return Err(stage("L2 identity oracle"));
            }
            let group = client
                .load_group(group_id)
                .map_err(|_| stage("L2 MLS reload oracle"))?;
            if group.epoch() != 1 || group.member_count() != 2 {
                return Err(stage("L2 MLS reload oracle"));
            }
        }
        OracleState::JoinerOld => {
            if !storage
                .key_package_exists(&fixture.key_package_reference)
                .map_err(|_| stage("L2 KeyPackage oracle"))?
                || storage
                    .recover_joiner(&fixture.transaction_id)
                    .map_err(|_| stage("L2 joiner oracle"))?
                    .is_some()
            {
                return Err(stage("L2 joiner oracle"));
            }
            let client = load_durable_client_with_storage(
                group_id,
                storage.clone(),
                storage.clone(),
                storage.clone(),
            )
            .map_err(|_| stage("L2 identity oracle"))?;
            if client.credential_identity().as_bytes() != &fixture.credential_identity {
                return Err(stage("L2 identity oracle"));
            }
        }
        OracleState::JoinerNew => {
            let recovery = storage
                .recover_joiner(&fixture.transaction_id)
                .map_err(|_| stage("L2 joiner oracle"))?
                .ok_or_else(|| stage("L2 joiner oracle"))?;
            if recovery.group_id != fixture.group_id {
                return Err(stage("L2 joiner group oracle"));
            }
            if storage
                .key_package_exists(&fixture.key_package_reference)
                .map_err(|_| stage("L2 KeyPackage oracle"))?
            {
                return Err(stage("L2 joiner KeyPackage oracle"));
            }
            let client = load_durable_client_with_storage(
                group_id,
                storage.clone(),
                storage.clone(),
                storage.clone(),
            )
            .map_err(|_| stage("L2 identity oracle"))?;
            if client.credential_identity().as_bytes() != &fixture.credential_identity {
                return Err(stage("L2 identity oracle"));
            }
            let group = client
                .load_group(group_id)
                .map_err(|_| stage("L2 MLS reload oracle"))?;
            if group.epoch() != 1 || group.member_count() != 2 {
                return Err(stage("L2 MLS reload oracle"));
            }
        }
    }
    Ok(())
}

fn verify_exact_sql_state(
    connection: &Connection,
    expected: OracleState,
    fixture: &CaseFixture,
    expected_welcome: Option<&[u8]>,
) -> Result<(), SessionCtlError> {
    type InviterJoinRow = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
    );
    type DeliveryLifecycleRow = (i64, i64, i64, Option<Vec<u8>>, Option<i64>);
    let identity: Option<(Vec<u8>, i64)> = connection
        .query_row(
            "SELECT group_id, length(identity_record) FROM mls_client_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| stage("L2 identity oracle"))?;
    if identity != Some((fixture.group_id.to_vec(), 141)) {
        return Err(stage("L2 identity oracle"));
    }
    let counts = [
        table_count(connection, "reservations")?,
        table_count(connection, "inviter_joins")?,
        table_count(connection, "mls_groups")?,
        table_count(connection, "mls_epochs")?,
        table_count(connection, "key_packages")?,
        table_count(connection, "joiner_commits")?,
        table_count(connection, "mls_client_identity")?,
    ];
    match expected {
        OracleState::InviterOld => {
            let row: Option<(Vec<u8>, Vec<u8>, i64, i64)> = connection
                .query_row(
                    "SELECT generation, join_request_id, expires_at, state FROM reservations WHERE invitation_id = ?1",
                    params![fixture.invitation_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(|_| stage("L2 reservation oracle"))?;
            if row
                != Some((
                    fixture.invitation_generation.to_vec(),
                    fixture.join_request_id.to_vec(),
                    RESERVATION_EXPIRES_AT as i64,
                    1,
                ))
                || counts != [1, 0, 0, 0, 0, 0, 1]
            {
                return Err(stage("L2 inviter oracle"));
            }
        }
        OracleState::InviterNew => {
            let expected_welcome = expected_welcome.ok_or_else(|| stage("L2 inviter oracle"))?;
            let endpoint = fixture_endpoint()?;
            let reservation: Option<(Vec<u8>, Vec<u8>, i64, i64)> = connection
                .query_row(
                    "SELECT generation, join_request_id, expires_at, state FROM reservations WHERE invitation_id = ?1",
                    params![fixture.invitation_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(|_| stage("L2 reservation oracle"))?;
            let row: Option<InviterJoinRow> = connection
                .query_row(
                    "SELECT invitation_id, generation, join_request_id, request_fingerprint, group_id, approval_record, epoch_before, epoch_after, outbox_state FROM inviter_joins WHERE transaction_id = ?1",
                    params![fixture.transaction_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?)),
                )
                .optional()
                .map_err(|_| stage("L2 inviter oracle"))?;
            let payloads: Option<(Vec<u8>, Vec<u8>, i64)> = connection
                .query_row(
                    "SELECT welcome, endpoint, outbox_expires_at FROM inviter_joins WHERE transaction_id = ?1",
                    params![fixture.transaction_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|_| stage("L2 inviter oracle"))?;
            let lifecycle: Option<DeliveryLifecycleRow> = connection
                .query_row(
                    "SELECT delivery_attempts, maximum_delivery_attempts, lease_generation, lease_id, lease_expires_at FROM inviter_joins WHERE transaction_id = ?1",
                    params![fixture.transaction_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                )
                .optional()
                .map_err(|_| stage("L2 inviter oracle"))?;
            if row
                != Some((
                    fixture.invitation_id.to_vec(),
                    fixture.invitation_generation.to_vec(),
                    fixture.join_request_id.to_vec(),
                    fixture.request_fingerprint.to_vec(),
                    fixture.group_id.to_vec(),
                    APPROVAL_RECORD.to_vec(),
                    0,
                    1,
                    1,
                ))
                || reservation
                    != Some((
                        fixture.invitation_generation.to_vec(),
                        fixture.join_request_id.to_vec(),
                        RESERVATION_EXPIRES_AT as i64,
                        2,
                    ))
                || payloads
                    != Some((
                        expected_welcome.to_vec(),
                        endpoint,
                        OUTBOX_EXPIRES_AT as i64,
                    ))
                || lifecycle
                    != Some((
                        0,
                        i64::from(MAXIMUM_WELCOME_DELIVERY_ATTEMPTS),
                        0,
                        None,
                        None,
                    ))
                || counts[0..2] != [1, 1]
                || counts[2] != 1
                || counts[3] == 0
                || counts[4..] != [0, 0, 1]
            {
                return Err(stage("L2 inviter oracle"));
            }
        }
        OracleState::JoinerOld => {
            let reference: Option<Vec<u8>> = connection
                .query_row(
                    "SELECT key_package_ref FROM key_packages WHERE key_package_ref = ?1",
                    params![fixture.key_package_reference],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| stage("L2 KeyPackage oracle"))?;
            if reference != Some(fixture.key_package_reference.to_vec())
                || counts != [0, 0, 0, 0, 1, 0, 1]
            {
                return Err(stage("L2 joiner oracle"));
            }
        }
        OracleState::JoinerNew => {
            let row: Option<(Vec<u8>, Vec<u8>)> = connection
                .query_row(
                    "SELECT group_id, key_package_ref FROM joiner_commits WHERE transaction_id = ?1",
                    params![fixture.transaction_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|_| stage("L2 joiner oracle"))?;
            if row
                != Some((
                    fixture.group_id.to_vec(),
                    fixture.key_package_reference.to_vec(),
                ))
                || counts[0..2] != [0, 0]
                || counts != [0, 0, 1, 0, 0, 1, 1]
            {
                return Err(stage("L2 joiner SQL oracle"));
            }
        }
    }
    Ok(())
}

fn verify_connection_configuration(connection: &Connection) -> Result<(), SessionCtlError> {
    let journal: String = connection
        .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
        .map_err(|_| stage("L2 configuration"))?;
    let values = [
        pragma_i64(connection, "PRAGMA synchronous;")?,
        pragma_i64(connection, "PRAGMA temp_store;")?,
        pragma_i64(connection, "PRAGMA secure_delete;")?,
        pragma_i64(connection, "PRAGMA trusted_schema;")?,
        pragma_i64(connection, "PRAGMA foreign_keys;")?,
    ];
    if journal != "delete" || values != [2, 2, 1, 0, 1] {
        return Err(stage("L2 configuration"));
    }
    Ok(())
}

fn pragma_i64(connection: &Connection, pragma: &str) -> Result<i64, SessionCtlError> {
    connection
        .query_row(pragma, [], |row| row.get(0))
        .map_err(|_| stage("L2 configuration"))
}

fn schema_fingerprint(connection: &Connection) -> Result<String, SessionCtlError> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, coalesce(sql, '') FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(|_| stage("L2 schema"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| stage("L2 schema"))?;
    let mut canonical = Vec::new();
    for row in rows {
        let (kind, name, table, sql) = row.map_err(|_| stage("L2 schema"))?;
        for field in [kind, name, table, sql] {
            canonical.extend_from_slice(field.as_bytes());
            canonical.push(0);
        }
        canonical.push(b'\n');
    }
    Ok(hex(digest(&SHA256, &canonical).as_ref()))
}

struct L2ArtifactSnapshot {
    digest: [u8; 32],
    bytes: Vec<u8>,
}

fn encrypted_artifact_snapshot(root: &Path) -> Result<L2ArtifactSnapshot, SessionCtlError> {
    let mut canonical = Vec::new();
    let mut artifact_bytes = Vec::new();
    let mut found_database = false;
    for name in [
        DATABASE_NAME,
        "case.sqlite3-journal",
        "case.sqlite3-wal",
        "case.sqlite3-shm",
    ] {
        let path = root.join(name);
        if !path.exists() {
            continue;
        }
        validate_owned_file(&path, None)?;
        let bytes = read_bounded_repository_file(&path, MAX_DATABASE_BYTES)
            .ok_or_else(|| stage("L2 encrypted artifact"))?;
        if name == DATABASE_NAME {
            found_database = true;
        }
        if artifact_bytes.len().saturating_add(bytes.len()) > MAX_DATABASE_BYTES {
            return Err(stage("L2 encrypted artifact bound"));
        }
        canonical.extend_from_slice(name.as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(
            &u64::try_from(bytes.len())
                .map_err(|_| stage("L2 encrypted artifact"))?
                .to_be_bytes(),
        );
        canonical.extend_from_slice(&bytes);
        artifact_bytes.extend_from_slice(&bytes);
    }
    if !found_database || canonical.is_empty() {
        return Err(stage("L2 encrypted artifact"));
    }
    Ok(L2ArtifactSnapshot {
        digest: digest(&SHA256, &canonical)
            .as_ref()
            .try_into()
            .map_err(|_| stage("L2 encrypted artifact"))?,
        bytes: artifact_bytes,
    })
}

fn collect_evidence_binding(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    fixture: &CaseFixture,
    welcome_canary: Option<&[u8]>,
    baseline: L2ArtifactSnapshot,
    surfaces: &[&[u8]],
) -> Result<L2EvidenceBinding, SessionCtlError> {
    let post_recovery = encrypted_artifact_snapshot(root)?;
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;
    let sqlcipher_version: String = connection
        .query_row("PRAGMA cipher_version;", [], |row| row.get(0))
        .map_err(|_| stage("L2 evidence SQLCipher version"))?;
    let sqlite_version: String = connection
        .query_row("SELECT sqlite_version();", [], |row| row.get(0))
        .map_err(|_| stage("L2 evidence SQLite version"))?;
    drop(connection);
    let mut scanned = Vec::with_capacity(surfaces.len() + 2);
    scanned.extend_from_slice(surfaces);
    scanned.push(baseline.bytes.as_slice());
    scanned.push(post_recovery.bytes.as_slice());
    let endpoint = fixture_endpoint()?;
    let mut secrets = vec![
        key.as_slice(),
        fixture.invitation_id.as_slice(),
        fixture.invitation_generation.as_slice(),
        fixture.join_request_id.as_slice(),
        fixture.request_fingerprint.as_slice(),
        fixture.transaction_id.as_slice(),
        fixture.group_id.as_slice(),
        fixture.key_package_reference.as_slice(),
        fixture.credential_identity.as_slice(),
        APPROVAL_RECORD,
        endpoint.as_slice(),
    ];
    if let Some(welcome) = welcome_canary {
        secrets.push(welcome);
    }
    evidence::scan_secret_values(scanned, secrets)?;
    Ok(L2EvidenceBinding {
        executables: None,
        sqlcipher_version,
        sqlite_version,
        baseline_artifact_digest: baseline.digest,
        post_recovery_artifact_digest: post_recovery.digest,
        redaction: true,
    })
}

fn prove_database_handle_cleanup(root: &Path) -> Result<bool, SessionCtlError> {
    let database = root.join(DATABASE_NAME);
    let guard = root.join("case.handle-guard");
    fs::rename(&database, &guard).map_err(|_| stage("L2 handle cleanup"))?;
    fs::rename(&guard, &database).map_err(|_| stage("L2 handle cleanup"))?;
    Ok(true)
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
        .execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA synchronous = FULL;
             PRAGMA temp_store = MEMORY;
             PRAGMA secure_delete = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(|_| stage("L2 verifier configuration"))?;
    Ok(connection)
}

struct AutoContinueBarrier;

impl BarrierTransport for AutoContinueBarrier {
    fn exchange(
        &self,
        encoded: [u8; CONTROL_FRAME_BYTES],
    ) -> Result<[u8; CONTROL_FRAME_BYTES], BarrierFailure> {
        let checkpoint = ControlFrame::decode(&encoded).map_err(|_| BarrierFailure::Rejected)?;
        if checkpoint.kind() != FrameKind::Checkpoint || checkpoint.role() != Role::Writer {
            return Err(BarrierFailure::Rejected);
        }
        Ok(checkpoint.acknowledgement().encode())
    }
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
    write_bounded_owned_file(path, bytes, secret, 4_096)
}

fn write_bounded_owned_file(
    path: &Path,
    bytes: &[u8],
    secret: bool,
    maximum: usize,
) -> Result<(), SessionCtlError> {
    if bytes.len() > maximum || path.parent().is_none() {
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

fn read_bounded_owned_file(path: &Path, maximum: usize) -> Result<Vec<u8>, SessionCtlError> {
    validate_owned_file(path, None)?;
    let metadata = fs::metadata(path).map_err(|_| stage("L2 file"))?;
    if metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err(stage("L2 file"));
    }
    let file = File::open(path).map_err(|_| stage("L2 file"))?;
    let mut bytes =
        Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| stage("L2 file"))?);
    file.take(
        u64::try_from(maximum)
            .map_err(|_| stage("L2 file"))?
            .saturating_add(1),
    )
    .read_to_end(&mut bytes)
    .map_err(|_| stage("L2 file"))?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(stage("L2 file"));
    }
    Ok(bytes)
}

fn read_bounded_owned_file_once(
    path: &Path,
    maximum: usize,
    cleanup_stage: &'static str,
) -> Result<Zeroizing<Vec<u8>>, SessionCtlError> {
    let bytes = Zeroizing::new(read_bounded_owned_file(path, maximum)?);
    fs::remove_file(path).map_err(|_| stage(cleanup_stage))?;
    Ok(bytes)
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
        if child
            .try_wait()
            .map_err(|_| stage("L2 child termination"))?
            .is_some()
        {
            return Err(stage("L2 child escaped barrier"));
        }
        child.kill().map_err(|_| stage("L2 child termination"))?;
        self.stdin.take();
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
    OverLimit,
    ReadFailed,
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
                    Ok(_) => {
                        let _ = sender.send(PipeMessage::OverLimit);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        let _ = sender.send(PipeMessage::ReadFailed);
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
            Ok(PipeMessage::OverLimit) => Err(stage("L2 output bound")),
            Ok(PipeMessage::ReadFailed) => Err(stage("L2 output read")),
            Err(RecvTimeoutError::Disconnected) => Err(stage("L2 output disconnected")),
            Err(RecvTimeoutError::Timeout) => Err(stage("L2 output timeout")),
        }
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        if self.eof
            && let Some(join) = self.join.take()
        {
            let _ = join.join();
        } else {
            self.join.take();
        }
    }
}

fn sanitize_environment(command: &mut Command) {
    command.env_clear();
    for name in ["PATH", "TMPDIR", "SystemRoot", "WINDIR"] {
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
    repository_dirty_at(root).ok()
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
