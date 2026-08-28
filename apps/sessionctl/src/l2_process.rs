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
use super::{SessionCtlError, random_nonzero, resolve_l1_process_git_commit, stage};

mod evidence;
pub use evidence::{L2EvidenceBundle, L2EvidenceChannels, L2EvidenceManifest};

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
const SCHEMA_FINGERPRINT_SHA256: &str =
    "ed39426dff273ef7192ae3ca326e46747c6dc98f200e47734c2d5223e2ece192";

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
    /// The canonical durable client identity is removed before verification.
    IdentityLoss,
    /// One reserved invitation field is substituted before verification.
    ReservationSubstitution,
    /// The declared schema version masks a structurally defective schema.
    DefectiveSchema,
    /// A verifier retains its database handle past the bounded success window.
    LingeringHandle,
    /// A valid-schema pending row invents a lease generation.
    NonzeroLeaseGeneration,
    /// A valid-schema pending row changes the retained delivery-attempt ceiling.
    ChangedAttemptCeiling,
    /// Exact inviter retry encounters a changed committed transaction.
    InviterRetryMutation,
    /// Exact joiner retry encounters a changed committed transaction.
    JoinerRetryMutation,
    /// The controller withholds a required acknowledgement at a non-target checkpoint.
    MissingAcknowledgement,
    /// A checked integration driver injects one SQLite-visible I/O failure.
    IoFault,
    /// A committed joiner state incorrectly retains its consumed KeyPackage.
    JoinerRetainedKeyPackage,
}

impl L2HarnessProbe {
    const fn is_retry_conflict(self) -> bool {
        matches!(self, Self::InviterRetryMutation | Self::JoinerRetryMutation)
    }

    const fn code(self) -> u8 {
        match self {
            Self::GracefulContinue => 1,
            Self::KillWhileBlocked => 2,
            Self::AdvanceWithoutAcknowledgement => 3,
            Self::OversizedOutput => 4,
            Self::SecretDiagnostic => 5,
            Self::Stall => 6,
            Self::MixedFixture => 7,
            Self::IdentityLoss => 8,
            Self::ReservationSubstitution => 9,
            Self::DefectiveSchema => 10,
            Self::LingeringHandle => 11,
            Self::NonzeroLeaseGeneration => 12,
            Self::ChangedAttemptCeiling => 13,
            Self::InviterRetryMutation => 14,
            Self::JoinerRetryMutation => 15,
            Self::MissingAcknowledgement => 16,
            Self::IoFault => 17,
            Self::JoinerRetainedKeyPackage => 18,
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
            | Self::MixedFixture
            | Self::IdentityLoss
            | Self::ReservationSubstitution
            | Self::DefectiveSchema
            | Self::LingeringHandle
            | Self::NonzeroLeaseGeneration
            | Self::ChangedAttemptCeiling
            | Self::InviterRetryMutation
            | Self::JoinerRetryMutation
            | Self::MissingAcknowledgement
            | Self::IoFault
            | Self::JoinerRetainedKeyPackage => "negative-probe",
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
            8 => Ok(Self::IdentityLoss),
            9 => Ok(Self::ReservationSubstitution),
            10 => Ok(Self::DefectiveSchema),
            11 => Ok(Self::LingeringHandle),
            12 => Ok(Self::NonzeroLeaseGeneration),
            13 => Ok(Self::ChangedAttemptCeiling),
            14 => Ok(Self::InviterRetryMutation),
            15 => Ok(Self::JoinerRetryMutation),
            16 => Ok(Self::MissingAcknowledgement),
            17 => Ok(Self::IoFault),
            18 => Ok(Self::JoinerRetainedKeyPackage),
            _ => Err(stage("L2 probe")),
        }
    }
}

/// One closed application-process fault case consumed by the reusable L2 roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct L2ProcessCase {
    checkpoint: Checkpoint,
    occurrence: u8,
}

impl L2ProcessCase {
    /// Constructs one checkpoint whose complete-state oracle is derived internally.
    pub fn new(checkpoint: Checkpoint, occurrence: u8) -> Result<Self, SessionCtlError> {
        let case_id = CaseId::new([1; 16]).map_err(|_| stage("L2 case"))?;
        ControlFrame::new_checkpoint(case_id, checkpoint, occurrence)
            .map_err(|_| stage("L2 case"))?;
        Ok(Self {
            checkpoint,
            occurrence,
        })
    }

    const fn expected(self) -> OracleState {
        match self.checkpoint {
            Checkpoint::InviterAfterCommitReturn | Checkpoint::InviterBeforeShadowFinalize => {
                OracleState::InviterNew
            }
            Checkpoint::InviterBeforeBegin
            | Checkpoint::InviterAfterGroupUpsert
            | Checkpoint::InviterAfterEpochInsert
            | Checkpoint::InviterAfterEpochUpdate
            | Checkpoint::InviterAfterJoinInsert
            | Checkpoint::InviterAfterReservationConsumed
            | Checkpoint::InviterBeforeCommit => OracleState::InviterOld,
            Checkpoint::JoinerAfterCommitReturn => OracleState::JoinerNew,
            Checkpoint::JoinerBeforeBegin
            | Checkpoint::JoinerAfterGroupUpsert
            | Checkpoint::JoinerAfterEpochInsert
            | Checkpoint::JoinerAfterEpochUpdate
            | Checkpoint::JoinerAfterCommitInsert
            | Checkpoint::JoinerBeforeKeyPackageDelete
            | Checkpoint::JoinerAfterKeyPackageDelete
            | Checkpoint::JoinerBeforeCommit => OracleState::JoinerOld,
        }
    }

    const fn scenario(self) -> Scenario {
        self.checkpoint.scenario()
    }
}

const fn oracle_label(state: OracleState) -> &'static str {
    match state {
        OracleState::InviterOld => "I0",
        OracleState::InviterNew => "I1",
        OracleState::JoinerOld => "J0",
        OracleState::JoinerNew => "J1",
    }
}

const fn checkpoint_label(checkpoint: Checkpoint) -> &'static str {
    match checkpoint {
        Checkpoint::InviterBeforeBegin => "INVITER_BEFORE_BEGIN",
        Checkpoint::InviterAfterGroupUpsert => "INVITER_AFTER_GROUP_UPSERT",
        Checkpoint::InviterAfterEpochInsert => "INVITER_AFTER_EPOCH_INSERT",
        Checkpoint::InviterAfterEpochUpdate => "INVITER_AFTER_EPOCH_UPDATE",
        Checkpoint::InviterAfterJoinInsert => "INVITER_AFTER_JOIN_INSERT",
        Checkpoint::InviterAfterReservationConsumed => "INVITER_AFTER_RESERVATION_CONSUMED",
        Checkpoint::InviterBeforeCommit => "INVITER_BEFORE_COMMIT",
        Checkpoint::InviterAfterCommitReturn => "INVITER_AFTER_COMMIT_RETURN",
        Checkpoint::InviterBeforeShadowFinalize => "INVITER_BEFORE_SHADOW_FINALIZE",
        Checkpoint::JoinerBeforeBegin => "JOINER_BEFORE_BEGIN",
        Checkpoint::JoinerAfterGroupUpsert => "JOINER_AFTER_GROUP_UPSERT",
        Checkpoint::JoinerAfterEpochInsert => "JOINER_AFTER_EPOCH_INSERT",
        Checkpoint::JoinerAfterEpochUpdate => "JOINER_AFTER_EPOCH_UPDATE",
        Checkpoint::JoinerAfterCommitInsert => "JOINER_AFTER_COMMIT_INSERT",
        Checkpoint::JoinerBeforeKeyPackageDelete => "JOINER_BEFORE_KEY_PACKAGE_DELETE",
        Checkpoint::JoinerAfterKeyPackageDelete => "JOINER_AFTER_KEY_PACKAGE_DELETE",
        Checkpoint::JoinerBeforeCommit => "JOINER_BEFORE_COMMIT",
        Checkpoint::JoinerAfterCommitReturn => "JOINER_AFTER_COMMIT_RETURN",
    }
}

/// Secret-free evidence from one successful L2 controller probe.
#[derive(Clone, Eq, PartialEq)]
pub struct L2ProcessReport {
    case_id: CaseId,
    case: L2ProcessCase,
    trace: Vec<L2ProcessCase>,
    probe: L2HarnessProbe,
    commit: String,
    dirty: bool,
    toolchain: String,
    lock_digest: String,
    observed: OracleState,
    integrity: bool,
    schema: bool,
    semantic_oracle: bool,
    exact_retry: bool,
    fixture_cleanup: bool,
    writer_termination: bool,
    fresh_verifier: bool,
    redaction: bool,
    handle_cleanup: bool,
    child_cleanup: bool,
    directory_cleanup: bool,
    evidence_binding: L2EvidenceBinding,
}

#[derive(Clone, Eq, PartialEq)]
struct L2EvidenceBinding {
    sqlcipher_version: String,
    sqlite_version: String,
    baseline_artifact_digest: [u8; 32],
    post_recovery_artifact_digest: [u8; 32],
    redaction: bool,
}

#[derive(Clone, Eq, PartialEq)]
enum L2EvidenceCaseTarget {
    ApplicationCheckpoint {
        checkpoint: &'static str,
        ordinal: u16,
        expected: &'static str,
        observed: &'static str,
    },
    SqliteReturnCode {
        file_role: &'static str,
        operation: &'static str,
        mode: &'static str,
        ordinal: u16,
        last_fully_explored_ordinal: u16,
        expected: &'static str,
        observed: &'static str,
        primary_code: i32,
        extended_code: i32,
        transaction_result: &'static str,
    },
    CommitWindowProcessKill {
        file_role: &'static str,
        operation: &'static str,
        ordinal: u16,
        last_fully_explored_ordinal: u16,
        expected: &'static str,
        observed: &'static str,
    },
}

#[derive(Clone, Eq, PartialEq)]
struct L2EvidenceCase {
    key: String,
    target: L2EvidenceCaseTarget,
    binding: L2EvidenceBinding,
}

impl L2EvidenceCase {
    fn application(report: &L2ProcessReport) -> Self {
        let checkpoint = checkpoint_label(report.case.checkpoint);
        Self {
            key: format!(
                "checkpoint-{}-{}",
                checkpoint.to_ascii_lowercase().replace('_', "-"),
                report.case.occurrence,
            ),
            target: L2EvidenceCaseTarget::ApplicationCheckpoint {
                checkpoint,
                ordinal: u16::from(report.case.occurrence),
                expected: oracle_label(report.case.expected()),
                observed: oracle_label(report.observed),
            },
            binding: report.evidence_binding.clone(),
        }
    }

    fn sqlite_return_code(report: &L2IoFaultReport, last_fully_explored_ordinal: u16) -> Self {
        let file_role = report.fault.file_role.label();
        let operation = report.fault.operation.label();
        let mode = report.fault.mode.label();
        Self {
            key: format!(
                "sqlite-{file_role}-{operation}-{mode}-{:010}-{:04}",
                report.fault.sqlite_code, report.fault.target_ordinal,
            ),
            target: L2EvidenceCaseTarget::SqliteReturnCode {
                file_role,
                operation,
                mode,
                ordinal: report.fault.target_ordinal,
                last_fully_explored_ordinal,
                expected: match report.scenario {
                    Scenario::InviterTransaction => "I0|I1",
                    Scenario::JoinerTransaction => "J0|J1",
                },
                observed: oracle_label(report.observed),
                primary_code: report.fault.sqlite_code & 0xff,
                extended_code: report.fault.sqlite_code,
                transaction_result: if report.fault.transaction_succeeded {
                    "success"
                } else {
                    "rejected"
                },
            },
            binding: report.evidence_binding.clone(),
        }
    }

    fn commit_window_process_kill(
        report: &L2IoPauseKillReport,
        last_fully_explored_ordinal: u16,
    ) -> Self {
        let file_role = report.pause.file_role.label();
        let operation = report.pause.operation.label();
        Self {
            key: format!(
                "pause-{file_role}-{operation}-{:04}",
                report.pause.target_ordinal,
            ),
            target: L2EvidenceCaseTarget::CommitWindowProcessKill {
                file_role,
                operation,
                ordinal: report.pause.target_ordinal,
                last_fully_explored_ordinal,
                expected: match report.scenario {
                    Scenario::InviterTransaction => "I0|I1",
                    Scenario::JoinerTransaction => "J0|J1",
                },
                observed: oracle_label(report.observed),
            },
            binding: report.evidence_binding.clone(),
        }
    }
}

/// Baseline-observed application checkpoints for one real storage transaction.
pub struct L2ProcessBaseline {
    scenario: Scenario,
    cases: Vec<L2ProcessCase>,
}

impl L2ProcessBaseline {
    /// Iterates every checkpoint occurrence emitted by the clean transaction.
    pub fn cases(&self) -> impl ExactSizeIterator<Item = L2ProcessCase> + '_ {
        self.cases.iter().copied()
    }
}

/// Non-public proof that every baseline-observed checkpoint was killed once.
pub struct L2ProcessSweepReport {
    scenario: Scenario,
    cases: Vec<L2ProcessCase>,
    old_states: usize,
    new_states: usize,
    evidence_cases: Vec<L2EvidenceCase>,
}

impl L2ProcessSweepReport {
    /// Requires an exact one-to-one match with the clean checkpoint trace.
    pub fn new(
        scenario: Scenario,
        baseline: &L2ProcessBaseline,
        reports: &[L2ProcessReport],
    ) -> Result<Self, SessionCtlError> {
        if baseline.scenario != scenario
            || baseline.cases.is_empty()
            || baseline.cases.len() > MAX_APPLICATION_CHECKPOINTS
            || reports.len() != baseline.cases.len()
        {
            return Err(stage("L2 process sweep baseline"));
        }
        let mut old_states = 0_usize;
        let mut new_states = 0_usize;
        for (target_index, expected_case) in baseline.cases.iter().enumerate() {
            let mut matches = reports
                .iter()
                .filter(|report| report.case == *expected_case);
            let report = matches
                .next()
                .ok_or_else(|| stage("L2 process sweep coverage"))?;
            if matches.next().is_some()
                || report.probe != L2HarnessProbe::KillWhileBlocked
                || report.case.scenario() != scenario
                || report.trace != baseline.cases[..=target_index]
                || report.observed != report.case.expected()
                || !report.integrity
                || !report.schema
                || !report.semantic_oracle
                || !report.exact_retry
                || !report.fixture_cleanup
                || !report.writer_termination
                || !report.fresh_verifier
                || !report.redaction
                || !report.handle_cleanup
                || !report.child_cleanup
                || !report.directory_cleanup
            {
                return Err(stage("L2 process sweep case"));
            }
            match report.observed {
                OracleState::InviterOld | OracleState::JoinerOld => {
                    old_states = old_states.saturating_add(1);
                }
                OracleState::InviterNew | OracleState::JoinerNew => {
                    new_states = new_states.saturating_add(1);
                }
            }
        }
        if old_states == 0 || new_states == 0 {
            return Err(stage("L2 process sweep oracle coverage"));
        }
        let evidence_cases =
            canonical_evidence_cases(reports.iter().map(L2EvidenceCase::application).collect())?;
        Ok(Self {
            scenario,
            cases: baseline.cases.clone(),
            old_states,
            new_states,
            evidence_cases,
        })
    }

    /// Encodes bounded internal matrix coverage, not public L2 evidence.
    #[must_use]
    pub fn encode_v1(&self) -> String {
        let checkpoint_transcript = self
            .cases
            .iter()
            .map(|case| format!("{}:{}", checkpoint_label(case.checkpoint), case.occurrence))
            .collect::<Vec<_>>()
            .join(",");
        let checkpoint_digest = hex(digest(&SHA256, checkpoint_transcript.as_bytes()).as_ref());
        let evidence = format!(
            concat!(
                "version=1\n",
                "protocol=l2-checkpoint-observation-v1\n",
                "scenario=E2E-TXN-001\n",
                "publication=prohibited\n",
                "status=validated\n",
                "coverage=complete\n",
                "sweep=application-process-kill\n",
                "fault_build=true\n",
                "storage_scenario={}\n",
                "checkpoint_trace_sha256={}\n",
                "completed_cases={}\n",
                "observed_old_states={}\n",
                "observed_new_states={}\n",
                "integrity=pass\n",
                "schema=pass\n",
                "semantic_oracle=pass\n",
                "exact_retry=pass\n",
                "fixture_cleanup=pass\n",
                "handle_cleanup=pass\n",
                "child_cleanup=pass\n",
                "directory_cleanup=pass\n"
            ),
            match self.scenario {
                Scenario::InviterTransaction => "inviter-transaction",
                Scenario::JoinerTransaction => "joiner-transaction",
            },
            checkpoint_digest,
            self.cases.len(),
            self.old_states,
            self.new_states,
        );
        debug_assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
        evidence
    }
}

impl L2ProcessReport {
    /// Encodes one bounded provisional L2 harness record.
    #[must_use]
    pub fn encode_v1(&self) -> String {
        let evidence = format!(
            concat!(
                "version=1\n",
                "protocol=l2-harness-evidence-v1\n",
                "scenario=L2-HARNESS-001\n",
                "result=pass\n",
                "coverage=partial\n",
                "evidence_scope=harness-foundation\n",
                "fault_build=true\n",
                "case_id={}\n",
                "schedule_seed=1\n",
                "checkpoint={}\n",
                "occurrence={}\n",
                "control={}\n",
                "expected={}\n",
                "observed={}\n",
                "workload=real-storage-transaction\n",
                "storage_scenario={}\n",
                "platform={}-{}\n",
                "commit={}\n",
                "dirty={}\n",
                "toolchain={}\n",
                "lock_sha256={}\n",
                "frame_bytes={}\n",
                "frame_wait_ms={}\n",
                "child_wait_ms={}\n",
                "integrity={}\n",
                "schema={}\n",
                "semantic_oracle={}\n",
                "exact_retry={}\n",
                "fixture_cleanup={}\n",
                "writer_termination={}\n",
                "fresh_verifier={}\n",
                "redaction={}\n",
                "handle_cleanup={}\n",
                "child_cleanup={}\n",
                "directory_cleanup={}\n"
            ),
            hex(self.case_id.as_bytes()),
            checkpoint_label(self.case.checkpoint),
            self.case.occurrence,
            self.probe.control_label(),
            oracle_label(self.case.expected()),
            oracle_label(self.observed),
            match self.case.scenario() {
                Scenario::InviterTransaction => "inviter-transaction",
                Scenario::JoinerTransaction => "joiner-transaction",
            },
            std::env::consts::OS,
            std::env::consts::ARCH,
            self.commit,
            if self.dirty { "true" } else { "false" },
            self.toolchain,
            self.lock_digest,
            CONTROL_FRAME_BYTES,
            FRAME_WAIT.as_millis(),
            CHILD_WAIT.as_millis(),
            pass_fail(self.integrity),
            pass_fail(self.schema),
            pass_fail(self.semantic_oracle),
            pass_fail(self.exact_retry),
            pass_fail(self.fixture_cleanup),
            if self.writer_termination {
                "confirmed"
            } else {
                "failed"
            },
            pass_fail(self.fresh_verifier),
            pass_fail(self.redaction),
            pass_fail(self.handle_cleanup),
            pass_fail(self.child_cleanup),
            pass_fail(self.directory_cleanup),
        );
        debug_assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
        evidence
    }
}

/// Closed file roles retained by the L2 I/O evidence schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L2IoFileRole {
    /// SQLCipher's main database file.
    MainDatabase,
    /// SQLCipher's rollback journal under the frozen DELETE-journal baseline.
    RollbackJournal,
}

impl L2IoFileRole {
    const fn label(self) -> &'static str {
        match self {
            Self::MainDatabase => "main-database",
            Self::RollbackJournal => "rollback-journal",
        }
    }
}

/// Closed SQLite operations retained by the L2 I/O evidence schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L2IoOperation {
    /// File read.
    Read,
    /// File write.
    Write,
    /// File truncation.
    Truncate,
    /// File synchronization.
    Sync,
    /// File deletion.
    Delete,
    /// File lock acquisition.
    Lock,
    /// File lock release.
    Unlock,
    /// Reserved-lock query.
    CheckReservedLock,
}

impl L2IoOperation {
    const fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Truncate => "truncate",
            Self::Sync => "sync",
            Self::Delete => "delete",
            Self::Lock => "lock",
            Self::Unlock => "unlock",
            Self::CheckReservedLock => "check-reserved-lock",
        }
    }
}

/// Closed injection modes retained by the L2 I/O evidence schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L2IoFaultMode {
    /// Return one failure at the exact target ordinal.
    OneShot,
    /// Return the failure at and after the exact target ordinal.
    Persistent,
}

impl L2IoFaultMode {
    const fn label(self) -> &'static str {
        match self {
            Self::OneShot => "one-shot",
            Self::Persistent => "persistent",
        }
    }
}

/// Bounded, path-free observation returned by a checked L2 I/O driver.
pub struct L2IoFaultObservation {
    file_role: L2IoFileRole,
    operation: L2IoOperation,
    mode: L2IoFaultMode,
    sqlite_code: i32,
    target_ordinal: u16,
    last_observed_ordinal: u16,
    total_operations: usize,
    injected_failures: usize,
    transaction_succeeded: bool,
}

/// One observed role/operation pair and its complete baseline ordinal count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct L2IoSweepTarget {
    file_role: L2IoFileRole,
    operation: L2IoOperation,
    observed_count: u16,
}

impl L2IoSweepTarget {
    /// Constructs one nonempty supported target count below the operation bound.
    pub fn new(
        file_role: L2IoFileRole,
        operation: L2IoOperation,
        observed_count: usize,
    ) -> Result<Self, SessionCtlError> {
        if observed_count == 0 || observed_count > 4_096 {
            return Err(stage("L2 I/O baseline target"));
        }
        Ok(Self {
            file_role,
            operation,
            observed_count: u16::try_from(observed_count)
                .map_err(|_| stage("L2 I/O baseline target"))?,
        })
    }

    /// Retained file role.
    pub const fn file_role(self) -> L2IoFileRole {
        self.file_role
    }

    /// Retained operation.
    pub const fn operation(self) -> L2IoOperation {
        self.operation
    }

    /// Number of matching operations in the clean transaction trace.
    pub const fn observed_count(self) -> u16 {
        self.observed_count
    }
}

/// Validated transaction-only operation coverage from one clean named-VFS run.
pub struct L2IoBaselineObservation {
    targets: Vec<L2IoSweepTarget>,
    last_observed_ordinal: u16,
    total_operations: usize,
}

impl L2IoBaselineObservation {
    /// Constructs a bounded baseline and rejects duplicate or incomplete target counts.
    pub fn new(
        targets: Vec<L2IoSweepTarget>,
        last_observed_ordinal: u16,
        total_operations: usize,
    ) -> Result<Self, SessionCtlError> {
        if targets.is_empty()
            || targets.len() > 16
            || total_operations == 0
            || total_operations > 4_096
            || usize::from(last_observed_ordinal) + 1 != total_operations
        {
            return Err(stage("L2 I/O baseline observation"));
        }
        let mut covered = 0_usize;
        for (index, target) in targets.iter().enumerate() {
            if targets[..index].iter().any(|prior| {
                prior.file_role == target.file_role && prior.operation == target.operation
            }) {
                return Err(stage("L2 I/O baseline observation"));
            }
            covered = covered
                .checked_add(usize::from(target.observed_count))
                .ok_or_else(|| stage("L2 I/O baseline observation"))?;
        }
        if covered > total_operations {
            return Err(stage("L2 I/O baseline observation"));
        }
        Ok(Self {
            targets,
            last_observed_ordinal,
            total_operations,
        })
    }
}

/// Closed result returned by an L2 named-VFS driver.
pub enum L2IoDriverObservation {
    /// Clean transaction-only trace used to enumerate the sweep.
    Baseline(L2IoBaselineObservation),
    /// One actual injected SQLite failure.
    Fault(L2IoFaultObservation),
}

impl L2IoFaultObservation {
    /// Constructs one closed observation and rejects incomplete or inconsistent evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        file_role: L2IoFileRole,
        operation: L2IoOperation,
        mode: L2IoFaultMode,
        sqlite_code: i32,
        target_ordinal: u16,
        last_observed_ordinal: u16,
        total_operations: usize,
        injected_failures: usize,
        transaction_succeeded: bool,
    ) -> Result<Self, SessionCtlError> {
        let code_matches_operation = matches!(
            (sqlite_code, operation),
            (rusqlite::ffi::SQLITE_FULL, L2IoOperation::Write)
                | (rusqlite::ffi::SQLITE_IOERR_READ, L2IoOperation::Read)
                | (rusqlite::ffi::SQLITE_IOERR_WRITE, L2IoOperation::Write)
                | (
                    rusqlite::ffi::SQLITE_IOERR_TRUNCATE,
                    L2IoOperation::Truncate
                )
                | (rusqlite::ffi::SQLITE_IOERR_FSYNC, L2IoOperation::Sync)
                | (rusqlite::ffi::SQLITE_IOERR_DELETE, L2IoOperation::Delete)
                | (rusqlite::ffi::SQLITE_IOERR_LOCK, L2IoOperation::Lock)
                | (rusqlite::ffi::SQLITE_IOERR_UNLOCK, L2IoOperation::Unlock)
                | (
                    rusqlite::ffi::SQLITE_IOERR_CHECKRESERVEDLOCK,
                    L2IoOperation::CheckReservedLock,
                )
        );
        let injection_count_is_valid = match mode {
            L2IoFaultMode::OneShot => injected_failures == 1,
            L2IoFaultMode::Persistent => injected_failures >= 1,
        };
        if !code_matches_operation
            || total_operations == 0
            || total_operations > 4_096
            || usize::from(last_observed_ordinal) + 1 != total_operations
            || usize::from(target_ordinal) >= 4_096
            || !injection_count_is_valid
            || injected_failures > total_operations
        {
            return Err(stage("L2 I/O observation"));
        }
        Ok(Self {
            file_role,
            operation,
            mode,
            sqlite_code,
            target_ordinal,
            last_observed_ordinal,
            total_operations,
            injected_failures,
            transaction_succeeded,
        })
    }
}

/// Test-only bridge implemented by the isolated named-VFS adapter consumer.
pub trait L2IoFaultDriver {
    /// Registers or resets the driver before the named connection opens.
    fn prepare_before_open(&mut self) -> bool;
    /// Clears open-time observations and arms the transaction-only fault.
    fn arm_after_open(&mut self) -> bool;
    /// Disables the fault before close and returns validated path-free evidence.
    fn disable_and_observe(&mut self, transaction_succeeded: bool)
    -> Option<L2IoDriverObservation>;
}

/// Test-only bridge that arms one process-blocking named-VFS pause.
pub trait L2IoPauseDriver {
    /// Registers or resets the driver before the named connection opens.
    fn prepare_before_open(&mut self) -> bool;
    /// Clears open-time observations and arms the transaction-only pause.
    fn arm_after_open(&mut self) -> bool;
}

/// Bounded, path-free proof that a child reached one commit-window pause.
pub struct L2IoPauseObservation {
    file_role: L2IoFileRole,
    operation: L2IoOperation,
    target_ordinal: u16,
    last_observed_ordinal: u16,
    total_operations: usize,
}

impl L2IoPauseObservation {
    /// Constructs one supported pause observation below the operation bound.
    pub fn new(
        file_role: L2IoFileRole,
        operation: L2IoOperation,
        target_ordinal: u16,
        last_observed_ordinal: u16,
        total_operations: usize,
    ) -> Result<Self, SessionCtlError> {
        let supported = matches!(
            (file_role, operation),
            (
                L2IoFileRole::RollbackJournal,
                L2IoOperation::Write | L2IoOperation::Sync | L2IoOperation::Delete,
            ) | (
                L2IoFileRole::MainDatabase,
                L2IoOperation::Write | L2IoOperation::Sync,
            )
        );
        if !supported
            || total_operations == 0
            || total_operations > 4_096
            || usize::from(last_observed_ordinal) + 1 != total_operations
            || usize::from(target_ordinal) >= total_operations
        {
            return Err(stage("L2 I/O pause observation"));
        }
        Ok(Self {
            file_role,
            operation,
            target_ordinal,
            last_observed_ordinal,
            total_operations,
        })
    }
}

/// Bounded internal observation from one clean named-VFS baseline.
///
/// This is not the public `l2-evidence-v1` manifest and must not be published
/// or treated as a security-gate result before L2-8 adds provenance, artifact
/// binding, and synthetic-canary scans.
pub struct L2IoBaselineReport {
    scenario: Scenario,
    observed: OracleState,
    baseline: L2IoBaselineObservation,
    fixture_cleanup: bool,
    handle_cleanup: bool,
    child_cleanup: bool,
    directory_cleanup: bool,
    _evidence_binding: L2EvidenceBinding,
}

impl L2IoBaselineReport {
    #[allow(clippy::too_many_arguments)]
    fn new(
        scenario: Scenario,
        observed: OracleState,
        baseline: L2IoBaselineObservation,
        fixture_cleanup: bool,
        handle_cleanup: bool,
        child_cleanup: bool,
        directory_cleanup: bool,
        evidence_binding: L2EvidenceBinding,
    ) -> Result<Self, SessionCtlError> {
        let is_clean_new_state = matches!(
            (scenario, observed),
            (Scenario::InviterTransaction, OracleState::InviterNew)
                | (Scenario::JoinerTransaction, OracleState::JoinerNew)
        );
        if !is_clean_new_state
            || !fixture_cleanup
            || !handle_cleanup
            || !child_cleanup
            || !directory_cleanup
        {
            return Err(stage("L2 I/O clean baseline"));
        }
        Ok(Self {
            scenario,
            observed,
            baseline,
            fixture_cleanup,
            handle_cleanup,
            child_cleanup,
            directory_cleanup,
            _evidence_binding: evidence_binding,
        })
    }

    /// Iterates every supported role/operation count observed in the clean trace.
    pub fn targets(&self) -> impl ExactSizeIterator<Item = L2IoSweepTarget> + '_ {
        self.baseline.targets.iter().copied()
    }

    /// Encodes a bounded, non-public baseline-discovery observation.
    #[must_use]
    pub fn encode_v1(&self) -> String {
        let target_counts = self
            .baseline
            .targets
            .iter()
            .map(|target| {
                format!(
                    "{}:{}={}",
                    target.file_role.label(),
                    target.operation.label(),
                    target.observed_count,
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let evidence = format!(
            concat!(
                "version=1\n",
                "protocol=l2-io-observation-v1\n",
                "scenario=E2E-TXN-001\n",
                "publication=prohibited\n",
                "status=validated\n",
                "coverage=partial\n",
                "sweep=baseline\n",
                "baseline=validated\n",
                "fault_build=true\n",
                "storage_scenario={}\n",
                "observed={}\n",
                "target_counts={}\n",
                "last_observed_ordinal={}\n",
                "total_observed_operations={}\n",
                "fixture_cleanup={}\n",
                "handle_cleanup={}\n",
                "child_cleanup={}\n",
                "directory_cleanup={}\n"
            ),
            match self.scenario {
                Scenario::InviterTransaction => "inviter-transaction",
                Scenario::JoinerTransaction => "joiner-transaction",
            },
            oracle_label(self.observed),
            target_counts,
            self.baseline.last_observed_ordinal,
            self.baseline.total_operations,
            pass_fail(self.fixture_cleanup),
            pass_fail(self.handle_cleanup),
            pass_fail(self.child_cleanup),
            pass_fail(self.directory_cleanup),
        );
        debug_assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
        evidence
    }
}

/// Bounded internal observation from one SQLite-visible L2 I/O failure case.
pub struct L2IoFaultReport {
    scenario: Scenario,
    observed: OracleState,
    fault: L2IoFaultObservation,
    fixture_cleanup: bool,
    handle_cleanup: bool,
    child_cleanup: bool,
    directory_cleanup: bool,
    evidence_binding: L2EvidenceBinding,
}

impl L2IoFaultReport {
    /// Encodes one bounded, non-public partial-coverage I/O observation.
    #[must_use]
    pub fn encode_v1(&self) -> String {
        let evidence = format!(
            concat!(
                "version=1\n",
                "protocol=l2-io-observation-v1\n",
                "scenario=E2E-TXN-001\n",
                "publication=prohibited\n",
                "status=validated\n",
                "coverage=partial\n",
                "sweep=return-code\n",
                "fault_build=true\n",
                "storage_scenario={}\n",
                "allowed={}\n",
                "observed={}\n",
                "file_role={}\n",
                "operation={}\n",
                "mode={}\n",
                "target_ordinal={}\n",
                "last_observed_ordinal={}\n",
                "total_observed_operations={}\n",
                "injected_failures={}\n",
                "sqlite_primary_code={}\n",
                "sqlite_extended_code={}\n",
                "transaction_result={}\n",
                "fixture_cleanup={}\n",
                "handle_cleanup={}\n",
                "child_cleanup={}\n",
                "directory_cleanup={}\n"
            ),
            match self.scenario {
                Scenario::InviterTransaction => "inviter-transaction",
                Scenario::JoinerTransaction => "joiner-transaction",
            },
            match self.scenario {
                Scenario::InviterTransaction => "I0|I1",
                Scenario::JoinerTransaction => "J0|J1",
            },
            oracle_label(self.observed),
            self.fault.file_role.label(),
            self.fault.operation.label(),
            self.fault.mode.label(),
            self.fault.target_ordinal,
            self.fault.last_observed_ordinal,
            self.fault.total_operations,
            self.fault.injected_failures,
            self.fault.sqlite_code & 0xff,
            self.fault.sqlite_code,
            if self.fault.transaction_succeeded {
                "success"
            } else {
                "rejected"
            },
            pass_fail(self.fixture_cleanup),
            pass_fail(self.handle_cleanup),
            pass_fail(self.child_cleanup),
            pass_fail(self.directory_cleanup),
        );
        debug_assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
        evidence
    }
}

/// Bounded internal observation from one commit-window pause/process kill.
pub struct L2IoPauseKillReport {
    scenario: Scenario,
    observed: OracleState,
    pause: L2IoPauseObservation,
    fixture_cleanup: bool,
    handle_cleanup: bool,
    child_cleanup: bool,
    directory_cleanup: bool,
    evidence_binding: L2EvidenceBinding,
}

impl L2IoPauseKillReport {
    /// Encodes one bounded, non-public pause/process-kill observation.
    #[must_use]
    pub fn encode_v1(&self) -> String {
        let evidence = format!(
            concat!(
                "version=1\n",
                "protocol=l2-io-observation-v1\n",
                "scenario=E2E-TXN-001\n",
                "publication=prohibited\n",
                "status=validated\n",
                "coverage=partial\n",
                "sweep=pause-process-kill\n",
                "fault_build=true\n",
                "storage_scenario={}\n",
                "allowed={}\n",
                "observed={}\n",
                "file_role={}\n",
                "operation={}\n",
                "mode=pause-process-kill\n",
                "target_ordinal={}\n",
                "last_observed_ordinal={}\n",
                "total_observed_operations={}\n",
                "pause=confirmed\n",
                "process_termination=confirmed\n",
                "fixture_cleanup={}\n",
                "handle_cleanup={}\n",
                "child_cleanup={}\n",
                "directory_cleanup={}\n"
            ),
            match self.scenario {
                Scenario::InviterTransaction => "inviter-transaction",
                Scenario::JoinerTransaction => "joiner-transaction",
            },
            match self.scenario {
                Scenario::InviterTransaction => "I0|I1",
                Scenario::JoinerTransaction => "J0|J1",
            },
            oracle_label(self.observed),
            self.pause.file_role.label(),
            self.pause.operation.label(),
            self.pause.target_ordinal,
            self.pause.last_observed_ordinal,
            self.pause.total_operations,
            pass_fail(self.fixture_cleanup),
            pass_fail(self.handle_cleanup),
            pass_fail(self.child_cleanup),
            pass_fail(self.directory_cleanup),
        );
        debug_assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
        evidence
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct L2IoSweepCase {
    file_role: L2IoFileRole,
    operation: L2IoOperation,
    mode: L2IoFaultMode,
    sqlite_code: i32,
    target_ordinal: u16,
}

impl L2IoFaultReport {
    const fn sweep_case(&self) -> L2IoSweepCase {
        L2IoSweepCase {
            file_role: self.fault.file_role,
            operation: self.fault.operation,
            mode: self.fault.mode,
            sqlite_code: self.fault.sqlite_code,
            target_ordinal: self.fault.target_ordinal,
        }
    }
}

/// Internal observation that every baseline-derived I/O case completed once.
pub struct L2IoSweepReport {
    scenario: Scenario,
    targets: Vec<L2IoSweepTarget>,
    baseline_last_observed_ordinal: u16,
    baseline_total_operations: usize,
    completed_cases: usize,
    empty_states: usize,
    committed_states: usize,
    evidence_cases: Vec<L2EvidenceCase>,
}

impl L2IoSweepReport {
    /// Validates exact coverage of every supported code, mode, and observed ordinal.
    pub fn new(
        scenario: Scenario,
        baseline: &L2IoBaselineReport,
        cases: &[L2IoFaultReport],
    ) -> Result<Self, SessionCtlError> {
        if baseline.scenario != scenario
            || !baseline.fixture_cleanup
            || !baseline.handle_cleanup
            || !baseline.child_cleanup
            || !baseline.directory_cleanup
            || !matches!(
                (scenario, baseline.observed),
                (Scenario::InviterTransaction, OracleState::InviterNew)
                    | (Scenario::JoinerTransaction, OracleState::JoinerNew)
            )
        {
            return Err(stage("L2 I/O sweep baseline"));
        }

        let mut expected = Vec::new();
        for target in &baseline.baseline.targets {
            for target_ordinal in 0..target.observed_count {
                for mode in [L2IoFaultMode::OneShot, L2IoFaultMode::Persistent] {
                    for &sqlite_code in l2_io_supported_codes(target.operation) {
                        expected.push(L2IoSweepCase {
                            file_role: target.file_role,
                            operation: target.operation,
                            mode,
                            sqlite_code,
                            target_ordinal,
                        });
                    }
                }
            }
        }
        if expected.is_empty() || expected.len() > 32_768 || cases.len() != expected.len() {
            return Err(stage("L2 I/O sweep coverage"));
        }

        let mut actual = Vec::with_capacity(cases.len());
        let mut empty_states = 0_usize;
        let mut committed_states = 0_usize;
        for case in cases {
            if case.scenario != scenario
                || !case.fixture_cleanup
                || !case.handle_cleanup
                || !case.child_cleanup
                || !case.directory_cleanup
            {
                return Err(stage("L2 I/O sweep case"));
            }
            match (scenario, case.observed) {
                (Scenario::InviterTransaction, OracleState::InviterOld)
                | (Scenario::JoinerTransaction, OracleState::JoinerOld) => {
                    empty_states = empty_states.saturating_add(1);
                }
                (Scenario::InviterTransaction, OracleState::InviterNew)
                | (Scenario::JoinerTransaction, OracleState::JoinerNew) => {
                    committed_states = committed_states.saturating_add(1);
                }
                _ => return Err(stage("L2 I/O sweep oracle")),
            }
            if case.fault.transaction_succeeded {
                let target = baseline
                    .baseline
                    .targets
                    .iter()
                    .find(|target| {
                        target.file_role == case.fault.file_role
                            && target.operation == case.fault.operation
                    })
                    .ok_or_else(|| stage("L2 I/O sweep success"))?;
                let committed = matches!(
                    (scenario, case.observed),
                    (Scenario::InviterTransaction, OracleState::InviterNew)
                        | (Scenario::JoinerTransaction, OracleState::JoinerNew)
                );
                let remaining = usize::from(target.observed_count)
                    .saturating_sub(usize::from(case.fault.target_ordinal));
                let persistent_suffix_is_exact = case.fault.mode != L2IoFaultMode::Persistent
                    || case.fault.injected_failures == remaining;
                if case.fault.operation != L2IoOperation::Unlock
                    || !committed
                    || !persistent_suffix_is_exact
                {
                    return Err(stage("L2 I/O sweep success"));
                }
            }
            actual.push(case.sweep_case());
        }
        for expected_case in &expected {
            if actual
                .iter()
                .filter(|actual_case| *actual_case == expected_case)
                .count()
                != 1
            {
                return Err(stage("L2 I/O sweep coverage"));
            }
        }

        let evidence_cases = canonical_evidence_cases(
            cases
                .iter()
                .map(|case| {
                    let last_fully_explored_ordinal = baseline
                        .baseline
                        .targets
                        .iter()
                        .find(|target| {
                            target.file_role == case.fault.file_role
                                && target.operation == case.fault.operation
                        })
                        .map(|target| target.observed_count.saturating_sub(1))
                        .ok_or_else(|| stage("L2 I/O evidence case"))?;
                    Ok(L2EvidenceCase::sqlite_return_code(
                        case,
                        last_fully_explored_ordinal,
                    ))
                })
                .collect::<Result<Vec<_>, SessionCtlError>>()?,
        )?;
        Ok(Self {
            scenario,
            targets: baseline.baseline.targets.clone(),
            baseline_last_observed_ordinal: baseline.baseline.last_observed_ordinal,
            baseline_total_operations: baseline.baseline.total_operations,
            completed_cases: cases.len(),
            empty_states,
            committed_states,
            evidence_cases,
        })
    }

    /// Encodes the bounded, non-public complete-coverage observation.
    #[must_use]
    pub fn encode_v1(&self) -> String {
        let target_counts = self
            .targets
            .iter()
            .map(|target| {
                format!(
                    "{}:{}={}",
                    target.file_role.label(),
                    target.operation.label(),
                    target.observed_count,
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let last_explored = self
            .targets
            .iter()
            .map(|target| {
                format!(
                    "{}:{}={}",
                    target.file_role.label(),
                    target.operation.label(),
                    target.observed_count.saturating_sub(1),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let mut extended_codes = self
            .targets
            .iter()
            .flat_map(|target| l2_io_supported_codes(target.operation).iter().copied())
            .collect::<Vec<_>>();
        extended_codes.sort_unstable();
        extended_codes.dedup();
        let extended_codes = extended_codes
            .iter()
            .map(i32::to_string)
            .collect::<Vec<_>>()
            .join("|");
        let evidence = format!(
            concat!(
                "version=1\n",
                "protocol=l2-io-observation-v1\n",
                "scenario=E2E-TXN-001\n",
                "publication=prohibited\n",
                "status=validated\n",
                "coverage=complete\n",
                "sweep=return-code\n",
                "fault_build=true\n",
                "storage_scenario={}\n",
                "allowed={}\n",
                "modes=one-shot|persistent\n",
                "sqlite_primary_codes=10|13\n",
                "sqlite_extended_codes={}\n",
                "target_counts={}\n",
                "last_fully_explored_ordinals={}\n",
                "baseline_last_observed_ordinal={}\n",
                "baseline_total_observed_operations={}\n",
                "completed_cases={}\n",
                "observed_empty_states={}\n",
                "observed_committed_states={}\n",
                "fixture_cleanup=pass\n",
                "handle_cleanup=pass\n",
                "child_cleanup=pass\n",
                "directory_cleanup=pass\n",
                "integrity=pass\n",
                "schema=pass\n",
                "semantic_oracle=pass\n",
                "exact_retry=pass\n"
            ),
            match self.scenario {
                Scenario::InviterTransaction => "inviter-transaction",
                Scenario::JoinerTransaction => "joiner-transaction",
            },
            match self.scenario {
                Scenario::InviterTransaction => "I0|I1",
                Scenario::JoinerTransaction => "J0|J1",
            },
            extended_codes,
            target_counts,
            last_explored,
            self.baseline_last_observed_ordinal,
            self.baseline_total_operations,
            self.completed_cases,
            self.empty_states,
            self.committed_states,
        );
        debug_assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
        evidence
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct L2IoPauseSweepCase {
    file_role: L2IoFileRole,
    operation: L2IoOperation,
    target_ordinal: u16,
}

impl L2IoPauseKillReport {
    const fn sweep_case(&self) -> L2IoPauseSweepCase {
        L2IoPauseSweepCase {
            file_role: self.pause.file_role,
            operation: self.pause.operation,
            target_ordinal: self.pause.target_ordinal,
        }
    }
}

/// Internal observation that every baseline-derived commit-window pause was killed once.
pub struct L2IoPauseSweepReport {
    scenario: Scenario,
    targets: Vec<L2IoSweepTarget>,
    completed_cases: usize,
    empty_states: usize,
    committed_states: usize,
    evidence_cases: Vec<L2EvidenceCase>,
}

impl L2IoPauseSweepReport {
    /// Validates exact pause/process-kill coverage for all supported baseline ordinals.
    pub fn new(
        scenario: Scenario,
        baseline: &L2IoBaselineReport,
        cases: &[L2IoPauseKillReport],
    ) -> Result<Self, SessionCtlError> {
        if baseline.scenario != scenario
            || !baseline.fixture_cleanup
            || !baseline.handle_cleanup
            || !baseline.child_cleanup
            || !baseline.directory_cleanup
            || !matches!(
                (scenario, baseline.observed),
                (Scenario::InviterTransaction, OracleState::InviterNew)
                    | (Scenario::JoinerTransaction, OracleState::JoinerNew)
            )
        {
            return Err(stage("L2 I/O pause sweep baseline"));
        }
        let targets = baseline
            .baseline
            .targets
            .iter()
            .copied()
            .filter(|target| l2_io_pause_supported(target.file_role, target.operation))
            .collect::<Vec<_>>();
        let expected = targets
            .iter()
            .flat_map(|target| {
                (0..target.observed_count).map(|target_ordinal| L2IoPauseSweepCase {
                    file_role: target.file_role,
                    operation: target.operation,
                    target_ordinal,
                })
            })
            .collect::<Vec<_>>();
        if expected.is_empty() || expected.len() > 4_096 || cases.len() != expected.len() {
            return Err(stage("L2 I/O pause sweep coverage"));
        }

        let mut actual = Vec::with_capacity(cases.len());
        let mut empty_states = 0_usize;
        let mut committed_states = 0_usize;
        for case in cases {
            if case.scenario != scenario
                || !case.fixture_cleanup
                || !case.handle_cleanup
                || !case.child_cleanup
                || !case.directory_cleanup
            {
                return Err(stage("L2 I/O pause sweep case"));
            }
            match (scenario, case.observed) {
                (Scenario::InviterTransaction, OracleState::InviterOld)
                | (Scenario::JoinerTransaction, OracleState::JoinerOld) => {
                    empty_states = empty_states.saturating_add(1);
                }
                (Scenario::InviterTransaction, OracleState::InviterNew)
                | (Scenario::JoinerTransaction, OracleState::JoinerNew) => {
                    committed_states = committed_states.saturating_add(1);
                }
                _ => return Err(stage("L2 I/O pause sweep oracle")),
            }
            actual.push(case.sweep_case());
        }
        for expected_case in &expected {
            if actual
                .iter()
                .filter(|actual_case| *actual_case == expected_case)
                .count()
                != 1
            {
                return Err(stage("L2 I/O pause sweep coverage"));
            }
        }

        let evidence_cases = canonical_evidence_cases(
            cases
                .iter()
                .map(|case| {
                    let last_fully_explored_ordinal = targets
                        .iter()
                        .find(|target| {
                            target.file_role == case.pause.file_role
                                && target.operation == case.pause.operation
                        })
                        .map(|target| target.observed_count.saturating_sub(1))
                        .ok_or_else(|| stage("L2 I/O pause evidence case"))?;
                    Ok(L2EvidenceCase::commit_window_process_kill(
                        case,
                        last_fully_explored_ordinal,
                    ))
                })
                .collect::<Result<Vec<_>, SessionCtlError>>()?,
        )?;
        Ok(Self {
            scenario,
            targets,
            completed_cases: cases.len(),
            empty_states,
            committed_states,
            evidence_cases,
        })
    }

    /// Encodes the bounded, non-public pause/process-kill coverage observation.
    #[must_use]
    pub fn encode_v1(&self) -> String {
        let target_counts = self
            .targets
            .iter()
            .map(|target| {
                format!(
                    "{}:{}={}",
                    target.file_role.label(),
                    target.operation.label(),
                    target.observed_count,
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let last_explored = self
            .targets
            .iter()
            .map(|target| {
                format!(
                    "{}:{}={}",
                    target.file_role.label(),
                    target.operation.label(),
                    target.observed_count.saturating_sub(1),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let evidence = format!(
            concat!(
                "version=1\n",
                "protocol=l2-io-observation-v1\n",
                "scenario=E2E-TXN-001\n",
                "publication=prohibited\n",
                "status=validated\n",
                "coverage=complete\n",
                "sweep=pause-process-kill\n",
                "fault_build=true\n",
                "storage_scenario={}\n",
                "allowed={}\n",
                "target_counts={}\n",
                "last_fully_explored_ordinals={}\n",
                "completed_cases={}\n",
                "observed_empty_states={}\n",
                "observed_committed_states={}\n",
                "pause=confirmed\n",
                "process_termination=confirmed\n",
                "fixture_cleanup=pass\n",
                "handle_cleanup=pass\n",
                "child_cleanup=pass\n",
                "directory_cleanup=pass\n",
                "integrity=pass\n",
                "schema=pass\n",
                "semantic_oracle=pass\n",
                "exact_retry=pass\n"
            ),
            match self.scenario {
                Scenario::InviterTransaction => "inviter-transaction",
                Scenario::JoinerTransaction => "joiner-transaction",
            },
            match self.scenario {
                Scenario::InviterTransaction => "I0|I1",
                Scenario::JoinerTransaction => "J0|J1",
            },
            target_counts,
            last_explored,
            self.completed_cases,
            self.empty_states,
            self.committed_states,
        );
        debug_assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
        evidence
    }
}

const fn l2_io_pause_supported(file_role: L2IoFileRole, operation: L2IoOperation) -> bool {
    matches!(
        (file_role, operation),
        (
            L2IoFileRole::RollbackJournal,
            L2IoOperation::Write | L2IoOperation::Sync | L2IoOperation::Delete,
        ) | (
            L2IoFileRole::MainDatabase,
            L2IoOperation::Write | L2IoOperation::Sync,
        )
    )
}

fn l2_io_supported_codes(operation: L2IoOperation) -> &'static [i32] {
    match operation {
        L2IoOperation::Read => &[rusqlite::ffi::SQLITE_IOERR_READ],
        L2IoOperation::Write => &[
            rusqlite::ffi::SQLITE_FULL,
            rusqlite::ffi::SQLITE_IOERR_WRITE,
        ],
        L2IoOperation::Truncate => &[rusqlite::ffi::SQLITE_IOERR_TRUNCATE],
        L2IoOperation::Sync => &[rusqlite::ffi::SQLITE_IOERR_FSYNC],
        L2IoOperation::Delete => &[rusqlite::ffi::SQLITE_IOERR_DELETE],
        L2IoOperation::Lock => &[rusqlite::ffi::SQLITE_IOERR_LOCK],
        L2IoOperation::Unlock => &[rusqlite::ffi::SQLITE_IOERR_UNLOCK],
        L2IoOperation::CheckReservedLock => &[rusqlite::ffi::SQLITE_IOERR_CHECKRESERVEDLOCK],
    }
}

/// Runs one bounded controller probe through the checked hidden binary.
pub fn run_l2_process_probe(
    executable: &Path,
    probe: L2HarnessProbe,
) -> Result<L2ProcessReport, SessionCtlError> {
    let checkpoint = match probe {
        L2HarnessProbe::GracefulContinue => Checkpoint::InviterBeforeShadowFinalize,
        L2HarnessProbe::NonzeroLeaseGeneration
        | L2HarnessProbe::ChangedAttemptCeiling
        | L2HarnessProbe::InviterRetryMutation => Checkpoint::InviterAfterCommitReturn,
        L2HarnessProbe::JoinerRetryMutation => Checkpoint::JoinerAfterCommitReturn,
        L2HarnessProbe::JoinerRetainedKeyPackage => Checkpoint::JoinerAfterCommitReturn,
        L2HarnessProbe::MissingAcknowledgement => Checkpoint::InviterAfterGroupUpsert,
        _ => Checkpoint::InviterBeforeBegin,
    };
    run_l2_process_case(executable, L2ProcessCase::new(checkpoint, 0)?, probe)
}

/// Runs one closed real-storage case through the checked hidden binary.
pub fn run_l2_process_case(
    executable: &Path,
    case: L2ProcessCase,
    probe: L2HarnessProbe,
) -> Result<L2ProcessReport, SessionCtlError> {
    if !executable.is_absolute() || !executable.is_file() {
        return Err(stage("L2 executable"));
    }
    let case_id = CaseId::new(random_nonzero()?).map_err(|_| stage("L2 case"))?;
    let target = ControlFrame::new_checkpoint(case_id, case.checkpoint, case.occurrence)
        .map_err(|_| stage("L2 case"))?;
    let config = CaseConfig { target, probe };
    let mut root = ProcessRoot::new()?;
    let scenario_result = run_controller(executable, root.path(), config);
    let cleanup_result = root.cleanup();
    let controller = scenario_result?;
    cleanup_result?;
    let repository_root = repository_root();
    let report = L2ProcessReport {
        case_id,
        case,
        trace: controller.trace,
        probe,
        commit: resolve_l1_process_git_commit(&repository_root)
            .unwrap_or_else(|| String::from("unavailable")),
        dirty: git_dirty_at(&repository_root).unwrap_or(true),
        toolchain: pinned_toolchain_at(&repository_root)
            .unwrap_or_else(|| String::from("unavailable")),
        lock_digest: lock_digest_at(&repository_root)
            .unwrap_or_else(|| String::from("unavailable")),
        observed: controller.observed,
        integrity: controller.integrity,
        schema: controller.schema,
        semantic_oracle: controller.semantic_oracle,
        exact_retry: controller.exact_retry,
        fixture_cleanup: controller.fixture_cleanup,
        writer_termination: controller.writer_termination,
        fresh_verifier: controller.fresh_verifier,
        redaction: controller.redaction,
        handle_cleanup: controller.handle_cleanup,
        child_cleanup: controller.child_cleanup,
        directory_cleanup: true,
        evidence_binding: controller.evidence_binding,
    };
    if report.encode_v1().len() > MAX_EVIDENCE_BYTES {
        return Err(stage("L2 evidence"));
    }
    Ok(report)
}

/// Discovers the exact checkpoint occurrences emitted by one clean transaction.
pub fn run_l2_process_baseline(
    executable: &Path,
    scenario: Scenario,
) -> Result<L2ProcessBaseline, SessionCtlError> {
    let terminal = match scenario {
        Scenario::InviterTransaction => Checkpoint::InviterBeforeShadowFinalize,
        Scenario::JoinerTransaction => Checkpoint::JoinerAfterCommitReturn,
    };
    let report = run_l2_process_case(
        executable,
        L2ProcessCase::new(terminal, 0)?,
        L2HarnessProbe::GracefulContinue,
    )?;
    let expected = match scenario {
        Scenario::InviterTransaction => OracleState::InviterNew,
        Scenario::JoinerTransaction => OracleState::JoinerNew,
    };
    if report.observed != expected
        || report.trace.is_empty()
        || report.trace.len() > MAX_APPLICATION_CHECKPOINTS
        || report.trace.last().copied() != Some(report.case)
        || report.trace.iter().any(|case| case.scenario() != scenario)
    {
        return Err(stage("L2 process baseline"));
    }
    for (index, case) in report.trace.iter().enumerate() {
        if report.trace[index + 1..].contains(case) {
            return Err(stage("L2 process baseline coverage"));
        }
    }
    Ok(L2ProcessBaseline {
        scenario,
        cases: report.trace,
    })
}

/// Runs one SQLite-visible fault against a fresh closed baseline and verifier.
pub fn run_l2_io_fault_case(
    executable: &Path,
    scenario: Scenario,
    driver: &mut impl L2IoFaultDriver,
) -> Result<L2IoFaultReport, SessionCtlError> {
    if !executable.is_absolute() || !executable.is_file() {
        return Err(stage("L2 executable"));
    }
    let config = l2_io_case_config(scenario)?;
    let mut root = ProcessRoot::new()?;
    let result = run_l2_io_fault_controller(executable, root.path(), config, driver);
    let cleanup = root.cleanup();
    let (
        observed,
        driver_observation,
        fixture_cleanup,
        handle_cleanup,
        child_cleanup,
        evidence_binding,
    ) = result?;
    cleanup?;
    let L2IoDriverObservation::Fault(fault) = driver_observation else {
        return Err(stage("L2 I/O fault evidence"));
    };
    let report = L2IoFaultReport {
        scenario,
        observed,
        fault,
        fixture_cleanup,
        handle_cleanup,
        child_cleanup,
        directory_cleanup: true,
        evidence_binding,
    };
    if report.encode_v1().len() > MAX_EVIDENCE_BYTES {
        return Err(stage("L2 I/O evidence"));
    }
    Ok(report)
}

/// Discovers one clean transaction-only named-VFS trace on a fresh baseline.
pub fn run_l2_io_baseline(
    executable: &Path,
    scenario: Scenario,
    driver: &mut impl L2IoFaultDriver,
) -> Result<L2IoBaselineReport, SessionCtlError> {
    if !executable.is_absolute() || !executable.is_file() {
        return Err(stage("L2 executable"));
    }
    let config = l2_io_case_config(scenario)?;
    let mut root = ProcessRoot::new()?;
    let result = run_l2_io_fault_controller(executable, root.path(), config, driver);
    let cleanup = root.cleanup();
    let (
        observed,
        driver_observation,
        fixture_cleanup,
        handle_cleanup,
        child_cleanup,
        evidence_binding,
    ) = result?;
    cleanup?;
    let L2IoDriverObservation::Baseline(baseline) = driver_observation else {
        return Err(stage("L2 I/O baseline evidence"));
    };
    let report = L2IoBaselineReport::new(
        scenario,
        observed,
        baseline,
        fixture_cleanup,
        handle_cleanup,
        child_cleanup,
        true,
        evidence_binding,
    )?;
    if report.encode_v1().len() > MAX_EVIDENCE_BYTES {
        return Err(stage("L2 I/O evidence"));
    }
    Ok(report)
}

/// Parent-owned fresh baseline and key for one killable pause child.
pub struct L2IoPauseKillCase {
    root: ProcessRoot,
    key: Zeroizing<[u8; KEY_BYTES]>,
    scenario: Scenario,
    expected_pause: L2IoPauseSweepCase,
    baseline_artifact: L2ArtifactSnapshot,
    fixture: CaseFixture,
    welcome_canary: Option<Zeroizing<Vec<u8>>>,
}

impl L2IoPauseKillCase {
    /// Absolute marked root passed only to the direct checked test child.
    pub fn root(&self) -> &Path {
        self.root.path()
    }

    /// Verifies the killed child's database in a fresh process, then removes the case root.
    pub fn finish(
        mut self,
        executable: &Path,
        pause: L2IoPauseObservation,
        pause_stdout: &[u8],
        pause_stderr: &[u8],
    ) -> Result<L2IoPauseKillReport, SessionCtlError> {
        if pause_stdout.len() > MAX_CHILD_OUTPUT_BYTES
            || pause_stderr.len() > MAX_CHILD_OUTPUT_BYTES
        {
            return Err(stage("L2 I/O pause output bound"));
        }
        if !executable.is_absolute() || !executable.is_file() {
            return Err(stage("L2 executable"));
        }
        if pause.file_role != self.expected_pause.file_role
            || pause.operation != self.expected_pause.operation
            || pause.target_ordinal != self.expected_pause.target_ordinal
        {
            return Err(stage("L2 I/O pause binding"));
        }
        if self.root.path().join(WRITER_KEY_NAME).exists()
            || self.root.path().join(WRITER_CASE_FIXTURE_NAME).exists()
        {
            return Err(stage("L2 I/O pause child load"));
        }
        if self.welcome_canary.is_none() {
            self.welcome_canary = read_optional_welcome_canary(self.root.path())?;
        }
        let result = verify_l2_io_root(
            executable,
            self.root.path(),
            &self.key,
            self.scenario,
            L2CaseSecrets {
                fixture: &self.fixture,
                welcome_canary: self.welcome_canary.as_ref().map(|value| value.as_slice()),
            },
            self.baseline_artifact,
            &[pause_stdout, pause_stderr],
        );
        let cleanup = self.root.cleanup();
        let (observed, fixture_cleanup, handle_cleanup, child_cleanup, evidence_binding) = result?;
        cleanup?;
        let report = L2IoPauseKillReport {
            scenario: self.scenario,
            observed,
            pause,
            fixture_cleanup,
            handle_cleanup,
            child_cleanup,
            directory_cleanup: true,
            evidence_binding,
        };
        if report.encode_v1().len() > MAX_EVIDENCE_BYTES {
            return Err(stage("L2 I/O pause evidence"));
        }
        Ok(report)
    }
}

/// Prepares a fresh closed baseline and parent-retained verifier key for one pause child.
pub fn prepare_l2_io_pause_kill_case(
    scenario: Scenario,
    file_role: L2IoFileRole,
    operation: L2IoOperation,
    target_ordinal: u16,
) -> Result<L2IoPauseKillCase, SessionCtlError> {
    if !l2_io_pause_supported(file_role, operation) || usize::from(target_ordinal) >= 4_096 {
        return Err(stage("L2 I/O pause target"));
    }
    let config = l2_io_case_config(scenario)?;
    let root = ProcessRoot::new()?;
    let key = Zeroizing::new(random_nonzero::<KEY_BYTES>()?);
    write_owned_file(&root.path().join(CASE_CONFIG_NAME), &config.encode(), false)?;
    let fixture = prepare_baseline(root.path(), &key, scenario)?;
    let baseline_artifact = encrypted_artifact_snapshot(root.path())?;
    let welcome_canary = read_optional_welcome_canary(root.path())?;
    let fixture_bytes = fixture.encode();
    write_owned_file(
        &root.path().join(WRITER_CASE_FIXTURE_NAME),
        fixture_bytes.as_ref(),
        true,
    )?;
    write_owned_file(
        &root.path().join(VERIFIER_CASE_FIXTURE_NAME),
        fixture_bytes.as_ref(),
        true,
    )?;
    write_owned_file(&root.path().join(WRITER_KEY_NAME), key.as_slice(), true)?;
    Ok(L2IoPauseKillCase {
        root,
        key,
        scenario,
        expected_pause: L2IoPauseSweepCase {
            file_role,
            operation,
            target_ordinal,
        },
        baseline_artifact,
        fixture,
        welcome_canary,
    })
}

/// Runs the checked child transaction and must remain blocked until the process is killed.
pub fn run_l2_io_pause_writer(
    root: &Path,
    driver: &mut impl L2IoPauseDriver,
) -> Result<(), SessionCtlError> {
    validate_root(root)?;
    let config = read_case_config(root)?;
    if config.probe != L2HarnessProbe::IoFault {
        return Err(stage("L2 I/O pause config"));
    }
    let fixture = read_fixture(root, WRITER_CASE_FIXTURE_NAME)?;
    let key = read_key(root, WRITER_KEY_NAME)?;
    if !driver.prepare_before_open() {
        return Err(stage("L2 I/O pause preparation"));
    }
    let observer = FaultObserver::new(
        config.target.case_id(),
        config.target.scenario(),
        std::sync::Arc::new(AutoContinueBarrier),
    );
    let storage = fault_testing::open_with_fault_vfs(
        &root.join(DATABASE_NAME),
        VaultKey::new(*key).map_err(|_| stage("L2 I/O pause writer"))?,
        observer.clone(),
    )
    .map_err(|_| stage("L2 I/O pause writer open"))?;
    if !driver.arm_after_open() {
        return Err(stage("L2 I/O pause arm"));
    }
    let _ =
        run_real_storage_transaction(&storage, observer, config.target.scenario(), &fixture, root);
    Err(stage("L2 I/O pause escaped"))
}

fn l2_io_case_config(scenario: Scenario) -> Result<CaseConfig, SessionCtlError> {
    let checkpoint = match scenario {
        Scenario::InviterTransaction => Checkpoint::InviterBeforeShadowFinalize,
        Scenario::JoinerTransaction => Checkpoint::JoinerAfterCommitReturn,
    };
    let case_id = CaseId::new(random_nonzero()?).map_err(|_| stage("L2 I/O case"))?;
    let target =
        ControlFrame::new_checkpoint(case_id, checkpoint, 0).map_err(|_| stage("L2 I/O case"))?;
    Ok(CaseConfig {
        target,
        probe: L2HarnessProbe::IoFault,
    })
}

fn run_l2_io_fault_controller(
    executable: &Path,
    root: &Path,
    config: CaseConfig,
    driver: &mut impl L2IoFaultDriver,
) -> Result<
    (
        OracleState,
        L2IoDriverObservation,
        bool,
        bool,
        bool,
        L2EvidenceBinding,
    ),
    SessionCtlError,
> {
    let key = Zeroizing::new(random_nonzero::<KEY_BYTES>()?);
    write_owned_file(&root.join(CASE_CONFIG_NAME), &config.encode(), false)?;
    let fixture = prepare_baseline(root, &key, config.target.scenario())?;
    let baseline_artifact = encrypted_artifact_snapshot(root)?;
    let mut welcome_canary = read_optional_welcome_canary(root)?;
    write_owned_file(
        &root.join(VERIFIER_CASE_FIXTURE_NAME),
        fixture.encode().as_ref(),
        true,
    )?;
    if !driver.prepare_before_open() {
        return Err(stage("L2 I/O driver preparation"));
    }
    let observer = FaultObserver::new(
        config.target.case_id(),
        config.target.scenario(),
        std::sync::Arc::new(AutoContinueBarrier),
    );
    let storage = fault_testing::open_with_fault_vfs(
        &root.join(DATABASE_NAME),
        VaultKey::new(*key).map_err(|_| stage("L2 I/O writer"))?,
        observer.clone(),
    )
    .map_err(|_| stage("L2 I/O writer open"))?;
    if !driver.arm_after_open() {
        return Err(stage("L2 I/O driver arm"));
    }
    let transaction_succeeded =
        run_real_storage_transaction(&storage, observer, config.target.scenario(), &fixture, root)
            .is_ok();
    if welcome_canary.is_none() {
        welcome_canary = read_optional_welcome_canary(root)?;
    }
    let fault = driver
        .disable_and_observe(transaction_succeeded)
        .ok_or_else(|| stage("L2 I/O driver evidence"))?;
    drop(storage);

    let (observed, fixture_cleanup, handle_cleanup, child_cleanup, evidence_binding) =
        verify_l2_io_root(
            executable,
            root,
            &key,
            config.target.scenario(),
            L2CaseSecrets {
                fixture: &fixture,
                welcome_canary: welcome_canary.as_ref().map(|value| value.as_slice()),
            },
            baseline_artifact,
            &[],
        )?;
    Ok((
        observed,
        fault,
        fixture_cleanup,
        handle_cleanup,
        child_cleanup,
        evidence_binding,
    ))
}

struct L2CaseSecrets<'a> {
    fixture: &'a CaseFixture,
    welcome_canary: Option<&'a [u8]>,
}

fn verify_l2_io_root(
    executable: &Path,
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    scenario: Scenario,
    secrets: L2CaseSecrets<'_>,
    baseline_artifact: L2ArtifactSnapshot,
    additional_surfaces: &[&[u8]],
) -> Result<(OracleState, bool, bool, bool, L2EvidenceBinding), SessionCtlError> {
    write_owned_file(&root.join(VERIFIER_KEY_NAME), key.as_slice(), true)?;
    let mut verifier = ManagedChild::spawn(executable, "verifier", root, false)?;
    let status = match verifier.wait(CHILD_WAIT) {
        Ok(status) => status,
        Err(error) => {
            verifier.terminate_and_reap()?;
            return Err(error);
        }
    };
    if !status.success() {
        return Err(stage("L2 I/O verifier"));
    }
    let stdout = verifier.stdout.collect(CHILD_WAIT)?;
    let stderr = verifier.stderr.collect(CHILD_WAIT)?;
    if !stderr.is_empty() || root.join(VERIFIER_KEY_NAME).exists() {
        return Err(stage("L2 I/O verifier output"));
    }
    let evidence = parse_io_verifier_evidence(&stdout, scenario)?;
    let fixture_cleanup = !root.join(VERIFIER_CASE_FIXTURE_NAME).exists()
        && !root.join(WELCOME_FIXTURE_NAME).exists();
    if !fixture_cleanup {
        return Err(stage("L2 I/O fixture cleanup"));
    }
    let handle_cleanup = prove_database_handle_cleanup(root)?;
    let mut surfaces = Vec::with_capacity(additional_surfaces.len() + 2);
    surfaces.extend_from_slice(additional_surfaces);
    surfaces.push(stdout.as_slice());
    surfaces.push(stderr.as_slice());
    let evidence_binding = collect_evidence_binding(
        root,
        key,
        secrets.fixture,
        secrets.welcome_canary,
        baseline_artifact,
        &surfaces,
    )?;
    Ok((
        evidence.observed,
        fixture_cleanup,
        handle_cleanup,
        true,
        evidence_binding,
    ))
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
    probe: L2HarnessProbe,
}

impl CaseConfig {
    fn encode(self) -> [u8; CASE_CONFIG_BYTES] {
        let mut encoded = [0_u8; CASE_CONFIG_BYTES];
        encoded[..CONTROL_FRAME_BYTES].copy_from_slice(&self.target.encode());
        encoded[CONTROL_FRAME_BYTES] = self.probe.code();
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, SessionCtlError> {
        if encoded.len() != CASE_CONFIG_BYTES {
            return Err(stage("L2 case config"));
        }
        let target = ControlFrame::decode(&encoded[..CONTROL_FRAME_BYTES])
            .map_err(|_| stage("L2 case config"))?;
        let probe = L2HarnessProbe::try_from(encoded[CONTROL_FRAME_BYTES])?;
        if target.kind() != FrameKind::Checkpoint
            || target.role() != Role::Writer
            || L2ProcessCase::new(target.checkpoint(), target.occurrence()).is_err()
        {
            return Err(stage("L2 case config"));
        }
        Ok(Self { target, probe })
    }

    fn case(self) -> Result<L2ProcessCase, SessionCtlError> {
        L2ProcessCase::new(self.target.checkpoint(), self.target.occurrence())
    }
}

const fn pass_fail(value: bool) -> &'static str {
    if value { "pass" } else { "fail" }
}

fn canonical_evidence_cases(
    mut cases: Vec<L2EvidenceCase>,
) -> Result<Vec<L2EvidenceCase>, SessionCtlError> {
    if cases.is_empty() || cases.len() > 4_096 {
        return Err(stage("L2 evidence case index"));
    }
    cases.sort_by(|left, right| left.key.cmp(&right.key));
    let first = cases
        .first()
        .ok_or_else(|| stage("L2 evidence case index"))?;
    if cases.windows(2).any(|pair| pair[0].key == pair[1].key)
        || cases.iter().any(|case| {
            case.key.is_empty()
                || case.key.len() > 256
                || !case
                    .key
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || case.binding.sqlcipher_version != first.binding.sqlcipher_version
                || case.binding.sqlite_version != first.binding.sqlite_version
                || !case.binding.redaction
        })
    {
        return Err(stage("L2 evidence case index"));
    }
    Ok(cases)
}

struct ControllerEvidence {
    observed: OracleState,
    trace: Vec<L2ProcessCase>,
    integrity: bool,
    schema: bool,
    semantic_oracle: bool,
    exact_retry: bool,
    fixture_cleanup: bool,
    writer_termination: bool,
    fresh_verifier: bool,
    redaction: bool,
    handle_cleanup: bool,
    child_cleanup: bool,
    evidence_binding: L2EvidenceBinding,
}

fn run_controller(
    executable: &Path,
    root: &Path,
    config: CaseConfig,
) -> Result<ControllerEvidence, SessionCtlError> {
    let key = Zeroizing::new(random_nonzero::<KEY_BYTES>()?);
    write_owned_file(&root.join(CASE_CONFIG_NAME), &config.encode(), false)?;
    let fixture = prepare_baseline(root, &key, config.target.scenario())?;
    let baseline_artifact = encrypted_artifact_snapshot(root)?;
    let mut welcome_canary = read_optional_welcome_canary(root)?;
    let fixture_bytes = fixture.encode();
    write_owned_file(
        &root.join(WRITER_CASE_FIXTURE_NAME),
        fixture_bytes.as_ref(),
        true,
    )?;
    write_owned_file(
        &root.join(VERIFIER_CASE_FIXTURE_NAME),
        fixture_bytes.as_ref(),
        true,
    )?;
    write_owned_file(&root.join(WRITER_KEY_NAME), key.as_slice(), true)?;

    let mut writer = ManagedChild::spawn(executable, "writer", root, true)?;
    if config.probe == L2HarnessProbe::MissingAcknowledgement {
        let encoded = writer
            .stdout
            .read_exact_frame(CONTROL_FRAME_BYTES, FRAME_WAIT)?;
        let first = ControlFrame::decode(&encoded).map_err(|_| stage("L2 checkpoint"))?;
        if first == config.target || first.scenario() != config.target.scenario() {
            return Err(stage("L2 missing acknowledgement"));
        }
        let blocked = writer
            .stdout
            .read_exact_frame(CONTROL_FRAME_BYTES, FRAME_WAIT)
            .is_err();
        writer.terminate_and_reap()?;
        return if blocked {
            Err(stage("L2 missing acknowledgement"))
        } else {
            Err(stage("L2 checkpoint advanced without acknowledgement"))
        };
    }
    let trace = advance_writer_to_target(&mut writer, config.target)?;
    let observed = trace.target;

    match config.probe {
        L2HarnessProbe::GracefulContinue => {
            writer.write_stdin(&observed.acknowledgement().encode())?;
            writer.close_stdin();
            if !writer.wait(CHILD_WAIT)?.success() {
                return Err(stage("L2 writer"));
            }
        }
        L2HarnessProbe::KillWhileBlocked
        | L2HarnessProbe::AdvanceWithoutAcknowledgement
        | L2HarnessProbe::OversizedOutput
        | L2HarnessProbe::SecretDiagnostic
        | L2HarnessProbe::MixedFixture
        | L2HarnessProbe::IdentityLoss
        | L2HarnessProbe::ReservationSubstitution
        | L2HarnessProbe::DefectiveSchema
        | L2HarnessProbe::LingeringHandle
        | L2HarnessProbe::NonzeroLeaseGeneration
        | L2HarnessProbe::ChangedAttemptCeiling
        | L2HarnessProbe::InviterRetryMutation
        | L2HarnessProbe::JoinerRetryMutation
        | L2HarnessProbe::JoinerRetainedKeyPackage => {
            writer.terminate_and_reap()?;
        }
        L2HarnessProbe::MissingAcknowledgement => unreachable!("handled before target advance"),
        L2HarnessProbe::Stall => return Err(stage("L2 checkpoint timeout")),
        L2HarnessProbe::IoFault => return Err(stage("L2 process probe")),
    }
    writer.stdout.require_empty(CHILD_WAIT)?;
    writer.stderr.require_empty(CHILD_WAIT)?;
    if welcome_canary.is_none() {
        welcome_canary = read_optional_welcome_canary(root)?;
    }
    if root.join(WRITER_KEY_NAME).exists() {
        return Err(stage("L2 writer key cleanup"));
    }

    match config.probe {
        L2HarnessProbe::MixedFixture => inject_mixed_group(root, &key, &fixture)?,
        L2HarnessProbe::IdentityLoss => inject_identity_loss(root, &key)?,
        L2HarnessProbe::ReservationSubstitution => {
            inject_reservation_substitution(root, &key, &fixture)?;
        }
        L2HarnessProbe::DefectiveSchema => inject_defective_schema(root, &key)?,
        L2HarnessProbe::NonzeroLeaseGeneration => {
            inject_inviter_lifecycle_defect(root, &key, &fixture, "lease_generation")?;
        }
        L2HarnessProbe::ChangedAttemptCeiling => {
            inject_inviter_lifecycle_defect(root, &key, &fixture, "attempt_ceiling")?;
        }
        L2HarnessProbe::JoinerRetainedKeyPackage => {
            inject_joiner_retained_key_package(root, &key, &fixture)?;
        }
        _ => {}
    }

    write_owned_file(&root.join(VERIFIER_KEY_NAME), key.as_slice(), true)?;
    let mut verifier = ManagedChild::spawn(executable, "verifier", root, false)?;
    let status = match verifier.wait(CHILD_WAIT) {
        Ok(status) => status,
        Err(error) => {
            verifier.terminate_and_reap()?;
            return Err(error);
        }
    };
    if !status.success() {
        return Err(stage("L2 verifier"));
    }
    let stdout = verifier.stdout.collect(CHILD_WAIT)?;
    let stderr = verifier.stderr.collect(CHILD_WAIT)?;
    let expected = config.case()?.expected();
    if !stderr.is_empty() {
        return Err(stage("L2 verifier output"));
    }
    if root.join(VERIFIER_KEY_NAME).exists() {
        return Err(stage("L2 verifier key cleanup"));
    }
    let fixture_cleanup = !root.join(WRITER_CASE_FIXTURE_NAME).exists()
        && !root.join(VERIFIER_CASE_FIXTURE_NAME).exists()
        && !root.join(WELCOME_FIXTURE_NAME).exists();
    if !fixture_cleanup {
        return Err(stage("L2 fixture cleanup"));
    }
    let handle_cleanup = prove_database_handle_cleanup(root)?;
    if config.probe.is_retry_conflict() {
        parse_retry_conflict_evidence(&stdout, expected)?;
        if !handle_cleanup {
            return Err(stage("L2 handle cleanup"));
        }
        return Err(stage("L2 retry conflict confirmed"));
    }
    let verifier_evidence = parse_verifier_evidence(&stdout, expected)?;
    let control_frames = trace
        .cases
        .iter()
        .map(|case| {
            ControlFrame::new_checkpoint(config.target.case_id(), case.checkpoint, case.occurrence)
                .map(ControlFrame::encode)
                .map_err(|_| stage("L2 evidence control frame"))
        })
        .collect::<Result<Vec<_>, _>>()?
        .concat();
    let evidence_binding = collect_evidence_binding(
        root,
        &key,
        &fixture,
        welcome_canary.as_ref().map(|value| value.as_slice()),
        baseline_artifact,
        &[
            stdout.as_slice(),
            stderr.as_slice(),
            control_frames.as_slice(),
        ],
    )?;
    Ok(ControllerEvidence {
        observed: verifier_evidence.observed,
        trace: trace.cases,
        integrity: verifier_evidence.integrity,
        schema: verifier_evidence.schema,
        semantic_oracle: verifier_evidence.semantic_oracle,
        exact_retry: verifier_evidence.exact_retry,
        fixture_cleanup,
        writer_termination: true,
        fresh_verifier: true,
        redaction: true,
        handle_cleanup,
        child_cleanup: true,
        evidence_binding,
    })
}

fn parse_retry_conflict_evidence(
    bytes: &[u8],
    expected: OracleState,
) -> Result<(), SessionCtlError> {
    let text = std::str::from_utf8(bytes).map_err(|_| stage("L2 verifier output"))?;
    let expected_oracle = format!("oracle={}", oracle_label(expected));
    if text.lines().collect::<Vec<_>>()
        != [
            "role=verifier",
            "result=retry-conflict-rejected",
            expected_oracle.as_str(),
            "conflict=exact",
            "mutation_free=pass",
        ]
    {
        return Err(stage("L2 verifier output"));
    }
    Ok(())
}

struct VerifierEvidence {
    observed: OracleState,
    integrity: bool,
    schema: bool,
    semantic_oracle: bool,
    exact_retry: bool,
}

fn parse_verifier_evidence(
    bytes: &[u8],
    expected: OracleState,
) -> Result<VerifierEvidence, SessionCtlError> {
    let text = std::str::from_utf8(bytes).map_err(|_| stage("L2 verifier output"))?;
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != 8
        || lines[0] != "role=verifier"
        || lines[1] != "result=pass"
        || lines[3] != "integrity=pass"
        || lines[4] != "schema=pass"
        || lines[5] != "semantic_oracle=pass"
        || lines[6] != "exclusive_lock=pass"
        || lines[7] != "exact_retry=pass"
    {
        return Err(stage("L2 verifier output"));
    }
    let observed = match lines[2] {
        "oracle=I0" => OracleState::InviterOld,
        "oracle=I1" => OracleState::InviterNew,
        "oracle=J0" => OracleState::JoinerOld,
        "oracle=J1" => OracleState::JoinerNew,
        _ => return Err(stage("L2 verifier output")),
    };
    if observed != expected {
        return Err(stage("L2 verifier output"));
    }
    Ok(VerifierEvidence {
        observed,
        integrity: true,
        schema: true,
        semantic_oracle: true,
        exact_retry: true,
    })
}

fn parse_io_verifier_evidence(
    bytes: &[u8],
    scenario: Scenario,
) -> Result<VerifierEvidence, SessionCtlError> {
    let text = std::str::from_utf8(bytes).map_err(|_| stage("L2 I/O verifier output"))?;
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != 8
        || lines[0] != "role=verifier"
        || lines[1] != "result=pass"
        || lines[3] != "integrity=pass"
        || lines[4] != "schema=pass"
        || lines[5] != "semantic_oracle=pass"
        || lines[6] != "exclusive_lock=pass"
        || lines[7] != "exact_retry=pass"
    {
        return Err(stage("L2 I/O verifier output"));
    }
    let observed = match (scenario, lines[2]) {
        (Scenario::InviterTransaction, "oracle=I0") => OracleState::InviterOld,
        (Scenario::InviterTransaction, "oracle=I1") => OracleState::InviterNew,
        (Scenario::JoinerTransaction, "oracle=J0") => OracleState::JoinerOld,
        (Scenario::JoinerTransaction, "oracle=J1") => OracleState::JoinerNew,
        _ => return Err(stage("L2 I/O verifier output")),
    };
    Ok(VerifierEvidence {
        observed,
        integrity: true,
        schema: true,
        semantic_oracle: true,
        exact_retry: true,
    })
}

struct CaseFixture {
    invitation_id: [u8; 16],
    invitation_generation: [u8; 64],
    join_request_id: [u8; 16],
    request_fingerprint: [u8; 32],
    transaction_id: [u8; 16],
    group_id: [u8; 32],
    key_package_reference: [u8; 32],
    credential_identity: [u8; 32],
}

impl CaseFixture {
    fn random() -> Result<Self, SessionCtlError> {
        Ok(Self {
            invitation_id: random_nonzero()?,
            invitation_generation: random_nonzero()?,
            join_request_id: random_nonzero()?,
            request_fingerprint: random_nonzero()?,
            transaction_id: random_nonzero()?,
            group_id: random_nonzero()?,
            key_package_reference: random_nonzero()?,
            credential_identity: random_nonzero()?,
        })
    }

    fn encode(&self) -> Zeroizing<[u8; CASE_FIXTURE_BYTES]> {
        let mut bytes = Zeroizing::new([0_u8; CASE_FIXTURE_BYTES]);
        let mut offset = 0;
        for field in [
            CASE_FIXTURE_MAGIC.as_slice(),
            self.invitation_id.as_slice(),
            self.invitation_generation.as_slice(),
            self.join_request_id.as_slice(),
            self.request_fingerprint.as_slice(),
            self.transaction_id.as_slice(),
            self.group_id.as_slice(),
            self.key_package_reference.as_slice(),
            self.credential_identity.as_slice(),
        ] {
            bytes[offset..offset + field.len()].copy_from_slice(field);
            offset += field.len();
        }
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, SessionCtlError> {
        if bytes.len() != CASE_FIXTURE_BYTES || &bytes[..8] != CASE_FIXTURE_MAGIC {
            return Err(stage("L2 fixture"));
        }
        let mut offset = 8;
        fn take<const N: usize>(
            bytes: &[u8],
            offset: &mut usize,
        ) -> Result<[u8; N], SessionCtlError> {
            let end = offset.checked_add(N).ok_or_else(|| stage("L2 fixture"))?;
            let value = bytes
                .get(*offset..end)
                .ok_or_else(|| stage("L2 fixture"))?
                .try_into()
                .map_err(|_| stage("L2 fixture"))?;
            *offset = end;
            Ok(value)
        }
        let fixture = Self {
            invitation_id: take(bytes, &mut offset)?,
            invitation_generation: take(bytes, &mut offset)?,
            join_request_id: take(bytes, &mut offset)?,
            request_fingerprint: take(bytes, &mut offset)?,
            transaction_id: take(bytes, &mut offset)?,
            group_id: take(bytes, &mut offset)?,
            key_package_reference: take(bytes, &mut offset)?,
            credential_identity: take(bytes, &mut offset)?,
        };
        if fixture.invitation_id.iter().all(|byte| *byte == 0)
            || fixture.invitation_generation.iter().all(|byte| *byte == 0)
            || fixture.join_request_id.iter().all(|byte| *byte == 0)
            || fixture.request_fingerprint.iter().all(|byte| *byte == 0)
            || fixture.transaction_id.iter().all(|byte| *byte == 0)
            || fixture.group_id.iter().all(|byte| *byte == 0)
            || fixture.key_package_reference.iter().all(|byte| *byte == 0)
            || fixture.credential_identity.iter().all(|byte| *byte == 0)
        {
            return Err(stage("L2 fixture"));
        }
        Ok(fixture)
    }
}

impl Drop for CaseFixture {
    fn drop(&mut self) {
        self.invitation_id.zeroize();
        self.invitation_generation.zeroize();
        self.join_request_id.zeroize();
        self.request_fingerprint.zeroize();
        self.transaction_id.zeroize();
        self.group_id.zeroize();
        self.key_package_reference.zeroize();
        self.credential_identity.zeroize();
    }
}

fn read_fixture(root: &Path, name: &str) -> Result<CaseFixture, SessionCtlError> {
    let path = root.join(name);
    let bytes = Zeroizing::new(read_owned_file(&path, CASE_FIXTURE_BYTES)?);
    fs::remove_file(&path).map_err(|_| stage("L2 fixture cleanup"))?;
    CaseFixture::decode(&bytes)
}

fn read_optional_welcome_canary(
    root: &Path,
) -> Result<Option<Zeroizing<Vec<u8>>>, SessionCtlError> {
    let path = root.join(WELCOME_FIXTURE_NAME);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(Zeroizing::new(read_bounded_owned_file(
        &path, 65_536,
    )?)))
}

fn prepare_baseline(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    scenario: Scenario,
) -> Result<CaseFixture, SessionCtlError> {
    let mut fixture = CaseFixture::random()?;
    let storage = SqlCipherStorage::create(
        &root.join(DATABASE_NAME),
        VaultKey::new(**key).map_err(|_| stage("L2 baseline"))?,
    )
    .map_err(|_| stage("L2 baseline"))?;
    let group_id = SessionGroupId::new(fixture.group_id).map_err(|_| stage("L2 baseline"))?;
    match scenario {
        Scenario::InviterTransaction => {
            storage
                .seed_reservation(
                    fixture.invitation_id,
                    fixture.invitation_generation,
                    fixture.join_request_id,
                    RESERVATION_EXPIRES_AT,
                    BASELINE_NOW,
                )
                .map_err(|_| stage("L2 baseline"))?;
            let client = create_durable_client_with_storage(
                group_id,
                storage.clone(),
                storage.clone(),
                storage.clone(),
            )
            .map_err(|_| stage("L2 baseline identity"))?;
            fixture.credential_identity = *client.credential_identity().as_bytes();
            if client
                .credential_identity()
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            {
                return Err(stage("L2 baseline identity"));
            }
        }
        Scenario::JoinerTransaction => {
            let bob = create_durable_client_with_storage(
                group_id,
                storage.clone(),
                storage.clone(),
                storage.clone(),
            )
            .map_err(|_| stage("L2 baseline identity"))?;
            fixture.credential_identity = *bob.credential_identity().as_bytes();
            let key_package = bob
                .generate_key_package(BASELINE_NOW)
                .map_err(|_| stage("L2 baseline KeyPackage"))?;
            let validated = create_key_package_validator()
                .validate_key_package(key_package.as_bytes(), BASELINE_NOW)
                .map_err(|_| stage("L2 baseline KeyPackage"))?;
            fixture.key_package_reference = *validated.key_package_reference();
            let alice = create_client().map_err(|_| stage("L2 baseline Alice"))?;
            let mut group = alice
                .create_group(group_id, BASELINE_NOW)
                .map_err(|_| stage("L2 baseline group"))?;
            let welcome = group
                .prepare_add(validated, BASELINE_NOW)
                .map_err(|_| stage("L2 baseline Add"))?
                .apply()
                .map_err(|_| stage("L2 baseline Add"))?
                .into_welcome();
            write_bounded_owned_file(
                &root.join(WELCOME_FIXTURE_NAME),
                welcome.as_bytes(),
                true,
                65_536,
            )?;
        }
    }
    drop(storage);
    Ok(fixture)
}

fn inject_mixed_group(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    fixture: &CaseFixture,
) -> Result<(), SessionCtlError> {
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;
    connection
        .execute(
            "INSERT INTO mls_groups(group_id, state) VALUES (?1, ?2)",
            params![fixture.group_id, [0x41_u8]],
        )
        .map_err(|_| stage("L2 mixed fixture"))?;
    Ok(())
}

fn inject_identity_loss(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
) -> Result<(), SessionCtlError> {
    open_keyed_connection(&root.join(DATABASE_NAME), key)?
        .execute("DELETE FROM mls_client_identity", [])
        .map_err(|_| stage("L2 identity defect"))?;
    Ok(())
}

fn inject_reservation_substitution(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    fixture: &CaseFixture,
) -> Result<(), SessionCtlError> {
    let substitute: [u8; 16] = random_nonzero()?;
    open_keyed_connection(&root.join(DATABASE_NAME), key)?
        .execute(
            "UPDATE reservations SET join_request_id = ?1 WHERE invitation_id = ?2",
            params![substitute, fixture.invitation_id],
        )
        .map_err(|_| stage("L2 reservation defect"))?;
    Ok(())
}

fn inject_defective_schema(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
) -> Result<(), SessionCtlError> {
    open_keyed_connection(&root.join(DATABASE_NAME), key)?
        .execute_batch("ALTER TABLE reservations RENAME COLUMN expires_at TO expires_at_defective;")
        .map_err(|_| stage("L2 schema defect"))
}

fn inject_inviter_lifecycle_defect(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    fixture: &CaseFixture,
    defect: &str,
) -> Result<(), SessionCtlError> {
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;
    let sql = match defect {
        "lease_generation" => {
            "UPDATE inviter_joins SET lease_generation = 1 WHERE transaction_id = ?1"
        }
        "attempt_ceiling" => {
            "UPDATE inviter_joins SET maximum_delivery_attempts = 4 WHERE transaction_id = ?1"
        }
        _ => return Err(stage("L2 lifecycle defect")),
    };
    if connection
        .execute(sql, params![fixture.transaction_id])
        .map_err(|_| stage("L2 lifecycle defect"))?
        != 1
    {
        return Err(stage("L2 lifecycle defect"));
    }
    Ok(())
}

fn inject_joiner_retained_key_package(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    fixture: &CaseFixture,
) -> Result<(), SessionCtlError> {
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;
    if connection
        .execute(
            "INSERT INTO key_packages(
                 key_package_ref, key_package, init_key, leaf_key, expires_at
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                fixture.key_package_reference,
                [0x4b_u8],
                [0x49_u8],
                [0x4c_u8],
                (BASELINE_NOW + 600) as i64,
            ],
        )
        .map_err(|_| stage("L2 retained KeyPackage defect"))?
        != 1
    {
        return Err(stage("L2 retained KeyPackage defect"));
    }
    Ok(())
}

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
            let envelope = OpaqueEnvelope::new(
                [0x81; 16],
                OUTBOX_EXPIRES_AT,
                addition.welcome().as_bytes().to_vec(),
            )
            .map_err(|_| stage("L2 writer Welcome"))?
            .encode_canonical()
            .map_err(|_| stage("L2 writer Welcome"))?;
            write_bounded_owned_file(&root.join(WELCOME_FIXTURE_NAME), &envelope, true, 65_536)?;
            let endpoint = fixture_endpoint()?;
            let transaction = InviterJoinTransaction::new(
                fixture.transaction_id,
                fixture.invitation_id,
                fixture.invitation_generation,
                fixture.join_request_id,
                fixture.request_fingerprint,
                fixture.group_id,
                0,
                1,
                APPROVAL_RECORD.to_vec(),
                envelope,
                endpoint,
                OUTBOX_EXPIRES_AT,
            )
            .map_err(|_| stage("L2 writer transaction"))?;
            storage
                .stage_inviter(transaction, BASELINE_NOW, PersistenceFault::None)
                .map_err(|_| stage("L2 writer transaction"))?;
            group
                .write_to_storage()
                .map_err(|_| stage("L2 writer transaction"))?;
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
    let outcome = verify_complete_state(root, &key, expected, &fixture, config.probe)?;
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
    fixture: &CaseFixture,
    probe: L2HarnessProbe,
) -> Result<VerificationOutcome, SessionCtlError> {
    let storage = SqlCipherStorage::open(
        &root.join(DATABASE_NAME),
        VaultKey::new(**key).map_err(|_| stage("L2 production reopen"))?,
    )
    .map_err(|_| stage("L2 production reopen"))?;
    if storage.schema_version().map_err(|_| stage("L2 schema"))? != 4
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
    if user_version != 4
        || metadata != (1, 4, 4)
        || schema_fingerprint(&connection)? != SCHEMA_FINGERPRINT_SHA256
    {
        return Err(stage("L2 schema"));
    }
    let welcome_path = root.join(WELCOME_FIXTURE_NAME);
    let expected_welcome = if expected == OracleState::InviterNew {
        Some(read_bounded_owned_file_once(
            &welcome_path,
            65_536,
            "L2 Welcome fixture cleanup",
        )?)
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

    fn test_evidence_binding() -> L2EvidenceBinding {
        L2EvidenceBinding {
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
