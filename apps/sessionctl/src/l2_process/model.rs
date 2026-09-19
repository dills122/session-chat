//! L2 process cases and evidence reports.

use super::*;

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
    pub(super) const fn is_retry_conflict(self) -> bool {
        matches!(self, Self::InviterRetryMutation | Self::JoinerRetryMutation)
    }

    pub(super) const fn code(self) -> u8 {
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

    pub(super) const fn control_label(self) -> &'static str {
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
    pub(super) checkpoint: Checkpoint,
    pub(super) occurrence: u8,
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

    pub(super) const fn expected(self) -> OracleState {
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

    pub(super) const fn scenario(self) -> Scenario {
        self.checkpoint.scenario()
    }
}

pub(super) const fn oracle_label(state: OracleState) -> &'static str {
    match state {
        OracleState::InviterOld => "I0",
        OracleState::InviterNew => "I1",
        OracleState::JoinerOld => "J0",
        OracleState::JoinerNew => "J1",
    }
}

pub(super) const fn checkpoint_label(checkpoint: Checkpoint) -> &'static str {
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
    pub(super) case_id: CaseId,
    pub(super) case: L2ProcessCase,
    pub(super) trace: Vec<L2ProcessCase>,
    pub(super) probe: L2HarnessProbe,
    pub(super) commit: String,
    pub(super) dirty: bool,
    pub(super) toolchain: String,
    pub(super) lock_digest: String,
    pub(super) observed: OracleState,
    pub(super) integrity: bool,
    pub(super) schema: bool,
    pub(super) semantic_oracle: bool,
    pub(super) exact_retry: bool,
    pub(super) fixture_cleanup: bool,
    pub(super) writer_termination: bool,
    pub(super) fresh_verifier: bool,
    pub(super) redaction: bool,
    pub(super) handle_cleanup: bool,
    pub(super) child_cleanup: bool,
    pub(super) directory_cleanup: bool,
    pub(super) evidence_binding: L2EvidenceBinding,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct L2EvidenceBinding {
    pub(super) executables: Option<ExecutionIdentity>,
    pub(super) sqlcipher_version: String,
    pub(super) sqlite_version: String,
    pub(super) baseline_artifact_digest: [u8; 32],
    pub(super) post_recovery_artifact_digest: [u8; 32],
    pub(super) redaction: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) enum L2EvidenceCaseTarget {
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
pub(super) struct L2EvidenceCase {
    pub(super) key: String,
    pub(super) target: L2EvidenceCaseTarget,
    pub(super) binding: L2EvidenceBinding,
}

impl L2EvidenceCase {
    pub(super) fn application(report: &L2ProcessReport) -> Self {
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

    pub(super) fn sqlite_return_code(
        report: &L2IoFaultReport,
        last_fully_explored_ordinal: u16,
    ) -> Self {
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

    pub(super) fn commit_window_process_kill(
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
    pub(super) executables: Option<ExecutionIdentity>,
    pub(super) scenario: Scenario,
    pub(super) cases: Vec<L2ProcessCase>,
}

impl L2ProcessBaseline {
    /// Iterates every checkpoint occurrence emitted by the clean transaction.
    pub fn cases(&self) -> impl ExactSizeIterator<Item = L2ProcessCase> + '_ {
        self.cases.iter().copied()
    }
}

/// Non-public proof that every baseline-observed checkpoint was killed once.
pub struct L2ProcessSweepReport {
    pub(super) scenario: Scenario,
    pub(super) cases: Vec<L2ProcessCase>,
    pub(super) old_states: usize,
    pub(super) new_states: usize,
    pub(super) evidence_cases: Vec<L2EvidenceCase>,
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
                || report.evidence_binding.executables != baseline.executables
                || report.evidence_binding.executables.is_none()
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
