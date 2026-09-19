//! SQLite I/O fault and pause report models.

use super::*;

/// Closed file roles retained by the L2 I/O evidence schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L2IoFileRole {
    /// SQLCipher's main database file.
    MainDatabase,
    /// SQLCipher's rollback journal under the frozen DELETE-journal baseline.
    RollbackJournal,
}

impl L2IoFileRole {
    pub(super) const fn label(self) -> &'static str {
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
    pub(super) const fn label(self) -> &'static str {
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
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::OneShot => "one-shot",
            Self::Persistent => "persistent",
        }
    }
}

/// Bounded, path-free observation returned by a checked L2 I/O driver.
pub struct L2IoFaultObservation {
    pub(super) file_role: L2IoFileRole,
    pub(super) operation: L2IoOperation,
    pub(super) mode: L2IoFaultMode,
    pub(super) sqlite_code: i32,
    pub(super) target_ordinal: u16,
    pub(super) last_observed_ordinal: u16,
    pub(super) total_operations: usize,
    pub(super) injected_failures: usize,
    pub(super) transaction_succeeded: bool,
}

/// One observed role/operation pair and its complete baseline ordinal count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct L2IoSweepTarget {
    pub(super) file_role: L2IoFileRole,
    pub(super) operation: L2IoOperation,
    pub(super) observed_count: u16,
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
    pub(super) targets: Vec<L2IoSweepTarget>,
    pub(super) last_observed_ordinal: u16,
    pub(super) total_operations: usize,
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
    pub(super) file_role: L2IoFileRole,
    pub(super) operation: L2IoOperation,
    pub(super) target_ordinal: u16,
    pub(super) last_observed_ordinal: u16,
    pub(super) total_operations: usize,
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
    pub(super) scenario: Scenario,
    pub(super) observed: OracleState,
    pub(super) baseline: L2IoBaselineObservation,
    pub(super) fixture_cleanup: bool,
    pub(super) handle_cleanup: bool,
    pub(super) child_cleanup: bool,
    pub(super) directory_cleanup: bool,
    pub(super) _evidence_binding: L2EvidenceBinding,
}

impl L2IoBaselineReport {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
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
    pub(super) scenario: Scenario,
    pub(super) observed: OracleState,
    pub(super) fault: L2IoFaultObservation,
    pub(super) fixture_cleanup: bool,
    pub(super) handle_cleanup: bool,
    pub(super) child_cleanup: bool,
    pub(super) directory_cleanup: bool,
    pub(super) evidence_binding: L2EvidenceBinding,
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
    pub(super) scenario: Scenario,
    pub(super) observed: OracleState,
    pub(super) pause: L2IoPauseObservation,
    pub(super) fixture_cleanup: bool,
    pub(super) handle_cleanup: bool,
    pub(super) child_cleanup: bool,
    pub(super) directory_cleanup: bool,
    pub(super) evidence_binding: L2EvidenceBinding,
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
pub(super) struct L2IoSweepCase {
    pub(super) file_role: L2IoFileRole,
    pub(super) operation: L2IoOperation,
    pub(super) mode: L2IoFaultMode,
    pub(super) sqlite_code: i32,
    pub(super) target_ordinal: u16,
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
    pub(super) scenario: Scenario,
    pub(super) targets: Vec<L2IoSweepTarget>,
    pub(super) baseline_last_observed_ordinal: u16,
    pub(super) baseline_total_operations: usize,
    pub(super) completed_cases: usize,
    pub(super) empty_states: usize,
    pub(super) committed_states: usize,
    pub(super) evidence_cases: Vec<L2EvidenceCase>,
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
            if case.evidence_binding.executables != baseline._evidence_binding.executables
                || case.evidence_binding.executables.is_none()
                || case.scenario != scenario
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
pub(super) struct L2IoPauseSweepCase {
    pub(super) file_role: L2IoFileRole,
    pub(super) operation: L2IoOperation,
    pub(super) target_ordinal: u16,
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
    pub(super) scenario: Scenario,
    pub(super) targets: Vec<L2IoSweepTarget>,
    pub(super) completed_cases: usize,
    pub(super) empty_states: usize,
    pub(super) committed_states: usize,
    pub(super) evidence_cases: Vec<L2EvidenceCase>,
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
            if case.evidence_binding.executables != baseline._evidence_binding.executables
                || case.evidence_binding.executables.is_none()
                || case.scenario != scenario
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

pub(super) const fn l2_io_pause_supported(
    file_role: L2IoFileRole,
    operation: L2IoOperation,
) -> bool {
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

pub(super) fn l2_io_supported_codes(operation: L2IoOperation) -> &'static [i32] {
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
