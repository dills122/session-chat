#![forbid(unsafe_code)]

use std::{
    fmt,
    sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock},
    time::Duration,
};

use crate::MAX_OPERATIONS;

const ROLE_COUNT: usize = 6;
const OPERATION_COUNT: usize = 11;
const MAX_PAUSE_WAIT: Duration = Duration::from_secs(90);

/// Closed SQLite file roles retained by the L2 adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum FileRole {
    /// The main encrypted database.
    MainDatabase = 0,
    /// The rollback journal used by the retained `journal_mode=DELETE` baseline.
    RollbackJournal = 1,
    /// A WAL file. Its appearance violates the retained baseline.
    Wal = 2,
    /// Shared-memory/WAL coordination. Its appearance violates the baseline.
    SharedMemory = 3,
    /// Any file-backed SQLite temporary role. Its appearance violates the baseline.
    Temporary = 4,
    /// An unrecognized or contradictory role. It always fails validation.
    Unknown = 5,
}

impl FileRole {
    const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn from_index(value: i32) -> Self {
        match value {
            0 => Self::MainDatabase,
            1 => Self::RollbackJournal,
            2 => Self::Wal,
            3 => Self::SharedMemory,
            4 => Self::Temporary,
            _ => Self::Unknown,
        }
    }
}

/// Closed, bounded VFS operations retained by the adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Operation {
    /// A delegated file open completed.
    Open = 0,
    /// File read.
    Read = 1,
    /// File write.
    Write = 2,
    /// File truncate.
    Truncate = 3,
    /// File synchronization.
    Sync = 4,
    /// VFS-level delete.
    Delete = 5,
    /// Advisory lock acquisition.
    Lock = 6,
    /// Advisory unlock.
    Unlock = 7,
    /// Reserved-lock query.
    CheckReservedLock = 8,
    /// Any shared-memory map/lock/barrier/unmap operation.
    SharedMemory = 9,
    /// Memory-mapped fetch or unfetch.
    Fetch = 10,
}

impl Operation {
    const fn index(self) -> usize {
        self as usize
    }
}

/// SQLite failure codes supported by the closed adapter protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultCode {
    /// `SQLITE_FULL` from a main/journal write.
    Full,
    /// `SQLITE_IOERR_READ`.
    IoErrRead,
    /// `SQLITE_IOERR_WRITE`.
    IoErrWrite,
    /// `SQLITE_IOERR_FSYNC`.
    IoErrFsync,
    /// `SQLITE_IOERR_TRUNCATE`.
    IoErrTruncate,
    /// `SQLITE_IOERR_DELETE`.
    IoErrDelete,
    /// `SQLITE_IOERR_LOCK`.
    IoErrLock,
    /// `SQLITE_IOERR_UNLOCK`.
    IoErrUnlock,
    /// `SQLITE_IOERR_CHECKRESERVEDLOCK`.
    IoErrCheckReservedLock,
}

impl FaultCode {
    /// Returns the actual SQLite primary or extended result code.
    pub const fn sqlite_code(self) -> i32 {
        match self {
            Self::Full => libsqlite3_sys::SQLITE_FULL,
            Self::IoErrRead => libsqlite3_sys::SQLITE_IOERR_READ,
            Self::IoErrWrite => libsqlite3_sys::SQLITE_IOERR_WRITE,
            Self::IoErrFsync => libsqlite3_sys::SQLITE_IOERR_FSYNC,
            Self::IoErrTruncate => libsqlite3_sys::SQLITE_IOERR_TRUNCATE,
            Self::IoErrDelete => libsqlite3_sys::SQLITE_IOERR_DELETE,
            Self::IoErrLock => libsqlite3_sys::SQLITE_IOERR_LOCK,
            Self::IoErrUnlock => libsqlite3_sys::SQLITE_IOERR_UNLOCK,
            Self::IoErrCheckReservedLock => libsqlite3_sys::SQLITE_IOERR_CHECKRESERVEDLOCK,
        }
    }

    const fn supports(self, operation: Operation) -> bool {
        matches!(
            (self, operation),
            (Self::Full | Self::IoErrWrite, Operation::Write)
                | (Self::IoErrRead, Operation::Read)
                | (Self::IoErrFsync, Operation::Sync)
                | (Self::IoErrTruncate, Operation::Truncate)
                | (Self::IoErrDelete, Operation::Delete)
                | (Self::IoErrLock, Operation::Lock)
                | (Self::IoErrUnlock, Operation::Unlock)
                | (Self::IoErrCheckReservedLock, Operation::CheckReservedLock)
        )
    }
}

/// One-shot or persistent injection behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultMode {
    /// Inject exactly at the requested observed ordinal.
    OneShot,
    /// Inject at the requested ordinal and every later matching operation.
    Persistent,
}

/// Public, secret-free action kind retained by a plan/snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultAction {
    /// Return the contained actual SQLite code.
    Return(FaultCode),
    /// Block at one supported commit-window operation.
    Pause,
}

/// One exact role/operation/zero-based ordinal target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultTarget {
    role: FileRole,
    operation: Operation,
    ordinal: u16,
}

impl FaultTarget {
    /// Constructs a target below the retained 4,096-operation bound.
    pub fn new(
        role: FileRole,
        operation: Operation,
        ordinal: usize,
    ) -> Result<Self, ControllerError> {
        if ordinal >= MAX_OPERATIONS
            || matches!(
                role,
                FileRole::Wal | FileRole::SharedMemory | FileRole::Temporary | FileRole::Unknown
            )
        {
            return Err(ControllerError::Rejected);
        }
        Ok(Self {
            role,
            operation,
            ordinal: u16::try_from(ordinal).map_err(|_| ControllerError::Rejected)?,
        })
    }

    /// Target file role.
    pub const fn role(self) -> FileRole {
        self.role
    }

    /// Target operation.
    pub const fn operation(self) -> Operation {
        self.operation
    }

    /// Zero-based ordinal among operations with the same role and operation.
    pub const fn ordinal(self) -> u16 {
        self.ordinal
    }
}

/// One closed injection or pause plan.
#[derive(Clone)]
pub struct FaultPlan {
    target: FaultTarget,
    mode: FaultMode,
    action: FaultAction,
    gate: Option<Arc<PauseGate>>,
}

impl FaultPlan {
    /// Constructs a result-code injection and rejects role/operation mismatches.
    pub fn return_code(
        target: FaultTarget,
        mode: FaultMode,
        code: FaultCode,
    ) -> Result<Self, ControllerError> {
        if !code.supports(target.operation) {
            return Err(ControllerError::Rejected);
        }
        Ok(Self {
            target,
            mode,
            action: FaultAction::Return(code),
            gate: None,
        })
    }

    /// Constructs a one-shot pause at a retained rollback-journal commit window.
    pub fn pause(target: FaultTarget, gate: Arc<PauseGate>) -> Result<Self, ControllerError> {
        let supported = matches!(
            (target.role, target.operation),
            (
                FileRole::RollbackJournal,
                Operation::Write | Operation::Sync | Operation::Delete
            ) | (FileRole::MainDatabase, Operation::Write | Operation::Sync)
        );
        if !supported {
            return Err(ControllerError::Rejected);
        }
        Ok(Self {
            target,
            mode: FaultMode::OneShot,
            action: FaultAction::Pause,
            gate: Some(gate),
        })
    }

    /// Returns the target without exposing any path or data bytes.
    pub const fn target(&self) -> FaultTarget {
        self.target
    }

    /// Returns the closed action kind.
    pub const fn action(&self) -> FaultAction {
        self.action
    }

    /// Returns whether injection is one-shot or persistent.
    pub const fn mode(&self) -> FaultMode {
        self.mode
    }
}

/// Coarse controller configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerError {
    /// The request is invalid, concurrent, or controller state is unavailable.
    Rejected,
}

impl fmt::Display for ControllerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fault VFS controller rejected")
    }
}

impl std::error::Error for ControllerError {}

/// Process-local pause gate used by a supervised writer operation.
pub struct PauseGate {
    state: Mutex<PauseState>,
    changed: Condvar,
}

#[derive(Default)]
struct PauseState {
    reached: bool,
    released: bool,
}

impl PauseGate {
    /// Creates an unreached, unreleased gate.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(PauseState::default()),
            changed: Condvar::new(),
        }
    }

    /// Waits a bounded time for the delegated operation to reach this gate.
    pub fn wait_until_reached(&self, timeout: Duration) -> bool {
        let timeout = timeout.min(MAX_PAUSE_WAIT);
        let Ok(state) = self.state.lock() else {
            return false;
        };
        let Ok((state, _)) = self
            .changed
            .wait_timeout_while(state, timeout, |state| !state.reached)
        else {
            return false;
        };
        state.reached
    }

    /// Releases a reached operation. Repeated release is harmless.
    pub fn release(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.released = true;
            self.changed.notify_all();
        }
    }

    pub(crate) fn block(&self) -> Result<(), ControllerError> {
        let mut state = self.state.lock().map_err(|_| ControllerError::Rejected)?;
        state.reached = true;
        self.changed.notify_all();
        while !state.released {
            state = self
                .changed
                .wait(state)
                .map_err(|_| ControllerError::Rejected)?;
        }
        Ok(())
    }
}

impl Default for PauseGate {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RoleEvidence {
    MainFlag,
    JournalFlag,
    WalFlag,
    TemporaryFlag,
    JournalName,
    WalName,
    SharedMemoryName,
    TemporaryName,
    SharedMemoryCallback,
    Unknown,
}

impl RoleEvidence {
    const fn expected_role(self) -> FileRole {
        match self {
            Self::MainFlag => FileRole::MainDatabase,
            Self::JournalFlag | Self::JournalName => FileRole::RollbackJournal,
            Self::WalFlag | Self::WalName => FileRole::Wal,
            Self::SharedMemoryName | Self::SharedMemoryCallback => FileRole::SharedMemory,
            Self::TemporaryFlag | Self::TemporaryName => FileRole::Temporary,
            Self::Unknown => FileRole::Unknown,
        }
    }

    pub(crate) const fn code(self) -> i32 {
        self as i32
    }

    pub(crate) const fn from_index(value: i32) -> Self {
        match value {
            0 => Self::MainFlag,
            1 => Self::JournalFlag,
            2 => Self::WalFlag,
            3 => Self::TemporaryFlag,
            4 => Self::JournalName,
            5 => Self::WalName,
            6 => Self::SharedMemoryName,
            7 => Self::TemporaryName,
            8 => Self::SharedMemoryCallback,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Delegated,
    Returned(i32),
    Paused,
}

/// Secret-free observed operation disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationDisposition {
    /// The operation was delegated to the captured default VFS.
    Delegated,
    /// The adapter returned this actual SQLite primary/extended result code.
    Returned(i32),
    /// The operation reached and blocked on the configured pause gate.
    Paused,
}

/// One bounded, path-free operation record suitable for L2 manifests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationRecord {
    global_ordinal: u16,
    matching_ordinal: u16,
    role: FileRole,
    operation: Operation,
    disposition: OperationDisposition,
}

impl OperationRecord {
    /// Zero-based ordinal across all observed operations since reset.
    pub const fn global_ordinal(self) -> u16 {
        self.global_ordinal
    }

    /// Zero-based ordinal for this exact role and operation.
    pub const fn matching_ordinal(self) -> u16 {
        self.matching_ordinal
    }

    /// Classified file role.
    pub const fn role(self) -> FileRole {
        self.role
    }

    /// Delegated operation kind.
    pub const fn operation(self) -> Operation {
        self.operation
    }

    /// Delegated, returned-code, or pause disposition.
    pub const fn disposition(self) -> OperationDisposition {
        self.disposition
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Event {
    global_ordinal: u16,
    matching_ordinal: u16,
    role: FileRole,
    evidence: RoleEvidence,
    operation: Operation,
    outcome: Outcome,
}

#[derive(Clone)]
struct PublicPlan {
    target: FaultTarget,
    mode: FaultMode,
    action: FaultAction,
}

struct State {
    events: Vec<Event>,
    counts: [[u16; OPERATION_COUNT]; ROLE_COUNT],
    overflowed: bool,
    plan: Option<FaultPlan>,
    armed: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            events: Vec::with_capacity(MAX_OPERATIONS),
            counts: [[0; OPERATION_COUNT]; ROLE_COUNT],
            overflowed: false,
            plan: None,
            armed: false,
        }
    }
}

/// Singleton bounded fault controller.
pub struct Controller {
    state: Mutex<State>,
}

/// Returns the process-local controller used by the registered named VFS.
pub fn controller() -> &'static Controller {
    static CONTROLLER: OnceLock<Controller> = OnceLock::new();
    CONTROLLER.get_or_init(|| Controller {
        state: Mutex::new(State::default()),
    })
}

impl Controller {
    /// Clears observations and disarms any prior plan.
    pub fn reset(&self) -> Result<(), ControllerError> {
        *self.lock()? = State::default();
        Ok(())
    }

    /// Arms one plan. A prior plan must be disabled or reset first.
    pub fn arm(&self, plan: FaultPlan) -> Result<(), ControllerError> {
        let mut state = self.lock()?;
        if state.plan.is_some() {
            return Err(ControllerError::Rejected);
        }
        state.plan = Some(plan);
        state.armed = true;
        Ok(())
    }

    /// Disables injection/pause while preserving bounded observations.
    pub fn disable(&self) -> Result<(), ControllerError> {
        self.lock()?.armed = false;
        Ok(())
    }

    /// Returns a bounded, path-free snapshot.
    pub fn snapshot(&self) -> Snapshot {
        let Ok(state) = self.state.lock() else {
            return Snapshot {
                events: Vec::new(),
                overflowed: true,
                plan: None,
            };
        };
        Snapshot {
            events: state.events.clone(),
            overflowed: state.overflowed,
            plan: state.plan.as_ref().map(|plan| PublicPlan {
                target: plan.target,
                mode: plan.mode,
                action: plan.action,
            }),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, ControllerError> {
        self.state.lock().map_err(|_| ControllerError::Rejected)
    }
}

pub(crate) enum Decision {
    Delegate,
    Return(i32),
    Pause(Arc<PauseGate>),
}

pub(crate) fn observe(role: FileRole, evidence: RoleEvidence, operation: Operation) -> Decision {
    let Ok(mut state) = controller().state.lock() else {
        return Decision::Return(fail_closed_code(operation));
    };
    if state.events.len() >= MAX_OPERATIONS {
        state.overflowed = true;
        return Decision::Return(fail_closed_code(operation));
    }

    let matching_ordinal = state.counts[role.index()][operation.index()];
    let global_ordinal = u16::try_from(state.events.len()).unwrap_or(u16::MAX);
    state.counts[role.index()][operation.index()] = matching_ordinal.saturating_add(1);

    let decision = match state.plan.as_ref().filter(|_| state.armed) {
        Some(plan)
            if plan.target.role == role
                && plan.target.operation == operation
                && match plan.mode {
                    FaultMode::OneShot => matching_ordinal == plan.target.ordinal,
                    FaultMode::Persistent => matching_ordinal >= plan.target.ordinal,
                } =>
        {
            match plan.action {
                FaultAction::Return(code) => Decision::Return(code.sqlite_code()),
                FaultAction::Pause => match plan.gate.as_ref() {
                    Some(gate) => Decision::Pause(Arc::clone(gate)),
                    None => Decision::Return(fail_closed_code(operation)),
                },
            }
        }
        _ => Decision::Delegate,
    };
    let outcome = match &decision {
        Decision::Delegate => Outcome::Delegated,
        Decision::Return(code) => Outcome::Returned(*code),
        Decision::Pause(_) => Outcome::Paused,
    };
    state.events.push(Event {
        global_ordinal,
        matching_ordinal,
        role,
        evidence,
        operation,
        outcome,
    });
    decision
}

fn fail_closed_code(operation: Operation) -> i32 {
    match operation {
        Operation::Read => libsqlite3_sys::SQLITE_IOERR_READ,
        Operation::Write => libsqlite3_sys::SQLITE_IOERR_WRITE,
        Operation::Truncate => libsqlite3_sys::SQLITE_IOERR_TRUNCATE,
        Operation::Sync => libsqlite3_sys::SQLITE_IOERR_FSYNC,
        Operation::Delete => libsqlite3_sys::SQLITE_IOERR_DELETE,
        Operation::Lock => libsqlite3_sys::SQLITE_IOERR_LOCK,
        Operation::Unlock => libsqlite3_sys::SQLITE_IOERR_UNLOCK,
        Operation::CheckReservedLock => libsqlite3_sys::SQLITE_IOERR_CHECKRESERVEDLOCK,
        Operation::Open | Operation::SharedMemory | Operation::Fetch => {
            libsqlite3_sys::SQLITE_IOERR
        }
    }
}

/// Coarse validation failure with no paths or data bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    /// The trace is incomplete, inconsistent, unexpected, or exceeds a bound.
    Rejected,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fault VFS evidence rejected")
    }
}

impl std::error::Error for ValidationError {}

/// Bounded, secret-free operation evidence.
pub struct Snapshot {
    events: Vec<Event>,
    overflowed: bool,
    plan: Option<PublicPlan>,
}

impl Snapshot {
    /// Total retained operation count.
    pub fn total_operations(&self) -> usize {
        self.events.len()
    }

    /// Number of operations for one exact role and operation.
    pub fn count(&self, role: FileRole, operation: Operation) -> usize {
        self.events
            .iter()
            .filter(|event| event.role == role && event.operation == operation)
            .count()
    }

    /// Number of actual injected SQLite failures.
    pub fn injected_failures(&self) -> usize {
        self.events
            .iter()
            .filter(|event| matches!(event.outcome, Outcome::Returned(_)))
            .count()
    }

    /// Number of reached pause operations.
    pub fn pauses(&self) -> usize {
        self.events
            .iter()
            .filter(|event| event.outcome == Outcome::Paused)
            .count()
    }

    /// Iterates the bounded, path-free operation records in observed order.
    pub fn operations(&self) -> impl ExactSizeIterator<Item = OperationRecord> + '_ {
        self.events.iter().map(|event| OperationRecord {
            global_ordinal: event.global_ordinal,
            matching_ordinal: event.matching_ordinal,
            role: event.role,
            operation: event.operation,
            disposition: match event.outcome {
                Outcome::Delegated => OperationDisposition::Delegated,
                Outcome::Returned(code) => OperationDisposition::Returned(code),
                Outcome::Paused => OperationDisposition::Paused,
            },
        })
    }

    /// Returns whether the hard operation bound was exceeded.
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Validates role classification, contiguous ordinals, bounds, and action codes.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.overflowed || self.events.len() > MAX_OPERATIONS {
            return Err(ValidationError::Rejected);
        }
        let mut next = [[0_u16; OPERATION_COUNT]; ROLE_COUNT];
        for (index, event) in self.events.iter().enumerate() {
            if usize::from(event.global_ordinal) != index
                || event.matching_ordinal != next[event.role.index()][event.operation.index()]
                || event.role != event.evidence.expected_role()
            {
                return Err(ValidationError::Rejected);
            }
            next[event.role.index()][event.operation.index()] =
                event.matching_ordinal.saturating_add(1);
            self.validate_outcome(event)?;
        }
        self.validate_plan_reached()
    }

    /// Additionally requires positive explicitly named connection reachability.
    pub fn validate_named_reachability(&self) -> Result<(), ValidationError> {
        self.validate()?;
        if self.count(FileRole::MainDatabase, Operation::Open) == 0 {
            return Err(ValidationError::Rejected);
        }
        Ok(())
    }

    /// Additionally rejects WAL, shared-memory, temp, and unknown file roles.
    pub fn validate_delete_journal_baseline(&self) -> Result<(), ValidationError> {
        self.validate_named_reachability()?;
        if self.events.iter().any(|event| {
            matches!(
                event.role,
                FileRole::Wal | FileRole::SharedMemory | FileRole::Temporary | FileRole::Unknown
            )
        }) {
            return Err(ValidationError::Rejected);
        }
        Ok(())
    }

    fn validate_outcome(&self, event: &Event) -> Result<(), ValidationError> {
        match event.outcome {
            Outcome::Delegated => Ok(()),
            Outcome::Returned(actual) => match self.plan.as_ref() {
                Some(plan) => match plan.action {
                    FaultAction::Return(expected)
                        if plan.target.role == event.role
                            && plan.target.operation == event.operation
                            && expected.sqlite_code() == actual =>
                    {
                        Ok(())
                    }
                    FaultAction::Return(_) | FaultAction::Pause => Err(ValidationError::Rejected),
                },
                None => Err(ValidationError::Rejected),
            },
            Outcome::Paused => match self.plan.as_ref() {
                Some(plan)
                    if plan.action == FaultAction::Pause
                        && plan.target.role == event.role
                        && plan.target.operation == event.operation =>
                {
                    Ok(())
                }
                Some(_) | None => Err(ValidationError::Rejected),
            },
        }
    }

    fn validate_plan_reached(&self) -> Result<(), ValidationError> {
        let Some(plan) = self.plan.as_ref() else {
            return Ok(());
        };
        let matching: Vec<&Event> = self
            .events
            .iter()
            .filter(|event| {
                event.role == plan.target.role
                    && event.operation == plan.target.operation
                    && match plan.action {
                        FaultAction::Return(code) => {
                            event.outcome == Outcome::Returned(code.sqlite_code())
                        }
                        FaultAction::Pause => event.outcome == Outcome::Paused,
                    }
            })
            .collect();
        let valid_count = match plan.mode {
            FaultMode::OneShot => matching.len() == 1,
            FaultMode::Persistent => !matching.is_empty(),
        };
        let starts_at_target = matching
            .first()
            .is_some_and(|event| event.matching_ordinal == plan.target.ordinal);
        if valid_count && starts_at_target {
            Ok(())
        } else {
            Err(ValidationError::Rejected)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(
        global: u16,
        matching: u16,
        role: FileRole,
        evidence: RoleEvidence,
        operation: Operation,
        outcome: Outcome,
    ) -> Event {
        Event {
            global_ordinal: global,
            matching_ordinal: matching,
            role,
            evidence,
            operation,
            outcome,
        }
    }

    fn snapshot(events: Vec<Event>, plan: Option<PublicPlan>) -> Snapshot {
        Snapshot {
            events,
            overflowed: false,
            plan,
        }
    }

    #[test]
    fn defective_wrong_role_classification_is_rejected() {
        let defective = snapshot(
            vec![event(
                0,
                0,
                FileRole::Temporary,
                RoleEvidence::MainFlag,
                Operation::Open,
                Outcome::Delegated,
            )],
            None,
        );
        assert_eq!(defective.validate(), Err(ValidationError::Rejected));
    }

    #[test]
    fn defective_skipped_ordinal_is_rejected() {
        let defective = snapshot(
            vec![event(
                0,
                1,
                FileRole::MainDatabase,
                RoleEvidence::MainFlag,
                Operation::Write,
                Outcome::Delegated,
            )],
            None,
        );
        assert_eq!(defective.validate(), Err(ValidationError::Rejected));
    }

    #[test]
    fn defective_result_code_is_rejected() {
        let target =
            FaultTarget::new(FileRole::MainDatabase, Operation::Write, 0).expect("valid target");
        let plan = PublicPlan {
            target,
            mode: FaultMode::OneShot,
            action: FaultAction::Return(FaultCode::IoErrWrite),
        };
        let defective = snapshot(
            vec![event(
                0,
                0,
                FileRole::MainDatabase,
                RoleEvidence::MainFlag,
                Operation::Write,
                Outcome::Returned(libsqlite3_sys::SQLITE_IOERR_FSYNC),
            )],
            Some(plan),
        );
        assert_eq!(defective.validate(), Err(ValidationError::Rejected));
    }

    #[test]
    fn unexpected_wal_temp_and_shared_memory_roles_are_rejected() {
        for (role, evidence) in [
            (FileRole::Wal, RoleEvidence::WalFlag),
            (FileRole::Temporary, RoleEvidence::TemporaryFlag),
            (FileRole::SharedMemory, RoleEvidence::SharedMemoryCallback),
        ] {
            let defective = snapshot(
                vec![
                    event(
                        0,
                        0,
                        FileRole::MainDatabase,
                        RoleEvidence::MainFlag,
                        Operation::Open,
                        Outcome::Delegated,
                    ),
                    event(1, 0, role, evidence, Operation::Open, Outcome::Delegated),
                ],
                None,
            );
            assert_eq!(
                defective.validate_delete_journal_baseline(),
                Err(ValidationError::Rejected)
            );
        }
    }

    #[test]
    fn defective_named_path_non_reachability_is_rejected() {
        let ordinary_bypass = snapshot(Vec::new(), None);
        assert_eq!(
            ordinary_bypass.validate_named_reachability(),
            Err(ValidationError::Rejected)
        );
    }

    #[test]
    fn unsupported_code_operation_and_pause_targets_fail_closed() {
        let read =
            FaultTarget::new(FileRole::MainDatabase, Operation::Read, 0).expect("read target");
        assert!(FaultPlan::return_code(read, FaultMode::OneShot, FaultCode::IoErrWrite).is_err());
        assert!(FaultPlan::pause(read, Arc::new(PauseGate::new())).is_err());
        assert!(
            FaultTarget::new(FileRole::MainDatabase, Operation::Write, MAX_OPERATIONS).is_err()
        );
    }

    #[test]
    fn every_closed_commit_window_pause_target_is_accepted() {
        for (role, operation) in [
            (FileRole::RollbackJournal, Operation::Write),
            (FileRole::RollbackJournal, Operation::Sync),
            (FileRole::RollbackJournal, Operation::Delete),
            (FileRole::MainDatabase, Operation::Write),
            (FileRole::MainDatabase, Operation::Sync),
        ] {
            let target = FaultTarget::new(role, operation, 0).expect("bounded target");
            assert!(FaultPlan::pause(target, Arc::new(PauseGate::new())).is_ok());
        }
    }

    #[test]
    fn bounded_trace_overflow_is_rejected() {
        let overflow = Snapshot {
            events: Vec::new(),
            overflowed: true,
            plan: None,
        };
        assert_eq!(overflow.validate(), Err(ValidationError::Rejected));
    }

    #[test]
    fn every_supported_code_is_the_exact_sqlite_code() {
        for (code, expected) in [
            (FaultCode::Full, libsqlite3_sys::SQLITE_FULL),
            (FaultCode::IoErrRead, libsqlite3_sys::SQLITE_IOERR_READ),
            (FaultCode::IoErrWrite, libsqlite3_sys::SQLITE_IOERR_WRITE),
            (FaultCode::IoErrFsync, libsqlite3_sys::SQLITE_IOERR_FSYNC),
            (
                FaultCode::IoErrTruncate,
                libsqlite3_sys::SQLITE_IOERR_TRUNCATE,
            ),
            (FaultCode::IoErrDelete, libsqlite3_sys::SQLITE_IOERR_DELETE),
            (FaultCode::IoErrLock, libsqlite3_sys::SQLITE_IOERR_LOCK),
            (FaultCode::IoErrUnlock, libsqlite3_sys::SQLITE_IOERR_UNLOCK),
            (
                FaultCode::IoErrCheckReservedLock,
                libsqlite3_sys::SQLITE_IOERR_CHECKRESERVEDLOCK,
            ),
        ] {
            assert_eq!(code.sqlite_code(), expected);
        }
    }
}
