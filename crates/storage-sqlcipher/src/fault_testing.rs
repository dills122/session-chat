//! Checked protocol used only by the retained L2 storage-fault build.

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use thiserror::Error;

use super::{OpenMode, SqlCipherStorage, StoreError, VaultKey};

const MAGIC: [u8; 8] = *b"SCL2CTL1";
const PROTOCOL_VERSION: u8 = 1;
const MAX_OCCURRENCE: u8 = 64;

/// Exact byte length of one canonical L2 control frame.
pub const CONTROL_FRAME_BYTES: usize = 30;
/// Evidence bit set only when the checked fault-testing cfg is compiled.
pub const FAULT_BUILD: bool = true;
/// One closed SQLite VFS name accepted by the cfg-only connection seam.
pub const FAULT_VFS_NAME: &str = "session-chat-storage-fault-v1";

/// Creates a fault-observed store while retaining SQLite's default VFS.
pub fn create(
    path: &Path,
    key: VaultKey,
    observer: FaultObserver,
) -> Result<SqlCipherStorage, StoreError> {
    SqlCipherStorage::open_internal(path, key, true, OpenMode::ObservedDefault(observer))
}

/// Opens a fault-observed store while retaining SQLite's default VFS.
pub fn open(
    path: &Path,
    key: VaultKey,
    observer: FaultObserver,
) -> Result<SqlCipherStorage, StoreError> {
    SqlCipherStorage::open_internal(path, key, false, OpenMode::ObservedDefault(observer))
}

/// Creates a fault-observed store through the one closed named VFS.
pub fn create_with_fault_vfs(
    path: &Path,
    key: VaultKey,
    observer: FaultObserver,
) -> Result<SqlCipherStorage, StoreError> {
    SqlCipherStorage::open_internal(path, key, true, OpenMode::ObservedFaultVfs(observer))
}

/// Opens a fault-observed store through the one closed named VFS.
pub fn open_with_fault_vfs(
    path: &Path,
    key: VaultKey,
    observer: FaultObserver,
) -> Result<SqlCipherStorage, StoreError> {
    SqlCipherStorage::open_internal(path, key, false, OpenMode::ObservedFaultVfs(observer))
}

/// Public, nonzero identifier for one disposable fault case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaseId([u8; 16]);

impl CaseId {
    /// Accepts one nonzero controller-generated case identifier.
    pub fn new(bytes: [u8; 16]) -> Result<Self, FaultProtocolError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(FaultProtocolError::Rejected);
        }
        Ok(Self(bytes))
    }

    /// Returns the public case identifier bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Closed L2 scenario carried by every control frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scenario {
    /// Inviter membership and pending-Welcome transaction.
    InviterTransaction,
    /// Joiner group and one-time KeyPackage transaction.
    JoinerTransaction,
}

impl Scenario {
    const fn code(self) -> u8 {
        match self {
            Self::InviterTransaction => 1,
            Self::JoinerTransaction => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, FaultProtocolError> {
        match code {
            1 => Ok(Self::InviterTransaction),
            2 => Ok(Self::JoinerTransaction),
            _ => Err(FaultProtocolError::Rejected),
        }
    }
}

/// Closed sender role carried by one frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Killable storage writer emitting a checkpoint.
    Writer,
    /// Parent controller acknowledging the exact checkpoint.
    Controller,
}

impl Role {
    const fn code(self) -> u8 {
        match self {
            Self::Writer => 1,
            Self::Controller => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, FaultProtocolError> {
        match code {
            1 => Ok(Self::Writer),
            2 => Ok(Self::Controller),
            _ => Err(FaultProtocolError::Rejected),
        }
    }
}

/// Closed control-frame kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameKind {
    /// Writer reached one exact statement boundary.
    Checkpoint,
    /// Controller accepted and echoed that exact boundary.
    Acknowledgement,
}

impl FrameKind {
    const fn code(self) -> u8 {
        match self {
            Self::Checkpoint => 1,
            Self::Acknowledgement => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, FaultProtocolError> {
        match code {
            1 => Ok(Self::Checkpoint),
            2 => Ok(Self::Acknowledgement),
            _ => Err(FaultProtocolError::Rejected),
        }
    }
}

/// Closed application checkpoint set frozen at Checkpoint A.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Checkpoint {
    /// Inviter baseline is closed, before `BEGIN IMMEDIATE`.
    InviterBeforeBegin,
    /// Inviter group upsert completed inside the open transaction.
    InviterAfterGroupUpsert,
    /// One bounded inviter epoch insert completed.
    InviterAfterEpochInsert,
    /// One bounded inviter epoch update completed.
    InviterAfterEpochUpdate,
    /// Inviter join/pending-Welcome row insert completed.
    InviterAfterJoinInsert,
    /// Inviter reservation became consumed inside the transaction.
    InviterAfterReservationConsumed,
    /// Every inviter statement completed, before SQL commit.
    InviterBeforeCommit,
    /// Inviter SQL commit returned.
    InviterAfterCommitReturn,
    /// Composition is about to finalize the in-memory admission shadow.
    InviterBeforeShadowFinalize,
    /// Joiner baseline is closed, before `BEGIN IMMEDIATE`.
    JoinerBeforeBegin,
    /// Joiner group upsert completed inside the open transaction.
    JoinerAfterGroupUpsert,
    /// One bounded joiner epoch insert completed.
    JoinerAfterEpochInsert,
    /// One bounded joiner epoch update completed.
    JoinerAfterEpochUpdate,
    /// Joiner transaction row insert completed.
    JoinerAfterCommitInsert,
    /// Joiner transaction remains open before exact KeyPackage deletion.
    JoinerBeforeKeyPackageDelete,
    /// Exact one-time KeyPackage deletion completed in the transaction.
    JoinerAfterKeyPackageDelete,
    /// Every joiner statement completed, before SQL commit.
    JoinerBeforeCommit,
    /// Joiner SQL commit returned.
    JoinerAfterCommitReturn,
}

impl Checkpoint {
    /// Returns the only scenario in which this checkpoint is valid.
    pub const fn scenario(self) -> Scenario {
        match self {
            Self::InviterBeforeBegin
            | Self::InviterAfterGroupUpsert
            | Self::InviterAfterEpochInsert
            | Self::InviterAfterEpochUpdate
            | Self::InviterAfterJoinInsert
            | Self::InviterAfterReservationConsumed
            | Self::InviterBeforeCommit
            | Self::InviterAfterCommitReturn
            | Self::InviterBeforeShadowFinalize => Scenario::InviterTransaction,
            Self::JoinerBeforeBegin
            | Self::JoinerAfterGroupUpsert
            | Self::JoinerAfterEpochInsert
            | Self::JoinerAfterEpochUpdate
            | Self::JoinerAfterCommitInsert
            | Self::JoinerBeforeKeyPackageDelete
            | Self::JoinerAfterKeyPackageDelete
            | Self::JoinerBeforeCommit
            | Self::JoinerAfterCommitReturn => Scenario::JoinerTransaction,
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::InviterBeforeBegin => 1,
            Self::InviterAfterGroupUpsert => 2,
            Self::InviterAfterEpochInsert => 3,
            Self::InviterAfterEpochUpdate => 4,
            Self::InviterAfterJoinInsert => 5,
            Self::InviterAfterReservationConsumed => 6,
            Self::InviterBeforeCommit => 7,
            Self::InviterAfterCommitReturn => 8,
            Self::InviterBeforeShadowFinalize => 9,
            Self::JoinerBeforeBegin => 16,
            Self::JoinerAfterGroupUpsert => 17,
            Self::JoinerAfterEpochInsert => 18,
            Self::JoinerAfterEpochUpdate => 19,
            Self::JoinerAfterCommitInsert => 20,
            Self::JoinerBeforeKeyPackageDelete => 21,
            Self::JoinerAfterKeyPackageDelete => 22,
            Self::JoinerBeforeCommit => 23,
            Self::JoinerAfterCommitReturn => 24,
        }
    }

    fn from_code(code: u8) -> Result<Self, FaultProtocolError> {
        match code {
            1 => Ok(Self::InviterBeforeBegin),
            2 => Ok(Self::InviterAfterGroupUpsert),
            3 => Ok(Self::InviterAfterEpochInsert),
            4 => Ok(Self::InviterAfterEpochUpdate),
            5 => Ok(Self::InviterAfterJoinInsert),
            6 => Ok(Self::InviterAfterReservationConsumed),
            7 => Ok(Self::InviterBeforeCommit),
            8 => Ok(Self::InviterAfterCommitReturn),
            9 => Ok(Self::InviterBeforeShadowFinalize),
            16 => Ok(Self::JoinerBeforeBegin),
            17 => Ok(Self::JoinerAfterGroupUpsert),
            18 => Ok(Self::JoinerAfterEpochInsert),
            19 => Ok(Self::JoinerAfterEpochUpdate),
            20 => Ok(Self::JoinerAfterCommitInsert),
            21 => Ok(Self::JoinerBeforeKeyPackageDelete),
            22 => Ok(Self::JoinerAfterKeyPackageDelete),
            23 => Ok(Self::JoinerBeforeCommit),
            24 => Ok(Self::JoinerAfterCommitReturn),
            _ => Err(FaultProtocolError::Rejected),
        }
    }

    const fn accepts_occurrence(self) -> bool {
        matches!(
            self,
            Self::InviterAfterEpochInsert
                | Self::InviterAfterEpochUpdate
                | Self::JoinerAfterEpochInsert
                | Self::JoinerAfterEpochUpdate
        )
    }

    fn validate_occurrence(self, occurrence: u8) -> Result<(), FaultProtocolError> {
        if (self.accepts_occurrence() && occurrence < MAX_OCCURRENCE)
            || (!self.accepts_occurrence() && occurrence == 0)
        {
            Ok(())
        } else {
            Err(FaultProtocolError::Rejected)
        }
    }
}

/// Secret-free complete-state oracle code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleState {
    /// Exact inviter old state (`I0`).
    InviterOld,
    /// Exact inviter new state (`I1`).
    InviterNew,
    /// Exact joiner old state (`J0`).
    JoinerOld,
    /// Exact joiner new state (`J1`).
    JoinerNew,
}

impl OracleState {
    /// Returns the scenario that owns this state code.
    pub const fn scenario(self) -> Scenario {
        match self {
            Self::InviterOld | Self::InviterNew => Scenario::InviterTransaction,
            Self::JoinerOld | Self::JoinerNew => Scenario::JoinerTransaction,
        }
    }

    /// Returns the stable protocol code.
    pub const fn code(self) -> u8 {
        match self {
            Self::InviterOld => 1,
            Self::InviterNew => 2,
            Self::JoinerOld => 3,
            Self::JoinerNew => 4,
        }
    }
}

impl TryFrom<u8> for OracleState {
    type Error = FaultProtocolError;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            1 => Ok(Self::InviterOld),
            2 => Ok(Self::InviterNew),
            3 => Ok(Self::JoinerOld),
            4 => Ok(Self::JoinerNew),
            _ => Err(FaultProtocolError::Rejected),
        }
    }
}

/// One canonical, fixed-size, secret-free barrier frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlFrame {
    kind: FrameKind,
    scenario: Scenario,
    role: Role,
    checkpoint: Checkpoint,
    occurrence: u8,
    case_id: CaseId,
}

impl ControlFrame {
    /// Creates one writer checkpoint after validating its occurrence.
    pub fn new_checkpoint(
        case_id: CaseId,
        checkpoint: Checkpoint,
        occurrence: u8,
    ) -> Result<Self, FaultProtocolError> {
        checkpoint.validate_occurrence(occurrence)?;
        Ok(Self {
            kind: FrameKind::Checkpoint,
            scenario: checkpoint.scenario(),
            role: Role::Writer,
            checkpoint,
            occurrence,
            case_id,
        })
    }

    /// Returns the controller acknowledgement for this exact frame.
    pub fn acknowledgement(self) -> Self {
        Self {
            kind: FrameKind::Acknowledgement,
            role: Role::Controller,
            ..self
        }
    }

    /// Encodes the exact canonical fixed-array representation.
    pub fn encode(self) -> [u8; CONTROL_FRAME_BYTES] {
        let mut encoded = [0_u8; CONTROL_FRAME_BYTES];
        encoded[..8].copy_from_slice(&MAGIC);
        encoded[8] = PROTOCOL_VERSION;
        encoded[9] = self.kind.code();
        encoded[10] = self.scenario.code();
        encoded[11] = self.role.code();
        encoded[12] = self.checkpoint.code();
        encoded[13] = self.occurrence;
        encoded[14..].copy_from_slice(self.case_id.as_bytes());
        encoded
    }

    /// Decodes one exact frame and rejects unknown, oversized, or inconsistent input.
    pub fn decode(encoded: &[u8]) -> Result<Self, FaultProtocolError> {
        if encoded.len() != CONTROL_FRAME_BYTES
            || encoded[..8] != MAGIC
            || encoded[8] != PROTOCOL_VERSION
        {
            return Err(FaultProtocolError::Rejected);
        }
        let kind = FrameKind::from_code(encoded[9])?;
        let scenario = Scenario::from_code(encoded[10])?;
        let role = Role::from_code(encoded[11])?;
        let checkpoint = Checkpoint::from_code(encoded[12])?;
        let occurrence = encoded[13];
        let case_id = CaseId::new(
            encoded[14..]
                .try_into()
                .map_err(|_| FaultProtocolError::Rejected)?,
        )?;
        checkpoint.validate_occurrence(occurrence)?;
        if checkpoint.scenario() != scenario
            || !matches!(
                (kind, role),
                (FrameKind::Checkpoint, Role::Writer)
                    | (FrameKind::Acknowledgement, Role::Controller)
            )
        {
            return Err(FaultProtocolError::Rejected);
        }
        Ok(Self {
            kind,
            scenario,
            role,
            checkpoint,
            occurrence,
            case_id,
        })
    }

    /// Returns the frame kind.
    pub const fn kind(self) -> FrameKind {
        self.kind
    }

    /// Returns the frame scenario.
    pub const fn scenario(self) -> Scenario {
        self.scenario
    }

    /// Returns the sender role.
    pub const fn role(self) -> Role {
        self.role
    }

    /// Returns the closed checkpoint.
    pub const fn checkpoint(self) -> Checkpoint {
        self.checkpoint
    }

    /// Returns the bounded occurrence index.
    pub const fn occurrence(self) -> u8 {
        self.occurrence
    }

    /// Returns the public case identifier.
    pub const fn case_id(self) -> CaseId {
        self.case_id
    }
}

/// Coarse failure returned by a barrier transport.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BarrierFailure {
    /// The frame exchange was rejected or could not complete.
    #[error("fault barrier rejected")]
    Rejected,
}

/// Bounded exchange implemented by the later supervised process controller.
pub trait BarrierTransport: Send + Sync {
    /// Flushes one exact checkpoint and returns one exact acknowledgement.
    fn exchange(
        &self,
        encoded: [u8; CONTROL_FRAME_BYTES],
    ) -> Result<[u8; CONTROL_FRAME_BYTES], BarrierFailure>;
}

/// Coarse protocol failure containing no caller-supplied diagnostic text.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FaultProtocolError {
    /// The frame, sequence, or acknowledgement was rejected.
    #[error("fault protocol rejected")]
    Rejected,
}

/// Shared observer that rejects duplicate or out-of-order checkpoints.
#[derive(Clone)]
pub struct FaultObserver {
    inner: Arc<ObserverInner>,
}

struct ObserverInner {
    case_id: CaseId,
    scenario: Scenario,
    transport: Arc<dyn BarrierTransport>,
    sequence: Mutex<Sequence>,
}

impl FaultObserver {
    /// Creates one observer bound to an exact case and scenario.
    pub fn new(case_id: CaseId, scenario: Scenario, transport: Arc<dyn BarrierTransport>) -> Self {
        Self {
            inner: Arc::new(ObserverInner {
                case_id,
                scenario,
                transport,
                sequence: Mutex::new(Sequence::new(scenario)),
            }),
        }
    }

    /// Exchanges one checkpoint only after its exact sequence is accepted.
    pub fn checkpoint(
        &self,
        checkpoint: Checkpoint,
        occurrence: u8,
    ) -> Result<(), FaultProtocolError> {
        let frame = ControlFrame::new_checkpoint(self.inner.case_id, checkpoint, occurrence)?;
        if frame.scenario() != self.inner.scenario {
            return Err(FaultProtocolError::Rejected);
        }
        self.inner
            .sequence
            .lock()
            .map_err(|_| FaultProtocolError::Rejected)?
            .accept(checkpoint, occurrence)?;
        let acknowledgement = self
            .inner
            .transport
            .exchange(frame.encode())
            .map_err(|_| FaultProtocolError::Rejected)?;
        if ControlFrame::decode(&acknowledgement)? != frame.acknowledgement() {
            return Err(FaultProtocolError::Rejected);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum EpochPhase {
    Inserts,
    Updates,
}

struct Sequence {
    scenario: Scenario,
    phase: u8,
    epoch_phase: EpochPhase,
    next_insert: u8,
    next_update: u8,
}

impl Sequence {
    const fn new(scenario: Scenario) -> Self {
        Self {
            scenario,
            phase: 0,
            epoch_phase: EpochPhase::Inserts,
            next_insert: 0,
            next_update: 0,
        }
    }

    fn accept(&mut self, checkpoint: Checkpoint, occurrence: u8) -> Result<(), FaultProtocolError> {
        if checkpoint.scenario() != self.scenario {
            return Err(FaultProtocolError::Rejected);
        }
        match self.scenario {
            Scenario::InviterTransaction => self.accept_inviter(checkpoint, occurrence),
            Scenario::JoinerTransaction => self.accept_joiner(checkpoint, occurrence),
        }
    }

    fn accept_inviter(
        &mut self,
        checkpoint: Checkpoint,
        occurrence: u8,
    ) -> Result<(), FaultProtocolError> {
        match (self.phase, checkpoint) {
            (0, Checkpoint::InviterBeforeBegin) => self.phase = 1,
            (1, Checkpoint::InviterAfterGroupUpsert) => self.phase = 2,
            (2, Checkpoint::InviterAfterEpochInsert)
                if matches!(self.epoch_phase, EpochPhase::Inserts)
                    && occurrence == self.next_insert =>
            {
                self.next_insert += 1;
            }
            (2, Checkpoint::InviterAfterEpochUpdate) if occurrence == self.next_update => {
                self.epoch_phase = EpochPhase::Updates;
                self.next_update += 1;
            }
            (2, Checkpoint::InviterAfterJoinInsert) => self.phase = 3,
            (3, Checkpoint::InviterAfterReservationConsumed) => self.phase = 4,
            (4, Checkpoint::InviterBeforeCommit) => self.phase = 5,
            (5, Checkpoint::InviterAfterCommitReturn) => self.phase = 6,
            (6, Checkpoint::InviterBeforeShadowFinalize) => self.phase = 7,
            _ => return Err(FaultProtocolError::Rejected),
        }
        Ok(())
    }

    fn accept_joiner(
        &mut self,
        checkpoint: Checkpoint,
        occurrence: u8,
    ) -> Result<(), FaultProtocolError> {
        match (self.phase, checkpoint) {
            (0, Checkpoint::JoinerBeforeBegin) => self.phase = 1,
            (1, Checkpoint::JoinerAfterGroupUpsert) => self.phase = 2,
            (2, Checkpoint::JoinerAfterEpochInsert)
                if matches!(self.epoch_phase, EpochPhase::Inserts)
                    && occurrence == self.next_insert =>
            {
                self.next_insert += 1;
            }
            (2, Checkpoint::JoinerAfterEpochUpdate) if occurrence == self.next_update => {
                self.epoch_phase = EpochPhase::Updates;
                self.next_update += 1;
            }
            (2, Checkpoint::JoinerAfterCommitInsert) => self.phase = 3,
            (3, Checkpoint::JoinerBeforeKeyPackageDelete) => self.phase = 4,
            (4, Checkpoint::JoinerAfterKeyPackageDelete) => self.phase = 5,
            (5, Checkpoint::JoinerBeforeCommit) => self.phase = 6,
            (6, Checkpoint::JoinerAfterCommitReturn) => self.phase = 7,
            _ => return Err(FaultProtocolError::Rejected),
        }
        Ok(())
    }
}
