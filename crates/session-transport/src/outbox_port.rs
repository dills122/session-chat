use thiserror::Error;
use zeroize::Zeroizing;

/// One exact owner-store lease and its secret-bearing LocalV1 delivery material.
///
/// This type intentionally implements neither diagnostics nor cloning. The
/// encoded endpoint contains deposit authority and is zeroized on every exit.
pub struct LeasedWelcome<L> {
    lease: L,
    welcome_envelope: Zeroizing<Vec<u8>>,
    deposit_endpoint: Zeroizing<Vec<u8>>,
    outbox_expires_at_unix_seconds: u64,
}

impl<L> LeasedWelcome<L> {
    /// Packages one lease issued by the authoritative owner store.
    #[must_use]
    pub fn from_owner(
        lease: L,
        welcome_envelope: Vec<u8>,
        deposit_endpoint: Vec<u8>,
        outbox_expires_at_unix_seconds: u64,
    ) -> Self {
        Self {
            lease,
            welcome_envelope: Zeroizing::new(welcome_envelope),
            deposit_endpoint: Zeroizing::new(deposit_endpoint),
            outbox_expires_at_unix_seconds,
        }
    }

    pub(crate) fn into_parts(self) -> (L, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, u64) {
        (
            self.lease,
            self.welcome_envelope,
            self.deposit_endpoint,
            self.outbox_expires_at_unix_seconds,
        )
    }
}

/// Stable, secret-free failures from the authoritative outbox owner.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum OutboxPortError {
    #[error("outbox owner temporarily unavailable")]
    Unavailable,
    #[error("outbox owner rejected a state transition")]
    Conflict,
    #[error("outbox owner failed")]
    Internal,
}

/// Sole-owner port consumed by the deposit-only coordinator.
///
/// Implementations own eligibility, attempt counts, leases, exact delivery
/// material, and terminal state. The coordinator owns no competing ledger.
pub trait WelcomeOutboxPort {
    /// Opaque authority required to report the result of one exact lease.
    type Lease;

    /// Leases the next exact eligible Welcome, or reports that no work exists.
    fn lease_next(
        &mut self,
        now_unix_seconds: u64,
        lease_seconds: u64,
    ) -> Result<Option<LeasedWelcome<Self::Lease>>, OutboxPortError>;

    /// Records adapter acceptance, not recipient receipt or processing.
    fn report_accepted(
        &mut self,
        lease: Self::Lease,
        now_unix_seconds: u64,
    ) -> Result<(), OutboxPortError>;

    /// Releases one failed exact lease according to owner-store retry policy.
    fn report_failed(&mut self, lease: Self::Lease) -> Result<(), OutboxPortError>;
}
