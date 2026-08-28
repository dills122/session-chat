//! Bounded named SQLite VFS fault adapter for Session Chat L2 tests.
//!
//! Registration never changes SQLite's process default. Only a connection that
//! explicitly requests [`VFS_NAME`] reaches the delegator. This publish-disabled
//! crate provides deterministic SQLite-visible fault evidence; it does not model
//! a truthful filesystem, power loss, or production durability.

#![deny(unsafe_code)]

mod controller;
#[allow(unsafe_code)]
mod native;

pub use controller::{
    Controller, ControllerError, FaultAction, FaultCode, FaultMode, FaultPlan, FaultTarget,
    FileRole, Operation, OperationDisposition, OperationRecord, PauseGate, Snapshot,
    ValidationError, controller,
};
pub use native::{
    DefaultVfsIdentity, RegistrationError, default_vfs_identity, register,
    validate_null_callback_boundaries, validate_optional_service_forwarding,
};

/// The one closed VFS name frozen by the L2-0 storage connection seam.
pub const VFS_NAME: &str = "session-chat-storage-fault-v1";

/// Maximum retained operations in one armed/reset observation interval.
pub const MAX_OPERATIONS: usize = 4_096;
