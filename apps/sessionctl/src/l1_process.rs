//! Bounded independent-process conformance runner.
//!
//! This module is a test topology, not a network transport or production
//! credential-custody design. Its relay receives only canonical public wire
//! objects and the one deposit authority it exercises. The bearer invitation
//! and encrypted-owner key state remain on distinct direct/private channels.

use std::time::Duration;

use session_crypto_mls::SESSION_GROUP_ID_BYTES;
use session_protocol::MAX_WIRE_OBJECT_BYTES;
use transport_iroh::MAX_FAST_FRAME_BYTES;

const IPC_MAGIC: &[u8; 8] = b"SCL1IPC1";
const IPC_VERSION: u8 = 1;
const IPC_HEADER_BYTES: usize = 12;
const IPC_LENGTH_BYTES: usize = 4;
const MAX_IPC_PARTS: usize = 2;
const MAX_IPC_FRAME_BYTES: usize =
    IPC_HEADER_BYTES + (MAX_IPC_PARTS * IPC_LENGTH_BYTES) + (2 * MAX_WIRE_OBJECT_BYTES);
const FRAME_WAIT: Duration = Duration::from_secs(30);
const CHILD_WAIT: Duration = Duration::from_secs(90);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_CHILD_OUTPUT_BYTES: usize = 512;
const PRIVATE_STATE_MAGIC: &[u8; 8] = b"SCL1STAT";
const PRIVATE_STATE_BYTES: usize = 8 + 32 + SESSION_GROUP_ID_BYTES;
const ROOT_MARKER: &[u8] = b"sessionctl-l1-v1\n";
const MAX_EVIDENCE_BYTES: usize = 2_048;
const EXPECTED_FRAMES: u8 = 7;
const MAX_LOCKFILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOOLCHAIN_BYTES: usize = 4_096;
const MAX_GIT_PATH_BYTES: usize = 4_096;
const MAX_GIT_REF_BYTES: usize = 512;
const TWO_TERMINAL_DONE: &[u8] = b"sessionctl-two-terminal-complete-v1\n";
const CAPABILITY_HANDOFF_DISCLOSURE: &str = "invitation_handling=authenticated-confidential-only\napproval=simulated-automatic\nrecipient_identity=not-verified\n";
const NETWORK_OPERATION_WAIT: Duration = Duration::from_secs(30);
const OPERATOR_HANDOFF_WAIT: Duration = Duration::from_secs(5 * 60);

const _: () = assert!(MAX_IPC_FRAME_BYTES <= MAX_FAST_FRAME_BYTES);

mod controller;
mod hostile;
mod ipc;
mod model;
mod network;
mod resources;
mod roles;
#[cfg(test)]
mod tests;

pub use controller::{
    run_l1_process_demo, run_l1_process_internal_role, run_two_terminal_host, run_two_terminal_join,
};
pub use model::L1ProcessReport;
pub use network::{run_network_host, run_network_join, run_network_loopback_demo};
pub use resources::resolve_l1_process_git_commit;
