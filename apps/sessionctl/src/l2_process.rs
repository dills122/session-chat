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

use std::time::Duration;

use storage_sqlcipher::fault_testing::CONTROL_FRAME_BYTES;

mod controller;
mod database;
mod execution;
mod fixtures;
mod io_model;
mod model;
mod resources;
mod verifier;
mod writer;
pub use controller::{
    L2IoPauseKillCase, prepare_l2_io_pause_kill_case, run_l2_io_baseline, run_l2_io_fault_case,
    run_l2_io_pause_writer, run_l2_process_baseline, run_l2_process_case,
    run_l2_process_internal_role, run_l2_process_probe,
};
pub use io_model::{
    L2IoBaselineObservation, L2IoBaselineReport, L2IoDriverObservation, L2IoFaultDriver,
    L2IoFaultMode, L2IoFaultObservation, L2IoFaultReport, L2IoFileRole, L2IoOperation,
    L2IoPauseDriver, L2IoPauseKillReport, L2IoPauseObservation, L2IoPauseSweepReport,
    L2IoSweepReport, L2IoSweepTarget,
};
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
// Child exit stays prompt; drain already exited or reaped pipes under a separate bound.
const PIPE_DRAIN_WAIT: Duration = Duration::from_secs(10);
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
mod tests;
