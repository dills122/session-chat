//! L1 evidence report and private client state.

use super::super::StageResult;
use super::super::{SessionCtlError, stage};
use super::{
    CHILD_WAIT, FRAME_WAIT, MAX_EVIDENCE_BYTES, MAX_IPC_FRAME_BYTES, PRIVATE_STATE_BYTES,
    PRIVATE_STATE_MAGIC,
};
use session_crypto_mls::SessionGroupId;
use std::io::{Read, Write};
use zeroize::Zeroizing;
/// Secret-free outcome of the bounded independent-process scenario.
#[derive(Clone, Eq, PartialEq)]
pub struct L1ProcessReport {
    pub(super) started_at: u64,
    pub(super) completed_at: u64,
    pub(super) commit: String,
    pub(super) dirty: bool,
    pub(super) toolchain: String,
    pub(super) lock_digest: String,
}

impl L1ProcessReport {
    /// Encodes the retained versioned evidence manifest.
    #[must_use]
    pub fn encode_v1(&self) -> String {
        let evidence = format!(
            concat!(
                "version=1\n",
                "scenario=E2E-JOIN-001\n",
                "topology=two-clients-one-untrusted-service\n",
                "result=pass\n",
                "schedule_seed=1\n",
                "ipc=sessionctl-l1-ipc-v1\n",
                "wire_objects=protected-join,local-welcome-endpoint,opaque-envelope\n",
                "alice_restart=close-reopen-independent-process\n",
                "platform={}-{}\n",
                "commit={}\n",
                "dirty={}\n",
                "toolchain={}\n",
                "lock_sha256={}\n",
                "command=sessionctl-l1\n",
                "started_at={}\n",
                "completed_at={}\n",
                "frame_budget_bytes={}\n",
                "frame_wait_seconds={}\n",
                "child_wait_seconds={}\n",
                "service_forwarded=7\n",
                "admission=approved\n",
                "welcome=delivered\n",
                "joined_epoch=1\n",
                "messages=2\n",
                "updated_epoch=2\n",
                "removal=enforced\n",
                "post_removal=rejected\n",
                "artifact_hashes=omitted-authority-bearing\n",
                "redaction=pass\n",
                "child_cleanup=pass\n",
                "directory_cleanup=pass\n"
            ),
            std::env::consts::OS,
            std::env::consts::ARCH,
            self.commit,
            if self.dirty { "true" } else { "false" },
            self.toolchain,
            self.lock_digest,
            self.started_at,
            self.completed_at,
            MAX_IPC_FRAME_BYTES,
            FRAME_WAIT.as_secs(),
            CHILD_WAIT.as_secs(),
        );
        debug_assert!(evidence.len() <= MAX_EVIDENCE_BYTES);
        evidence
    }
}
// This value is never persisted or formatted. Only an Alice child receives the
// inherited anonymous pipe; same-process compositions move it directly.
pub(super) struct PrivateState {
    pub(super) database_key: Zeroizing<[u8; 32]>,
    pub(super) group_id: SessionGroupId,
}

impl PrivateState {
    pub(super) fn write_to(self, mut writer: impl Write) -> Result<(), SessionCtlError> {
        let mut state = Zeroizing::new(Vec::with_capacity(PRIVATE_STATE_BYTES));
        state.extend_from_slice(PRIVATE_STATE_MAGIC);
        state.extend_from_slice(self.database_key.as_ref());
        state.extend_from_slice(self.group_id.as_bytes());
        writer
            .write_all(&state)
            .at_stage("process private state write")
    }

    pub(super) fn read_from(mut reader: impl Read) -> Result<Self, SessionCtlError> {
        // Exact fixed frame plus EOF: no ignored suffix or file fallback. The
        // controller enforces the child lifetime if a writer fails to close.
        let mut encoded = Zeroizing::new([0_u8; PRIVATE_STATE_BYTES]);
        reader
            .read_exact(encoded.as_mut())
            .at_stage("process private state read")?;
        let mut trailing = [0_u8; 1];
        if reader
            .read(&mut trailing)
            .at_stage("process private state read")?
            != 0
            || &encoded[..8] != PRIVATE_STATE_MAGIC
        {
            return Err(stage("process private state"));
        }
        let database_key: Zeroizing<[u8; 32]> = Zeroizing::new(
            encoded[8..40]
                .try_into()
                .map_err(|_| stage("process private state"))?,
        );
        if database_key.iter().all(|byte| *byte == 0) {
            return Err(stage("process private state"));
        }
        let group_id = SessionGroupId::new(
            encoded[40..]
                .try_into()
                .map_err(|_| stage("process private state"))?,
        )
        .at_stage("process private state")?;
        Ok(Self {
            database_key,
            group_id,
        })
    }
}
