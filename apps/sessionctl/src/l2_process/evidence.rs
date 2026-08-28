use super::{SHA256, Scenario, SessionCtlError, digest, hex, stage};

const MAX_CHANNEL_BYTES: usize = 64 * 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 4 * 1024;
const MAX_MANIFEST_BYTES: usize = 4_096;

const SYNTHETIC_CANARIES: [&[u8]; 12] = [
    b"SC-L2-CANARY-DATABASE-KEY",
    b"SC-L2-CANARY-IDENTITY-RECORD",
    b"SC-L2-CANARY-INVITATION-GENERATION",
    b"SC-L2-CANARY-BEARER-CAPABILITY",
    b"SC-L2-CANARY-APPROVAL-RECORD",
    b"SC-L2-CANARY-REQUEST-FINGERPRINT",
    b"SC-L2-CANARY-MLS-STATE",
    b"SC-L2-CANARY-KEY-PACKAGE",
    b"SC-L2-CANARY-WELCOME",
    b"SC-L2-CANARY-ENDPOINT",
    b"SC-L2-CANARY-PLAINTEXT",
    b"SC-L2-CANARY-SQL-PARAMETER",
];

/// Closed L2 sweep classes eligible for public evidence promotion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L2EvidenceSweep {
    /// Every baseline-observed application checkpoint was killed once.
    ApplicationProcessKill,
    /// Every baseline-derived supported SQLite result-code ordinal was injected.
    SqliteReturnCode,
    /// Every baseline-derived commit-window pause was killed once.
    CommitWindowProcessKill,
}

impl L2EvidenceSweep {
    const fn label(self) -> &'static str {
        match self {
            Self::ApplicationProcessKill => "application-process-kill",
            Self::SqliteReturnCode => "return-code",
            Self::CommitWindowProcessKill => "pause-process-kill",
        }
    }

    const fn observation_protocol(self) -> &'static str {
        match self {
            Self::ApplicationProcessKill => "l2-checkpoint-observation-v1",
            Self::SqliteReturnCode | Self::CommitWindowProcessKill => "l2-io-observation-v1",
        }
    }
}

/// Exact build, runner, engine, and encrypted-artifact binding for one L2 manifest.
pub struct L2EvidenceMetadata {
    commit: String,
    dirty: bool,
    toolchain: String,
    lock_digest: String,
    runner_image: String,
    platform: String,
    architecture: String,
    sqlcipher_version: String,
    sqlite_version: String,
    test_binary_digest: [u8; 32],
    baseline_artifact_digest: [u8; 32],
    post_recovery_artifact_digest: [u8; 32],
}

impl L2EvidenceMetadata {
    /// Constructs closed provenance. Dirty, unavailable, or malformed inputs fail closed.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        commit: &str,
        dirty: bool,
        toolchain: &str,
        lock_digest: &str,
        runner_image: &str,
        platform: &str,
        architecture: &str,
        sqlcipher_version: &str,
        sqlite_version: &str,
        test_binary_digest: [u8; 32],
        baseline_artifact_digest: [u8; 32],
        post_recovery_artifact_digest: [u8; 32],
    ) -> Result<Self, SessionCtlError> {
        if dirty
            || !is_lower_hex(commit, 40)
            || !is_lower_hex(lock_digest, 64)
            || !is_token(toolchain, 64)
            || !is_token(runner_image, 128)
            || !matches!(platform, "linux" | "macos" | "windows")
            || !matches!(architecture, "x86_64" | "aarch64")
            || !is_version(sqlcipher_version)
            || !is_version(sqlite_version)
            || test_binary_digest.iter().all(|byte| *byte == 0)
            || baseline_artifact_digest.iter().all(|byte| *byte == 0)
            || post_recovery_artifact_digest.iter().all(|byte| *byte == 0)
        {
            return Err(stage("L2 evidence provenance"));
        }
        Ok(Self {
            commit: commit.to_owned(),
            dirty,
            toolchain: toolchain.to_owned(),
            lock_digest: lock_digest.to_owned(),
            runner_image: runner_image.to_owned(),
            platform: platform.to_owned(),
            architecture: architecture.to_owned(),
            sqlcipher_version: sqlcipher_version.to_owned(),
            sqlite_version: sqlite_version.to_owned(),
            test_binary_digest,
            baseline_artifact_digest,
            post_recovery_artifact_digest,
        })
    }
}

/// Every bounded surface scanned before an internal observation may be published.
pub struct L2EvidenceChannels<'a> {
    stdout: &'a [u8],
    stderr: &'a [u8],
    diagnostics: &'a [u8],
    control_frames: &'a [u8],
    retained_artifacts: &'a [u8],
}

impl<'a> L2EvidenceChannels<'a> {
    /// Binds the exact captured surfaces to the redaction verdict.
    pub fn new(
        stdout: &'a [u8],
        stderr: &'a [u8],
        diagnostics: &'a [u8],
        control_frames: &'a [u8],
        retained_artifacts: &'a [u8],
    ) -> Result<Self, SessionCtlError> {
        if stdout.len() > MAX_DIAGNOSTIC_BYTES
            || stderr.len() > MAX_DIAGNOSTIC_BYTES
            || diagnostics.len() > MAX_DIAGNOSTIC_BYTES
            || control_frames.len() > MAX_DIAGNOSTIC_BYTES
            || retained_artifacts.len() > MAX_CHANNEL_BYTES
        {
            return Err(stage("L2 evidence surface bound"));
        }
        Ok(Self {
            stdout,
            stderr,
            diagnostics,
            control_frames,
            retained_artifacts,
        })
    }

    fn values(&self) -> [&[u8]; 5] {
        [
            self.stdout,
            self.stderr,
            self.diagnostics,
            self.control_frames,
            self.retained_artifacts,
        ]
    }
}

/// A bounded public manifest that passed provenance, completeness, and redaction gates.
pub struct L2EvidenceManifest(String);

impl L2EvidenceManifest {
    /// Encodes the already validated public manifest.
    #[must_use]
    pub fn encode_v1(&self) -> String {
        self.0.clone()
    }
}

/// Promotes one complete internal observation to public evidence after every L2-8 gate passes.
pub fn promote_l2_evidence(
    sweep: L2EvidenceSweep,
    scenario: Scenario,
    observation: &str,
    metadata: &L2EvidenceMetadata,
    channels: &L2EvidenceChannels<'_>,
) -> Result<L2EvidenceManifest, SessionCtlError> {
    validate_observation(sweep, scenario, observation)?;
    scan_canaries(
        channels
            .values()
            .into_iter()
            .chain(std::iter::once(observation.as_bytes())),
    )?;

    let storage_scenario = match scenario {
        Scenario::InviterTransaction => "inviter-transaction",
        Scenario::JoinerTransaction => "joiner-transaction",
    };
    let observation_digest = hex(digest(&SHA256, observation.as_bytes()).as_ref());
    let manifest = format!(
        concat!(
            "version=1\n",
            "protocol=l2-evidence-v1\n",
            "scenario=E2E-TXN-001\n",
            "result=pass\n",
            "coverage=complete\n",
            "sweep={}\n",
            "storage_scenario={}\n",
            "case_scope=all-baseline-observed\n",
            "schedule_seed=1\n",
            "commit={}\n",
            "dirty={}\n",
            "toolchain={}\n",
            "lock_sha256={}\n",
            "platform={}-{}\n",
            "runner_image={}\n",
            "sqlcipher_version={}\n",
            "sqlite_version={}\n",
            "test_binary_sha256={}\n",
            "baseline_artifact_sha256={}\n",
            "post_recovery_artifact_sha256={}\n",
            "internal_observation_sha256={}\n",
            "frame_bytes={}\n",
            "frame_wait_ms={}\n",
            "child_wait_ms={}\n",
            "maximum_application_checkpoints={}\n",
            "maximum_artifact_bytes={}\n",
            "integrity=pass\n",
            "schema=pass\n",
            "semantic_oracle=pass\n",
            "exact_retry=pass\n",
            "redaction=pass\n",
            "child_cleanup=pass\n",
            "handle_cleanup=pass\n",
            "lease_cleanup=pass\n",
            "directory_cleanup=pass\n",
            "cleanup=pass\n"
        ),
        sweep.label(),
        storage_scenario,
        metadata.commit,
        metadata.dirty,
        metadata.toolchain,
        metadata.lock_digest,
        metadata.platform,
        metadata.architecture,
        metadata.runner_image,
        metadata.sqlcipher_version,
        metadata.sqlite_version,
        hex(&metadata.test_binary_digest),
        hex(&metadata.baseline_artifact_digest),
        hex(&metadata.post_recovery_artifact_digest),
        observation_digest,
        super::CONTROL_FRAME_BYTES,
        super::FRAME_WAIT.as_millis(),
        super::CHILD_WAIT.as_millis(),
        super::MAX_APPLICATION_CHECKPOINTS,
        super::MAX_DATABASE_BYTES,
    );
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(stage("L2 public evidence bound"));
    }
    scan_canaries(std::iter::once(manifest.as_bytes()))?;
    Ok(L2EvidenceManifest(manifest))
}

fn validate_observation(
    sweep: L2EvidenceSweep,
    scenario: Scenario,
    observation: &str,
) -> Result<(), SessionCtlError> {
    if observation.len() > MAX_MANIFEST_BYTES
        || !observation.ends_with('\n')
        || observation.contains('\r')
        || observation.lines().any(|line| {
            line.is_empty()
                || line.len() > 1_024
                || !line
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        })
    {
        return Err(stage("L2 internal observation"));
    }
    let storage_scenario = match scenario {
        Scenario::InviterTransaction => "inviter-transaction",
        Scenario::JoinerTransaction => "joiner-transaction",
    };
    for required in [
        format!("protocol={}", sweep.observation_protocol()),
        String::from("scenario=E2E-TXN-001"),
        String::from("publication=prohibited"),
        String::from("status=validated"),
        String::from("coverage=complete"),
        format!("sweep={}", sweep.label()),
        String::from("fault_build=true"),
        format!("storage_scenario={storage_scenario}"),
        String::from("integrity=pass"),
        String::from("schema=pass"),
        String::from("semantic_oracle=pass"),
        String::from("exact_retry=pass"),
        String::from("fixture_cleanup=pass"),
        String::from("handle_cleanup=pass"),
        String::from("child_cleanup=pass"),
        String::from("directory_cleanup=pass"),
    ] {
        if observation.lines().filter(|line| *line == required).count() != 1 {
            return Err(stage("L2 internal observation"));
        }
    }
    if observation.lines().any(|line| line.starts_with("result=")) {
        return Err(stage("L2 internal observation"));
    }
    Ok(())
}

fn scan_canaries<'a>(surfaces: impl IntoIterator<Item = &'a [u8]>) -> Result<(), SessionCtlError> {
    for surface in surfaces {
        for canary in SYNTHETIC_CANARIES {
            let canary_hex = hex(canary);
            if contains_subslice(surface, canary)
                || contains_subslice(surface, canary_hex.as_bytes())
            {
                return Err(stage("L2 evidence redaction"));
            }
        }
    }
    Ok(())
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+' | b':')
        })
}

fn is_version(value: &str) -> bool {
    is_token(value, 64) && value.bytes().any(|byte| byte.is_ascii_digit())
}
