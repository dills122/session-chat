use std::{fs, path::Path, process::Command};

use super::{
    CHILD_WAIT, L2EvidenceCase, L2EvidenceCaseTarget, L2IoPauseSweepReport, L2IoSweepReport,
    L2ProcessSweepReport, ManagedChild, SHA256, Scenario, SessionCtlError, digest, git_dirty_at,
    hex, lock_digest_at, pinned_toolchain_at, repository_root, resolve_l1_process_git_commit,
    sanitize_environment, stage,
};

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
enum L2EvidenceSweep {
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
struct L2EvidenceMetadata {
    commit: String,
    dirty: bool,
    toolchain: String,
    rustc_release: String,
    rustc_commit: String,
    rustc_host: String,
    lock_digest: String,
    runner_image: String,
    platform: String,
    architecture: String,
    github_run_id: String,
    github_run_attempt: String,
    github_workflow_sha: String,
    github_workflow_ref: String,
    github_repository: String,
    github_event_name: String,
    runner_os: String,
    runner_arch: String,
    runner_environment: String,
    sqlcipher_version: String,
    sqlite_version: String,
    test_binary_digest: [u8; 32],
}

struct RustcProvenance {
    release: String,
    commit: String,
    host: String,
}

struct L2CiContext {
    runner_image: String,
    platform: String,
    architecture: String,
    github_run_id: String,
    github_run_attempt: String,
    github_workflow_sha: String,
    github_workflow_ref: String,
    github_repository: String,
    github_event_name: String,
    runner_os: String,
    runner_arch: String,
    runner_environment: String,
}

impl L2EvidenceMetadata {
    /// Constructs closed provenance. Dirty, unavailable, or malformed inputs fail closed.
    #[allow(clippy::too_many_arguments)]
    fn new(
        commit: &str,
        dirty: bool,
        toolchain: &str,
        rustc: RustcProvenance,
        lock_digest: &str,
        ci: L2CiContext,
        sqlcipher_version: &str,
        sqlite_version: &str,
        test_binary_digest: [u8; 32],
    ) -> Result<Self, SessionCtlError> {
        if dirty
            || !is_lower_hex(commit, 40)
            || !is_lower_hex(lock_digest, 64)
            || !is_token(toolchain, 64)
            || rustc.release != toolchain
            || !is_lower_hex(&rustc.commit, 40)
            || !is_token(&rustc.host, 128)
            || !is_lower_hex(&ci.github_workflow_sha, 40)
            || !is_version(sqlcipher_version)
            || !is_version(sqlite_version)
            || test_binary_digest.iter().all(|byte| *byte == 0)
        {
            return Err(stage("L2 evidence provenance"));
        }
        Ok(Self {
            commit: commit.to_owned(),
            dirty,
            toolchain: toolchain.to_owned(),
            rustc_release: rustc.release,
            rustc_commit: rustc.commit,
            rustc_host: rustc.host,
            lock_digest: lock_digest.to_owned(),
            runner_image: ci.runner_image,
            platform: ci.platform,
            architecture: ci.architecture,
            github_run_id: ci.github_run_id,
            github_run_attempt: ci.github_run_attempt,
            github_workflow_sha: ci.github_workflow_sha,
            github_workflow_ref: ci.github_workflow_ref,
            github_repository: ci.github_repository,
            github_event_name: ci.github_event_name,
            runner_os: ci.runner_os,
            runner_arch: ci.runner_arch,
            runner_environment: ci.runner_environment,
            sqlcipher_version: sqlcipher_version.to_owned(),
            sqlite_version: sqlite_version.to_owned(),
            test_binary_digest,
        })
    }

    fn collect(
        executable: &Path,
        runner_image: &str,
        cases: &[L2EvidenceCase],
    ) -> Result<Self, SessionCtlError> {
        let first = cases
            .first()
            .ok_or_else(|| stage("L2 evidence case index"))?;
        if cases.iter().any(|case| {
            case.binding.sqlcipher_version != first.binding.sqlcipher_version
                || case.binding.sqlite_version != first.binding.sqlite_version
                || !case.binding.redaction
        }) {
            return Err(stage("L2 evidence case index"));
        }
        let repository = repository_root();
        let executable_metadata =
            fs::metadata(executable).map_err(|_| stage("L2 evidence test binary"))?;
        if !executable.is_absolute()
            || !executable_metadata.is_file()
            || executable_metadata.len() == 0
            || executable_metadata.len() > 256 * 1024 * 1024
        {
            return Err(stage("L2 evidence test binary"));
        }
        let executable_bytes =
            fs::read(executable).map_err(|_| stage("L2 evidence test binary"))?;
        let test_binary_digest = digest(&SHA256, &executable_bytes)
            .as_ref()
            .try_into()
            .map_err(|_| stage("L2 evidence test binary"))?;
        let platform = match std::env::consts::OS {
            "linux" => "linux",
            "macos" => "macos",
            "windows" => "windows",
            _ => return Err(stage("L2 evidence platform")),
        };
        let architecture = std::env::consts::ARCH;
        let commit = resolve_l1_process_git_commit(&repository)
            .ok_or_else(|| stage("L2 evidence commit"))?;
        let toolchain =
            pinned_toolchain_at(&repository).ok_or_else(|| stage("L2 evidence toolchain"))?;
        let rustc = collect_rustc_provenance(&toolchain)?;
        let ci = validate_ci_context(&commit, platform, architecture, runner_image, |name| {
            std::env::var(name).ok()
        })?;
        Self::new(
            &commit,
            git_dirty_at(&repository).ok_or_else(|| stage("L2 evidence dirty state"))?,
            &toolchain,
            rustc,
            &lock_digest_at(&repository).ok_or_else(|| stage("L2 evidence lockfile"))?,
            ci,
            &first.binding.sqlcipher_version,
            &first.binding.sqlite_version,
            test_binary_digest,
        )
    }
}

fn collect_rustc_provenance(pinned_toolchain: &str) -> Result<RustcProvenance, SessionCtlError> {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let mut command = Command::new(rustc);
    command.arg("-Vv");
    sanitize_environment(&mut command);
    let mut child = ManagedChild::spawn_command(command)?;
    let status = child.wait(CHILD_WAIT)?;
    let stdout = child.stdout.collect(CHILD_WAIT)?;
    let stderr = child.stderr.collect(CHILD_WAIT)?;
    if !status.success() || !stderr.is_empty() || stdout.len() > 4_096 {
        return Err(stage("L2 evidence rustc provenance"));
    }
    parse_rustc_verbose(&stdout, pinned_toolchain)
}

fn parse_rustc_verbose(
    output: &[u8],
    pinned_toolchain: &str,
) -> Result<RustcProvenance, SessionCtlError> {
    let text = std::str::from_utf8(output).map_err(|_| stage("L2 evidence rustc provenance"))?;
    let field = |name: &str| {
        let prefix = format!("{name}: ");
        let mut matches = text.lines().filter_map(|line| line.strip_prefix(&prefix));
        let value = matches.next()?;
        matches.next().is_none().then_some(value)
    };
    let release = field("release").ok_or_else(|| stage("L2 evidence rustc provenance"))?;
    let commit = field("commit-hash").ok_or_else(|| stage("L2 evidence rustc provenance"))?;
    let host = field("host").ok_or_else(|| stage("L2 evidence rustc provenance"))?;
    if release != pinned_toolchain
        || !is_version(release)
        || !is_lower_hex(commit, 40)
        || !is_token(host, 128)
    {
        return Err(stage("L2 evidence rustc provenance"));
    }
    Ok(RustcProvenance {
        release: release.to_owned(),
        commit: commit.to_owned(),
        host: host.to_owned(),
    })
}

fn validate_ci_context(
    commit: &str,
    platform: &str,
    architecture: &str,
    runner_image: &str,
    mut value: impl FnMut(&str) -> Option<String>,
) -> Result<L2CiContext, SessionCtlError> {
    let required = |name: &str, value: &mut dyn FnMut(&str) -> Option<String>| {
        value(name).ok_or_else(|| stage("L2 evidence CI provenance"))
    };
    let github_actions = required("GITHUB_ACTIONS", &mut value)?;
    let github_sha = required("GITHUB_SHA", &mut value)?;
    let github_workflow_sha = required("GITHUB_WORKFLOW_SHA", &mut value)?;
    let github_run_id = required("GITHUB_RUN_ID", &mut value)?;
    let github_run_attempt = required("GITHUB_RUN_ATTEMPT", &mut value)?;
    let github_workflow_ref = required("GITHUB_WORKFLOW_REF", &mut value)?;
    let github_repository = required("GITHUB_REPOSITORY", &mut value)?;
    let github_event_name = required("GITHUB_EVENT_NAME", &mut value)?;
    let runner_os = required("RUNNER_OS", &mut value)?;
    let runner_arch = required("RUNNER_ARCH", &mut value)?;
    let runner_environment = required("RUNNER_ENVIRONMENT", &mut value)?;
    let tuple = match runner_image {
        "ubuntu-24.04" => ("linux", "x86_64", "Linux", "X64"),
        "macos-15" => ("macos", "aarch64", "macOS", "ARM64"),
        "windows-2025" => ("windows", "x86_64", "Windows", "X64"),
        _ => return Err(stage("L2 evidence CI provenance")),
    };
    if github_actions != "true"
        || github_sha != commit
        || !is_lower_hex(&github_workflow_sha, 40)
        || (
            platform,
            architecture,
            runner_os.as_str(),
            runner_arch.as_str(),
        ) != tuple
        || runner_environment != "github-hosted"
        || !is_decimal(&github_run_id, 32)
        || !is_decimal(&github_run_attempt, 8)
        || !is_safe_value(&github_workflow_ref, 256)
        || !github_workflow_ref.contains("/.github/workflows/ci.yml@")
        || !is_safe_value(&github_repository, 128)
        || !github_repository.contains('/')
        || !matches!(
            github_event_name.as_str(),
            "pull_request" | "push" | "schedule" | "workflow_dispatch"
        )
    {
        return Err(stage("L2 evidence CI provenance"));
    }
    Ok(L2CiContext {
        runner_image: runner_image.to_owned(),
        platform: platform.to_owned(),
        architecture: architecture.to_owned(),
        github_run_id,
        github_run_attempt,
        github_workflow_sha,
        github_workflow_ref,
        github_repository,
        github_event_name,
        runner_os,
        runner_arch,
        runner_environment,
    })
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

/// Complete bounded set of public case manifests from one validated L2 sweep.
pub struct L2EvidenceBundle(Vec<L2EvidenceManifest>);

impl L2EvidenceBundle {
    /// Iterates the exact canonical case records in their retained order.
    pub fn manifests(&self) -> impl ExactSizeIterator<Item = &L2EvidenceManifest> {
        self.0.iter()
    }
}

/// Promotes one complete internal observation to public evidence after every L2-8 gate passes.
fn promote_l2_evidence(
    sweep: L2EvidenceSweep,
    scenario: Scenario,
    observation: &str,
    metadata: &L2EvidenceMetadata,
    cases: &[L2EvidenceCase],
    channels: &L2EvidenceChannels<'_>,
) -> Result<L2EvidenceBundle, SessionCtlError> {
    validate_observation(sweep, scenario, observation)?;
    if cases.is_empty()
        || cases.len() > 4_096
        || cases.windows(2).any(|pair| pair[0].key >= pair[1].key)
    {
        return Err(stage("L2 evidence case index"));
    }
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
    let case_fields = cases.iter().map(case_fields).collect::<Vec<_>>();
    let mut matrix_index = Vec::new();
    for (case, fields) in cases.iter().zip(&case_fields) {
        append_index_value(&mut matrix_index, case.key.as_bytes())?;
        append_index_value(&mut matrix_index, fields.as_bytes())?;
        matrix_index.extend_from_slice(&case.binding.baseline_artifact_digest);
        matrix_index.extend_from_slice(&case.binding.post_recovery_artifact_digest);
    }
    let matrix_digest = hex(digest(&SHA256, &matrix_index).as_ref());
    let mut manifests = Vec::with_capacity(cases.len());
    for (case_index, (case, fields)) in cases.iter().zip(case_fields).enumerate() {
        let manifest = format!(
            concat!(
                "version=1\n",
                "protocol=l2-evidence-v1\n",
                "record=case\n",
                "scenario=E2E-TXN-001\n",
                "result=pass\n",
                "coverage=complete\n",
                "sweep={}\n",
                "storage_scenario={}\n",
                "case_index={}\n",
                "case_count={}\n",
                "schedule_seed=1\n",
                "{}",
                "commit={}\n",
                "dirty={}\n",
                "toolchain={}\n",
                "rustc_release={}\n",
                "rustc_commit={}\n",
                "rustc_host={}\n",
                "lock_sha256={}\n",
                "platform={}-{}\n",
                "runner_image={}\n",
                "github_run_id={}\n",
                "github_run_attempt={}\n",
                "github_workflow_sha={}\n",
                "github_workflow_ref={}\n",
                "github_repository={}\n",
                "github_event_name={}\n",
                "runner_os={}\n",
                "runner_arch={}\n",
                "runner_environment={}\n",
                "sqlcipher_version={}\n",
                "sqlite_version={}\n",
                "test_binary_sha256={}\n",
                "baseline_artifact_sha256={}\n",
                "post_recovery_artifact_sha256={}\n",
                "matrix_sha256={}\n",
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
            case_index,
            cases.len(),
            fields,
            metadata.commit,
            metadata.dirty,
            metadata.toolchain,
            metadata.rustc_release,
            metadata.rustc_commit,
            metadata.rustc_host,
            metadata.lock_digest,
            metadata.platform,
            metadata.architecture,
            metadata.runner_image,
            metadata.github_run_id,
            metadata.github_run_attempt,
            metadata.github_workflow_sha,
            metadata.github_workflow_ref,
            metadata.github_repository,
            metadata.github_event_name,
            metadata.runner_os,
            metadata.runner_arch,
            metadata.runner_environment,
            metadata.sqlcipher_version,
            metadata.sqlite_version,
            hex(&metadata.test_binary_digest),
            hex(&case.binding.baseline_artifact_digest),
            hex(&case.binding.post_recovery_artifact_digest),
            matrix_digest,
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
        manifests.push(L2EvidenceManifest(manifest));
    }
    Ok(L2EvidenceBundle(manifests))
}

fn append_index_value(index: &mut Vec<u8>, value: &[u8]) -> Result<(), SessionCtlError> {
    index.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| stage("L2 evidence case index"))?
            .to_be_bytes(),
    );
    index.extend_from_slice(value);
    Ok(())
}

fn case_fields(case: &L2EvidenceCase) -> String {
    let (
        target_kind,
        checkpoint,
        file_role,
        operation,
        fault_mode,
        target_ordinal,
        last_fully_explored_ordinal,
        expected_state,
        observed_state,
        sqlite_primary_code,
        sqlite_extended_code,
        transaction_result,
    ) = match case.target {
        L2EvidenceCaseTarget::ApplicationCheckpoint {
            checkpoint,
            ordinal,
            expected,
            observed,
        } => (
            "application-checkpoint",
            checkpoint,
            "none",
            "none",
            "process-kill",
            ordinal,
            ordinal,
            expected,
            observed,
            String::from("none"),
            String::from("none"),
            "terminated",
        ),
        L2EvidenceCaseTarget::SqliteReturnCode {
            file_role,
            operation,
            mode,
            ordinal,
            last_fully_explored_ordinal,
            expected,
            observed,
            primary_code,
            extended_code,
            transaction_result,
        } => (
            "sqlite-return-code",
            "none",
            file_role,
            operation,
            mode,
            ordinal,
            last_fully_explored_ordinal,
            expected,
            observed,
            primary_code.to_string(),
            extended_code.to_string(),
            transaction_result,
        ),
        L2EvidenceCaseTarget::CommitWindowProcessKill {
            file_role,
            operation,
            ordinal,
            last_fully_explored_ordinal,
            expected,
            observed,
        } => (
            "commit-window-process-kill",
            "none",
            file_role,
            operation,
            "pause-process-kill",
            ordinal,
            last_fully_explored_ordinal,
            expected,
            observed,
            String::from("none"),
            String::from("none"),
            "terminated",
        ),
    };
    format!(
        concat!(
            "case_id={}\n",
            "target_kind={}\n",
            "checkpoint={}\n",
            "file_role={}\n",
            "operation={}\n",
            "fault_mode={}\n",
            "target_ordinal={}\n",
            "last_fully_explored_ordinal={}\n",
            "expected_state={}\n",
            "observed_state={}\n",
            "sqlite_primary_code={}\n",
            "sqlite_extended_code={}\n",
            "transaction_result={}\n"
        ),
        case.key,
        target_kind,
        checkpoint,
        file_role,
        operation,
        fault_mode,
        target_ordinal,
        last_fully_explored_ordinal,
        expected_state,
        observed_state,
        sqlite_primary_code,
        sqlite_extended_code,
        transaction_result,
    )
}

impl L2ProcessSweepReport {
    /// Promotes one complete application-checkpoint sweep using exact runtime provenance.
    pub fn promote_v1(
        &self,
        executable: &Path,
        runner_image: &str,
        channels: &L2EvidenceChannels<'_>,
    ) -> Result<L2EvidenceBundle, SessionCtlError> {
        let metadata = L2EvidenceMetadata::collect(executable, runner_image, &self.evidence_cases)?;
        promote_l2_evidence(
            L2EvidenceSweep::ApplicationProcessKill,
            self.scenario,
            &self.encode_v1(),
            &metadata,
            &self.evidence_cases,
            channels,
        )
    }
}

impl L2IoSweepReport {
    /// Promotes one complete SQLite return-code sweep using exact runtime provenance.
    pub fn promote_v1(
        &self,
        executable: &Path,
        runner_image: &str,
        channels: &L2EvidenceChannels<'_>,
    ) -> Result<L2EvidenceBundle, SessionCtlError> {
        let metadata = L2EvidenceMetadata::collect(executable, runner_image, &self.evidence_cases)?;
        promote_l2_evidence(
            L2EvidenceSweep::SqliteReturnCode,
            self.scenario,
            &self.encode_v1(),
            &metadata,
            &self.evidence_cases,
            channels,
        )
    }
}

impl L2IoPauseSweepReport {
    /// Promotes one complete commit-window process-kill sweep using exact provenance.
    pub fn promote_v1(
        &self,
        executable: &Path,
        runner_image: &str,
        channels: &L2EvidenceChannels<'_>,
    ) -> Result<L2EvidenceBundle, SessionCtlError> {
        let metadata = L2EvidenceMetadata::collect(executable, runner_image, &self.evidence_cases)?;
        promote_l2_evidence(
            L2EvidenceSweep::CommitWindowProcessKill,
            self.scenario,
            &self.encode_v1(),
            &metadata,
            &self.evidence_cases,
            channels,
        )
    }
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
    let expected_fields: &[&str] = match sweep {
        L2EvidenceSweep::ApplicationProcessKill => &[
            "version",
            "protocol",
            "scenario",
            "publication",
            "status",
            "coverage",
            "sweep",
            "fault_build",
            "storage_scenario",
            "checkpoint_trace_sha256",
            "completed_cases",
            "observed_old_states",
            "observed_new_states",
            "integrity",
            "schema",
            "semantic_oracle",
            "exact_retry",
            "fixture_cleanup",
            "handle_cleanup",
            "child_cleanup",
            "directory_cleanup",
        ],
        L2EvidenceSweep::SqliteReturnCode => &[
            "version",
            "protocol",
            "scenario",
            "publication",
            "status",
            "coverage",
            "sweep",
            "fault_build",
            "storage_scenario",
            "allowed",
            "modes",
            "sqlite_primary_codes",
            "sqlite_extended_codes",
            "target_counts",
            "last_fully_explored_ordinals",
            "baseline_last_observed_ordinal",
            "baseline_total_observed_operations",
            "completed_cases",
            "observed_empty_states",
            "observed_committed_states",
            "fixture_cleanup",
            "handle_cleanup",
            "child_cleanup",
            "directory_cleanup",
            "integrity",
            "schema",
            "semantic_oracle",
            "exact_retry",
        ],
        L2EvidenceSweep::CommitWindowProcessKill => &[
            "version",
            "protocol",
            "scenario",
            "publication",
            "status",
            "coverage",
            "sweep",
            "fault_build",
            "storage_scenario",
            "allowed",
            "target_counts",
            "last_fully_explored_ordinals",
            "completed_cases",
            "observed_empty_states",
            "observed_committed_states",
            "pause",
            "process_termination",
            "fixture_cleanup",
            "handle_cleanup",
            "child_cleanup",
            "directory_cleanup",
            "integrity",
            "schema",
            "semantic_oracle",
            "exact_retry",
        ],
    };
    let fields = observation
        .lines()
        .map(|line| {
            line.split_once('=')
                .map(|(field, _)| field)
                .ok_or_else(|| stage("L2 internal observation"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if fields.len() != expected_fields.len()
        || fields.iter().any(|field| !expected_fields.contains(field))
        || expected_fields
            .iter()
            .any(|expected| fields.iter().filter(|field| *field == expected).count() != 1)
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

pub(super) fn scan_secret_values<'a, 'b>(
    surfaces: impl IntoIterator<Item = &'a [u8]>,
    secrets: impl IntoIterator<Item = &'b [u8]>,
) -> Result<(), SessionCtlError> {
    let surfaces = surfaces.into_iter().collect::<Vec<_>>();
    scan_canaries(surfaces.iter().copied())?;
    let secrets = secrets.into_iter().collect::<Vec<_>>();
    if secrets.is_empty()
        || secrets.len() > 32
        || secrets
            .iter()
            .any(|secret| secret.len() < 8 || secret.len() > 65_536)
    {
        return Err(stage("L2 evidence secret catalog"));
    }
    for secret in secrets {
        let encoded = hex(secret);
        if surfaces.iter().any(|surface| {
            contains_subslice(surface, secret) || contains_subslice(surface, encoded.as_bytes())
        }) {
            return Err(stage("L2 evidence redaction"));
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

fn is_decimal(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_safe_value(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn is_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().any(|byte| byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'-' | b'_' | b'+' | b':' | b' ' | b'(' | b')')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPLETE_PROCESS_OBSERVATION: &str = concat!(
        "version=1\n",
        "protocol=l2-checkpoint-observation-v1\n",
        "scenario=E2E-TXN-001\n",
        "publication=prohibited\n",
        "status=validated\n",
        "coverage=complete\n",
        "sweep=application-process-kill\n",
        "fault_build=true\n",
        "storage_scenario=inviter-transaction\n",
        "checkpoint_trace_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        "completed_cases=9\n",
        "observed_old_states=7\n",
        "observed_new_states=2\n",
        "integrity=pass\n",
        "schema=pass\n",
        "semantic_oracle=pass\n",
        "exact_retry=pass\n",
        "fixture_cleanup=pass\n",
        "handle_cleanup=pass\n",
        "child_cleanup=pass\n",
        "directory_cleanup=pass\n",
    );

    fn rustc_provenance() -> RustcProvenance {
        RustcProvenance {
            release: String::from("1.97.1"),
            commit: String::from("0123456789abcdef0123456789abcdef01234567"),
            host: String::from("aarch64-apple-darwin"),
        }
    }

    fn ci_context(commit: &str) -> L2CiContext {
        let values = [
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_SHA", commit),
            ("GITHUB_WORKFLOW_SHA", commit),
            ("GITHUB_RUN_ID", "123456"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            (
                "GITHUB_WORKFLOW_REF",
                "owner/session-chat/.github/workflows/ci.yml@refs/heads/master",
            ),
            ("GITHUB_REPOSITORY", "owner/session-chat"),
            ("GITHUB_EVENT_NAME", "push"),
            ("RUNNER_OS", "macOS"),
            ("RUNNER_ARCH", "ARM64"),
            ("RUNNER_ENVIRONMENT", "github-hosted"),
        ];
        validate_ci_context(commit, "macos", "aarch64", "macos-15", |name| {
            values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        })
        .expect("CI context")
    }

    fn metadata() -> L2EvidenceMetadata {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        L2EvidenceMetadata::new(
            commit,
            false,
            "1.97.1",
            rustc_provenance(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ci_context(commit),
            "4.14.0 community",
            "3.50.4",
            [0x11; 32],
        )
        .expect("closed provenance")
    }

    fn test_case() -> L2EvidenceCase {
        L2EvidenceCase {
            key: String::from("checkpoint-inviter-before-begin-0"),
            target: L2EvidenceCaseTarget::ApplicationCheckpoint {
                checkpoint: "INVITER_BEFORE_BEGIN",
                ordinal: 0,
                expected: "I0",
                observed: "I0",
            },
            binding: super::super::L2EvidenceBinding {
                sqlcipher_version: String::from("4.14.0 community"),
                sqlite_version: String::from("3.50.4"),
                baseline_artifact_digest: [0x22; 32],
                post_recovery_artifact_digest: [0x33; 32],
                redaction: true,
            },
        }
    }

    fn clean_channels() -> L2EvidenceChannels<'static> {
        L2EvidenceChannels::new(b"", b"", b"", b"checkpoint-only", b"encrypted-artifacts")
            .expect("bounded channels")
    }

    #[test]
    fn sealed_promotion_builds_a_bounded_manifest() {
        let cases = [test_case()];
        let bundle = promote_l2_evidence(
            L2EvidenceSweep::ApplicationProcessKill,
            Scenario::InviterTransaction,
            COMPLETE_PROCESS_OBSERVATION,
            &metadata(),
            &cases,
            &clean_channels(),
        )
        .expect("promote complete checked evidence");
        let manifest = bundle
            .manifests()
            .next()
            .expect("one case manifest")
            .encode_v1();

        for required in [
            "protocol=l2-evidence-v1\n",
            "result=pass\n",
            "coverage=complete\n",
            "record=case\n",
            "case_id=checkpoint-inviter-before-begin-0\n",
            "target_kind=application-checkpoint\n",
            "expected_state=I0\n",
            "observed_state=I0\n",
            "commit=0123456789abcdef0123456789abcdef01234567\n",
            "platform=macos-aarch64\n",
            "rustc_release=1.97.1\n",
            "rustc_commit=0123456789abcdef0123456789abcdef01234567\n",
            "rustc_host=aarch64-apple-darwin\n",
            "github_run_id=123456\n",
            "github_run_attempt=2\n",
            "github_workflow_sha=0123456789abcdef0123456789abcdef01234567\n",
            "runner_environment=github-hosted\n",
            "sqlcipher_version=4.14.0 community\n",
            "redaction=pass\n",
            "cleanup=pass\n",
        ] {
            assert!(manifest.contains(required), "missing {required:?}");
        }
        assert!(manifest.len() <= MAX_MANIFEST_BYTES);
        assert!(!manifest.contains("publication=prohibited"));
    }

    #[test]
    fn public_case_records_retain_sqlite_and_pause_targets() {
        let binding = test_case().binding;
        let sqlite = L2EvidenceCase {
            key: String::from("sqlite-main-database-write-one-shot-0000000013-0004"),
            target: L2EvidenceCaseTarget::SqliteReturnCode {
                file_role: "main-database",
                operation: "write",
                mode: "one-shot",
                ordinal: 4,
                last_fully_explored_ordinal: 7,
                expected: "I0|I1",
                observed: "I0",
                primary_code: 13,
                extended_code: 13,
                transaction_result: "rejected",
            },
            binding: binding.clone(),
        };
        let pause = L2EvidenceCase {
            key: String::from("pause-rollback-journal-sync-0002"),
            target: L2EvidenceCaseTarget::CommitWindowProcessKill {
                file_role: "rollback-journal",
                operation: "sync",
                ordinal: 2,
                last_fully_explored_ordinal: 5,
                expected: "I0|I1",
                observed: "I1",
            },
            binding,
        };

        let sqlite_fields = case_fields(&sqlite);
        for required in [
            "case_id=sqlite-main-database-write-one-shot-0000000013-0004\n",
            "target_kind=sqlite-return-code\n",
            "file_role=main-database\n",
            "operation=write\n",
            "target_ordinal=4\n",
            "last_fully_explored_ordinal=7\n",
            "expected_state=I0|I1\n",
            "observed_state=I0\n",
            "sqlite_primary_code=13\n",
            "sqlite_extended_code=13\n",
        ] {
            assert!(sqlite_fields.contains(required), "missing {required:?}");
        }
        let pause_fields = case_fields(&pause);
        for required in [
            "case_id=pause-rollback-journal-sync-0002\n",
            "target_kind=commit-window-process-kill\n",
            "fault_mode=pause-process-kill\n",
            "target_ordinal=2\n",
            "last_fully_explored_ordinal=5\n",
            "observed_state=I1\n",
        ] {
            assert!(pause_fields.contains(required), "missing {required:?}");
        }
    }

    #[test]
    fn sealed_promotion_rejects_canaries_on_every_surface() {
        const CANARY: &[u8] = b"SC-L2-CANARY-DATABASE-KEY";
        for channels in [
            L2EvidenceChannels::new(CANARY, b"", b"", b"", b""),
            L2EvidenceChannels::new(b"", CANARY, b"", b"", b""),
            L2EvidenceChannels::new(b"", b"", CANARY, b"", b""),
            L2EvidenceChannels::new(b"", b"", b"", CANARY, b""),
            L2EvidenceChannels::new(b"", b"", b"", b"", CANARY),
        ] {
            let cases = [test_case()];
            assert!(
                promote_l2_evidence(
                    L2EvidenceSweep::ApplicationProcessKill,
                    Scenario::InviterTransaction,
                    COMPLETE_PROCESS_OBSERVATION,
                    &metadata(),
                    &cases,
                    &channels.expect("bounded hostile channel"),
                )
                .is_err(),
                "canary-bearing evidence surface must fail closed",
            );
        }
    }

    #[test]
    fn sealed_promotion_rejects_unbound_or_dirty_provenance() {
        for (commit, dirty) in [
            ("unavailable", false),
            ("0123456789abcdef0123456789abcdef01234567", true),
        ] {
            assert!(
                L2EvidenceMetadata::new(
                    commit,
                    dirty,
                    "1.97.1",
                    rustc_provenance(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    ci_context("0123456789abcdef0123456789abcdef01234567"),
                    "4.14.0",
                    "3.50.4",
                    [0x11; 32],
                )
                .is_err(),
            );
        }
    }

    #[test]
    fn metadata_rejects_runner_image_platform_mismatch() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let values = [
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_SHA", commit),
            ("GITHUB_WORKFLOW_SHA", commit),
            ("GITHUB_RUN_ID", "123456"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            (
                "GITHUB_WORKFLOW_REF",
                "owner/session-chat/.github/workflows/ci.yml@refs/heads/master",
            ),
            ("GITHUB_REPOSITORY", "owner/session-chat"),
            ("GITHUB_EVENT_NAME", "push"),
            ("RUNNER_OS", "Linux"),
            ("RUNNER_ARCH", "X64"),
            ("RUNNER_ENVIRONMENT", "github-hosted"),
        ];
        assert!(
            validate_ci_context(commit, "linux", "x86_64", "macos-15", |name| {
                values
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| (*value).to_owned())
            })
            .is_err(),
            "a self-asserted runner label must not cross platform tuples",
        );
    }

    #[test]
    fn rustc_provenance_parses_actual_verbose_output_and_rejects_pin_mismatch() {
        let output = concat!(
            "rustc 1.97.1 (012345678 2026-08-01)\n",
            "binary: rustc\n",
            "commit-hash: 0123456789abcdef0123456789abcdef01234567\n",
            "commit-date: 2026-08-01\n",
            "host: aarch64-apple-darwin\n",
            "release: 1.97.1\n",
            "LLVM version: 21.1.0\n",
        );
        let parsed = parse_rustc_verbose(output.as_bytes(), "1.97.1").expect("actual rustc");
        assert_eq!(parsed.release, "1.97.1");
        assert_eq!(parsed.host, "aarch64-apple-darwin");
        assert_eq!(parsed.commit, "0123456789abcdef0123456789abcdef01234567",);
        assert!(parse_rustc_verbose(output.as_bytes(), "1.98.0").is_err());
    }

    #[test]
    fn ci_context_requires_exact_revision_and_github_hosted_runner() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let values = [
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_SHA", commit),
            ("GITHUB_WORKFLOW_SHA", commit),
            ("GITHUB_RUN_ID", "123456"),
            ("GITHUB_RUN_ATTEMPT", "2"),
            (
                "GITHUB_WORKFLOW_REF",
                "owner/session-chat/.github/workflows/ci.yml@refs/heads/master",
            ),
            ("GITHUB_REPOSITORY", "owner/session-chat"),
            ("GITHUB_EVENT_NAME", "push"),
            ("RUNNER_OS", "macOS"),
            ("RUNNER_ARCH", "ARM64"),
            ("RUNNER_ENVIRONMENT", "github-hosted"),
        ];
        let lookup = |name: &str| {
            values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        };
        assert!(validate_ci_context(commit, "macos", "aarch64", "macos-15", lookup).is_ok());
        assert!(
            validate_ci_context(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "macos",
                "aarch64",
                "macos-15",
                lookup,
            )
            .is_err()
        );
    }

    #[test]
    fn internal_observation_rejects_unknown_and_contradictory_fields() {
        for hostile in [
            COMPLETE_PROCESS_OBSERVATION.replace(
                "coverage=complete\n",
                "coverage=complete\ncoverage=partial\n",
            ),
            COMPLETE_PROCESS_OBSERVATION
                .replace("exact_retry=pass\n", "exact_retry=pass\nexact_retry=fail\n"),
            COMPLETE_PROCESS_OBSERVATION.replace(
                "directory_cleanup=pass\n",
                "directory_cleanup=pass\nunknown_claim=pass\n",
            ),
        ] {
            assert!(
                validate_observation(
                    L2EvidenceSweep::ApplicationProcessKill,
                    Scenario::InviterTransaction,
                    &hostile,
                )
                .is_err(),
                "hostile extra field must fail closed: {hostile}",
            );
        }
    }

    #[test]
    fn actual_secret_scanner_rejects_raw_and_hex_encoded_values() {
        let secret = b"actual-case-secret";
        assert!(scan_secret_values([secret.as_slice()], [secret.as_slice()]).is_err());
        let encoded = hex(secret);
        assert!(scan_secret_values([encoded.as_bytes()], [secret.as_slice()]).is_err());
        assert!(
            scan_secret_values([b"coarse-clean-output".as_slice()], [secret.as_slice()]).is_ok()
        );
    }
}
