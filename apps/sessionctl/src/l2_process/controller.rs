//! L2 process controllers, child roles, and evidence parsing.

use super::*;

/// Runs one bounded controller probe through the checked hidden binary.
pub fn run_l2_process_probe(
    executable: &Path,
    probe: L2HarnessProbe,
) -> Result<L2ProcessReport, SessionCtlError> {
    let checkpoint = match probe {
        L2HarnessProbe::GracefulContinue => Checkpoint::InviterBeforeShadowFinalize,
        L2HarnessProbe::NonzeroLeaseGeneration
        | L2HarnessProbe::ChangedAttemptCeiling
        | L2HarnessProbe::InviterRetryMutation => Checkpoint::InviterAfterCommitReturn,
        L2HarnessProbe::JoinerRetryMutation => Checkpoint::JoinerAfterCommitReturn,
        L2HarnessProbe::JoinerRetainedKeyPackage => Checkpoint::JoinerAfterCommitReturn,
        L2HarnessProbe::MissingAcknowledgement => Checkpoint::InviterAfterGroupUpsert,
        _ => Checkpoint::InviterBeforeBegin,
    };
    run_l2_process_case(executable, L2ProcessCase::new(checkpoint, 0)?, probe)
}

/// Runs one closed real-storage case through the checked hidden binary.
pub fn run_l2_process_case(
    executable: &Path,
    case: L2ProcessCase,
    probe: L2HarnessProbe,
) -> Result<L2ProcessReport, SessionCtlError> {
    if !executable.is_absolute() || !executable.is_file() {
        return Err(stage("L2 executable"));
    }
    let snapshot = ExecutableSnapshot::capture(executable)?;
    let identity = ExecutionIdentity::capture(snapshot.digest, None)?;
    let executable = snapshot.path();
    let case_id = CaseId::new(random_nonzero()?).map_err(|_| stage("L2 case"))?;
    let target = ControlFrame::new_checkpoint(case_id, case.checkpoint, case.occurrence)
        .map_err(|_| stage("L2 case"))?;
    let config = CaseConfig { target, probe };
    let mut root = ProcessRoot::new()?;
    let scenario_result = run_controller(executable, root.path(), config);
    let cleanup_result = root.cleanup();
    let mut controller = scenario_result?;
    snapshot.verify_source()?;
    controller.evidence_binding.executables = Some(identity);
    cleanup_result?;
    let repository_root = repository_root();
    let report = L2ProcessReport {
        case_id,
        case,
        trace: controller.trace,
        probe,
        commit: resolve_l1_process_git_commit(&repository_root)
            .unwrap_or_else(|| String::from("unavailable")),
        dirty: git_dirty_at(&repository_root).unwrap_or(true),
        toolchain: pinned_toolchain_at(&repository_root)
            .unwrap_or_else(|| String::from("unavailable")),
        lock_digest: lock_digest_at(&repository_root)
            .unwrap_or_else(|| String::from("unavailable")),
        observed: controller.observed,
        integrity: controller.integrity,
        schema: controller.schema,
        semantic_oracle: controller.semantic_oracle,
        exact_retry: controller.exact_retry,
        fixture_cleanup: controller.fixture_cleanup,
        writer_termination: controller.writer_termination,
        fresh_verifier: controller.fresh_verifier,
        redaction: controller.redaction,
        handle_cleanup: controller.handle_cleanup,
        child_cleanup: controller.child_cleanup,
        directory_cleanup: true,
        evidence_binding: controller.evidence_binding,
    };
    if report.encode_v1().len() > MAX_EVIDENCE_BYTES {
        return Err(stage("L2 evidence"));
    }
    Ok(report)
}

/// Discovers the exact checkpoint occurrences emitted by one clean transaction.
pub fn run_l2_process_baseline(
    executable: &Path,
    scenario: Scenario,
) -> Result<L2ProcessBaseline, SessionCtlError> {
    let terminal = match scenario {
        Scenario::InviterTransaction => Checkpoint::InviterBeforeShadowFinalize,
        Scenario::JoinerTransaction => Checkpoint::JoinerAfterCommitReturn,
    };
    let report = run_l2_process_case(
        executable,
        L2ProcessCase::new(terminal, 0)?,
        L2HarnessProbe::GracefulContinue,
    )?;
    let expected = match scenario {
        Scenario::InviterTransaction => OracleState::InviterNew,
        Scenario::JoinerTransaction => OracleState::JoinerNew,
    };
    if report.observed != expected
        || report.trace.is_empty()
        || report.trace.len() > MAX_APPLICATION_CHECKPOINTS
        || report.trace.last().copied() != Some(report.case)
        || report.trace.iter().any(|case| case.scenario() != scenario)
    {
        return Err(stage("L2 process baseline"));
    }
    for (index, case) in report.trace.iter().enumerate() {
        if report.trace[index + 1..].contains(case) {
            return Err(stage("L2 process baseline coverage"));
        }
    }
    Ok(L2ProcessBaseline {
        executables: report.evidence_binding.executables,
        scenario,
        cases: report.trace,
    })
}

/// Runs one SQLite-visible fault against a fresh closed baseline and verifier.
pub fn run_l2_io_fault_case(
    executable: &Path,
    scenario: Scenario,
    driver: &mut impl L2IoFaultDriver,
) -> Result<L2IoFaultReport, SessionCtlError> {
    if !executable.is_absolute() || !executable.is_file() {
        return Err(stage("L2 executable"));
    }
    let snapshot = ExecutableSnapshot::capture(executable)?;
    let identity = ExecutionIdentity::capture(snapshot.digest, None)?;
    let executable = snapshot.path();
    let config = l2_io_case_config(scenario)?;
    let mut root = ProcessRoot::new()?;
    let result = run_l2_io_fault_controller(executable, root.path(), config, driver);
    let cleanup = root.cleanup();
    let (
        observed,
        driver_observation,
        fixture_cleanup,
        handle_cleanup,
        child_cleanup,
        mut evidence_binding,
    ) = result?;
    snapshot.verify_source()?;
    evidence_binding.executables = Some(identity);
    cleanup?;
    let L2IoDriverObservation::Fault(fault) = driver_observation else {
        return Err(stage("L2 I/O fault evidence"));
    };
    let report = L2IoFaultReport {
        scenario,
        observed,
        fault,
        fixture_cleanup,
        handle_cleanup,
        child_cleanup,
        directory_cleanup: true,
        evidence_binding,
    };
    if report.encode_v1().len() > MAX_EVIDENCE_BYTES {
        return Err(stage("L2 I/O evidence"));
    }
    Ok(report)
}

/// Discovers one clean transaction-only named-VFS trace on a fresh baseline.
pub fn run_l2_io_baseline(
    executable: &Path,
    scenario: Scenario,
    driver: &mut impl L2IoFaultDriver,
) -> Result<L2IoBaselineReport, SessionCtlError> {
    if !executable.is_absolute() || !executable.is_file() {
        return Err(stage("L2 executable"));
    }
    let snapshot = ExecutableSnapshot::capture(executable)?;
    let identity = ExecutionIdentity::capture(snapshot.digest, None)?;
    let executable = snapshot.path();
    let config = l2_io_case_config(scenario)?;
    let mut root = ProcessRoot::new()?;
    let result = run_l2_io_fault_controller(executable, root.path(), config, driver);
    let cleanup = root.cleanup();
    let (
        observed,
        driver_observation,
        fixture_cleanup,
        handle_cleanup,
        child_cleanup,
        mut evidence_binding,
    ) = result?;
    snapshot.verify_source()?;
    evidence_binding.executables = Some(identity);
    cleanup?;
    let L2IoDriverObservation::Baseline(baseline) = driver_observation else {
        return Err(stage("L2 I/O baseline evidence"));
    };
    let report = L2IoBaselineReport::new(
        scenario,
        observed,
        baseline,
        fixture_cleanup,
        handle_cleanup,
        child_cleanup,
        true,
        evidence_binding,
    )?;
    if report.encode_v1().len() > MAX_EVIDENCE_BYTES {
        return Err(stage("L2 I/O evidence"));
    }
    Ok(report)
}

/// Parent-owned fresh baseline and key for one killable pause child.
pub struct L2IoPauseKillCase {
    driver_snapshot: ExecutableSnapshot,
    root: ProcessRoot,
    key: Zeroizing<[u8; KEY_BYTES]>,
    scenario: Scenario,
    expected_pause: L2IoPauseSweepCase,
    baseline_artifact: L2ArtifactSnapshot,
    fixture: CaseFixture,
    welcome_canary: Option<Zeroizing<Vec<u8>>>,
}

impl L2IoPauseKillCase {
    /// Exact captured controller binary to launch for the external pause child.
    pub fn driver_executable(&self) -> &Path {
        self.driver_snapshot.path()
    }

    /// Absolute marked root passed only to the direct checked test child.
    pub fn root(&self) -> &Path {
        self.root.path()
    }

    /// Verifies the killed child's database in a fresh process, then removes the case root.
    pub fn finish(
        mut self,
        executable: &Path,
        pause: L2IoPauseObservation,
        pause_stdout: &[u8],
        pause_stderr: &[u8],
    ) -> Result<L2IoPauseKillReport, SessionCtlError> {
        if pause_stdout.len() > MAX_CHILD_OUTPUT_BYTES
            || pause_stderr.len() > MAX_CHILD_OUTPUT_BYTES
        {
            return Err(stage("L2 I/O pause output bound"));
        }
        if !executable.is_absolute() || !executable.is_file() {
            return Err(stage("L2 executable"));
        }
        if pause.file_role != self.expected_pause.file_role
            || pause.operation != self.expected_pause.operation
            || pause.target_ordinal != self.expected_pause.target_ordinal
        {
            return Err(stage("L2 I/O pause binding"));
        }
        if self.root.path().join(WRITER_KEY_NAME).exists()
            || self.root.path().join(WRITER_CASE_FIXTURE_NAME).exists()
        {
            return Err(stage("L2 I/O pause child load"));
        }
        if self.welcome_canary.is_none() {
            self.welcome_canary = read_optional_welcome_canary(self.root.path())?;
        }
        let snapshot = ExecutableSnapshot::capture(executable)?;
        let identity = ExecutionIdentity::capture(snapshot.digest, None)?;
        self.driver_snapshot.verify_source()?;
        if identity.producer != self.driver_snapshot.digest {
            return Err(stage("L2 producer changed"));
        }
        let executable = snapshot.path();
        let result = verify_l2_io_root(
            executable,
            self.root.path(),
            &self.key,
            self.scenario,
            L2CaseSecrets {
                fixture: &self.fixture,
                welcome_canary: self.welcome_canary.as_ref().map(|value| value.as_slice()),
            },
            self.baseline_artifact,
            &[pause_stdout, pause_stderr],
        );
        let cleanup = self.root.cleanup();
        let (observed, fixture_cleanup, handle_cleanup, child_cleanup, mut evidence_binding) =
            result?;
        snapshot.verify_source()?;
        evidence_binding.executables = Some(identity);
        cleanup?;
        let report = L2IoPauseKillReport {
            scenario: self.scenario,
            observed,
            pause,
            fixture_cleanup,
            handle_cleanup,
            child_cleanup,
            directory_cleanup: true,
            evidence_binding,
        };
        if report.encode_v1().len() > MAX_EVIDENCE_BYTES {
            return Err(stage("L2 I/O pause evidence"));
        }
        Ok(report)
    }
}

/// Prepares a fresh closed baseline and parent-retained verifier key for one pause child.
pub fn prepare_l2_io_pause_kill_case(
    scenario: Scenario,
    file_role: L2IoFileRole,
    operation: L2IoOperation,
    target_ordinal: u16,
) -> Result<L2IoPauseKillCase, SessionCtlError> {
    if !l2_io_pause_supported(file_role, operation) || usize::from(target_ordinal) >= 4_096 {
        return Err(stage("L2 I/O pause target"));
    }
    let config = l2_io_case_config(scenario)?;
    let root = ProcessRoot::new()?;
    let key = Zeroizing::new(random_nonzero::<KEY_BYTES>()?);
    write_owned_file(&root.path().join(CASE_CONFIG_NAME), &config.encode(), false)?;
    let fixture = prepare_baseline(root.path(), &key, scenario)?;
    let baseline_artifact = encrypted_artifact_snapshot(root.path())?;
    let welcome_canary = read_optional_welcome_canary(root.path())?;
    let fixture_bytes = fixture.encode();
    write_owned_file(
        &root.path().join(WRITER_CASE_FIXTURE_NAME),
        fixture_bytes.as_ref(),
        true,
    )?;
    write_owned_file(
        &root.path().join(VERIFIER_CASE_FIXTURE_NAME),
        fixture_bytes.as_ref(),
        true,
    )?;
    write_owned_file(&root.path().join(WRITER_KEY_NAME), key.as_slice(), true)?;
    Ok(L2IoPauseKillCase {
        driver_snapshot: ExecutableSnapshot::capture(
            &std::env::current_exe().map_err(|_| stage("L2 producer"))?,
        )?,
        root,
        key,
        scenario,
        expected_pause: L2IoPauseSweepCase {
            file_role,
            operation,
            target_ordinal,
        },
        baseline_artifact,
        fixture,
        welcome_canary,
    })
}

/// Runs the checked child transaction and must remain blocked until the process is killed.
pub fn run_l2_io_pause_writer(
    root: &Path,
    driver: &mut impl L2IoPauseDriver,
) -> Result<(), SessionCtlError> {
    validate_root(root)?;
    let config = read_case_config(root)?;
    if config.probe != L2HarnessProbe::IoFault {
        return Err(stage("L2 I/O pause config"));
    }
    let fixture = read_fixture(root, WRITER_CASE_FIXTURE_NAME)?;
    let key = read_key(root, WRITER_KEY_NAME)?;
    if !driver.prepare_before_open() {
        return Err(stage("L2 I/O pause preparation"));
    }
    let observer = FaultObserver::new(
        config.target.case_id(),
        config.target.scenario(),
        std::sync::Arc::new(AutoContinueBarrier),
    );
    let storage = fault_testing::open_with_fault_vfs(
        &root.join(DATABASE_NAME),
        VaultKey::new(*key).map_err(|_| stage("L2 I/O pause writer"))?,
        observer.clone(),
    )
    .map_err(|_| stage("L2 I/O pause writer open"))?;
    if !driver.arm_after_open() {
        return Err(stage("L2 I/O pause arm"));
    }
    let _ =
        run_real_storage_transaction(&storage, observer, config.target.scenario(), &fixture, root);
    Err(stage("L2 I/O pause escaped"))
}

fn l2_io_case_config(scenario: Scenario) -> Result<CaseConfig, SessionCtlError> {
    let checkpoint = match scenario {
        Scenario::InviterTransaction => Checkpoint::InviterBeforeShadowFinalize,
        Scenario::JoinerTransaction => Checkpoint::JoinerAfterCommitReturn,
    };
    let case_id = CaseId::new(random_nonzero()?).map_err(|_| stage("L2 I/O case"))?;
    let target =
        ControlFrame::new_checkpoint(case_id, checkpoint, 0).map_err(|_| stage("L2 I/O case"))?;
    Ok(CaseConfig {
        target,
        probe: L2HarnessProbe::IoFault,
    })
}

fn run_l2_io_fault_controller(
    executable: &Path,
    root: &Path,
    config: CaseConfig,
    driver: &mut impl L2IoFaultDriver,
) -> Result<
    (
        OracleState,
        L2IoDriverObservation,
        bool,
        bool,
        bool,
        L2EvidenceBinding,
    ),
    SessionCtlError,
> {
    let key = Zeroizing::new(random_nonzero::<KEY_BYTES>()?);
    write_owned_file(&root.join(CASE_CONFIG_NAME), &config.encode(), false)?;
    let fixture = prepare_baseline(root, &key, config.target.scenario())?;
    let baseline_artifact = encrypted_artifact_snapshot(root)?;
    let mut welcome_canary = read_optional_welcome_canary(root)?;
    write_owned_file(
        &root.join(VERIFIER_CASE_FIXTURE_NAME),
        fixture.encode().as_ref(),
        true,
    )?;
    if !driver.prepare_before_open() {
        return Err(stage("L2 I/O driver preparation"));
    }
    let observer = FaultObserver::new(
        config.target.case_id(),
        config.target.scenario(),
        std::sync::Arc::new(AutoContinueBarrier),
    );
    let storage = fault_testing::open_with_fault_vfs(
        &root.join(DATABASE_NAME),
        VaultKey::new(*key).map_err(|_| stage("L2 I/O writer"))?,
        observer.clone(),
    )
    .map_err(|_| stage("L2 I/O writer open"))?;
    if !driver.arm_after_open() {
        return Err(stage("L2 I/O driver arm"));
    }
    let transaction_succeeded =
        run_real_storage_transaction(&storage, observer, config.target.scenario(), &fixture, root)
            .is_ok();
    if welcome_canary.is_none() {
        welcome_canary = read_optional_welcome_canary(root)?;
    }
    let fault = driver
        .disable_and_observe(transaction_succeeded)
        .ok_or_else(|| stage("L2 I/O driver evidence"))?;
    drop(storage);

    let (observed, fixture_cleanup, handle_cleanup, child_cleanup, evidence_binding) =
        verify_l2_io_root(
            executable,
            root,
            &key,
            config.target.scenario(),
            L2CaseSecrets {
                fixture: &fixture,
                welcome_canary: welcome_canary.as_ref().map(|value| value.as_slice()),
            },
            baseline_artifact,
            &[],
        )?;
    Ok((
        observed,
        fault,
        fixture_cleanup,
        handle_cleanup,
        child_cleanup,
        evidence_binding,
    ))
}

struct L2CaseSecrets<'a> {
    fixture: &'a CaseFixture,
    welcome_canary: Option<&'a [u8]>,
}

fn verify_l2_io_root(
    executable: &Path,
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    scenario: Scenario,
    secrets: L2CaseSecrets<'_>,
    baseline_artifact: L2ArtifactSnapshot,
    additional_surfaces: &[&[u8]],
) -> Result<(OracleState, bool, bool, bool, L2EvidenceBinding), SessionCtlError> {
    write_owned_file(&root.join(VERIFIER_KEY_NAME), key.as_slice(), true)?;
    let mut verifier = ManagedChild::spawn(executable, "verifier", root, false)?;
    let status = match verifier.wait(CHILD_WAIT) {
        Ok(status) => status,
        Err(error) => {
            verifier.terminate_and_reap()?;
            return Err(error);
        }
    };
    if !status.success() {
        return Err(stage("L2 I/O verifier"));
    }
    let stdout = verifier.stdout.collect(CHILD_WAIT)?;
    let stderr = verifier.stderr.collect(CHILD_WAIT)?;
    if !stderr.is_empty() || root.join(VERIFIER_KEY_NAME).exists() {
        return Err(stage("L2 I/O verifier output"));
    }
    let evidence = parse_io_verifier_evidence(&stdout, scenario)?;
    let fixture_cleanup = !root.join(VERIFIER_CASE_FIXTURE_NAME).exists()
        && !root.join(WELCOME_FIXTURE_NAME).exists();
    if !fixture_cleanup {
        return Err(stage("L2 I/O fixture cleanup"));
    }
    let handle_cleanup = prove_database_handle_cleanup(root)?;
    let mut surfaces = Vec::with_capacity(additional_surfaces.len() + 2);
    surfaces.extend_from_slice(additional_surfaces);
    surfaces.push(stdout.as_slice());
    surfaces.push(stderr.as_slice());
    let evidence_binding = collect_evidence_binding(
        root,
        key,
        secrets.fixture,
        secrets.welcome_canary,
        baseline_artifact,
        &surfaces,
    )?;
    Ok((
        evidence.observed,
        fixture_cleanup,
        handle_cleanup,
        true,
        evidence_binding,
    ))
}

/// Runs one hidden role selected only by the checked parent controller.
pub fn run_l2_process_internal_role(role: &str, root: PathBuf) -> Result<(), SessionCtlError> {
    validate_root(&root)?;
    match role {
        "welcome-writer" => welcome::writer(&root),
        "welcome-verifier" => welcome::verifier(&root),
        "writer" => run_writer(&root),
        "verifier" => run_verifier(&root),
        _ => Err(stage("L2 role")),
    }
}

#[derive(Clone, Copy)]
pub(super) struct CaseConfig {
    pub(super) target: ControlFrame,
    pub(super) probe: L2HarnessProbe,
}

impl CaseConfig {
    fn encode(self) -> [u8; CASE_CONFIG_BYTES] {
        let mut encoded = [0_u8; CASE_CONFIG_BYTES];
        encoded[..CONTROL_FRAME_BYTES].copy_from_slice(&self.target.encode());
        encoded[CONTROL_FRAME_BYTES] = self.probe.code();
        encoded
    }

    pub(super) fn decode(encoded: &[u8]) -> Result<Self, SessionCtlError> {
        if encoded.len() != CASE_CONFIG_BYTES {
            return Err(stage("L2 case config"));
        }
        let target = ControlFrame::decode(&encoded[..CONTROL_FRAME_BYTES])
            .map_err(|_| stage("L2 case config"))?;
        let probe = L2HarnessProbe::try_from(encoded[CONTROL_FRAME_BYTES])?;
        if target.kind() != FrameKind::Checkpoint
            || target.role() != Role::Writer
            || L2ProcessCase::new(target.checkpoint(), target.occurrence()).is_err()
        {
            return Err(stage("L2 case config"));
        }
        Ok(Self { target, probe })
    }

    pub(super) fn case(self) -> Result<L2ProcessCase, SessionCtlError> {
        L2ProcessCase::new(self.target.checkpoint(), self.target.occurrence())
    }
}

pub(super) const fn pass_fail(value: bool) -> &'static str {
    if value { "pass" } else { "fail" }
}

pub(super) fn canonical_evidence_cases(
    mut cases: Vec<L2EvidenceCase>,
) -> Result<Vec<L2EvidenceCase>, SessionCtlError> {
    if cases.is_empty() || cases.len() > 4_096 {
        return Err(stage("L2 evidence case index"));
    }
    cases.sort_by(|left, right| left.key.cmp(&right.key));
    let first = cases
        .first()
        .ok_or_else(|| stage("L2 evidence case index"))?;
    if cases.windows(2).any(|pair| pair[0].key == pair[1].key)
        || cases.iter().any(|case| {
            case.key.is_empty()
                || case.key.len() > 256
                || !case
                    .key
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || case.binding.sqlcipher_version != first.binding.sqlcipher_version
                || case.binding.sqlite_version != first.binding.sqlite_version
                || case.binding.executables.is_none()
                || case.binding.executables != first.binding.executables
                || !case.binding.redaction
        })
    {
        return Err(stage("L2 evidence case index"));
    }
    Ok(cases)
}

struct ControllerEvidence {
    observed: OracleState,
    trace: Vec<L2ProcessCase>,
    integrity: bool,
    schema: bool,
    semantic_oracle: bool,
    exact_retry: bool,
    fixture_cleanup: bool,
    writer_termination: bool,
    fresh_verifier: bool,
    redaction: bool,
    handle_cleanup: bool,
    child_cleanup: bool,
    evidence_binding: L2EvidenceBinding,
}

fn run_controller(
    executable: &Path,
    root: &Path,
    config: CaseConfig,
) -> Result<ControllerEvidence, SessionCtlError> {
    let key = Zeroizing::new(random_nonzero::<KEY_BYTES>()?);
    write_owned_file(&root.join(CASE_CONFIG_NAME), &config.encode(), false)?;
    let fixture = prepare_baseline(root, &key, config.target.scenario())?;
    let baseline_artifact = encrypted_artifact_snapshot(root)?;
    let mut welcome_canary = read_optional_welcome_canary(root)?;
    let fixture_bytes = fixture.encode();
    write_owned_file(
        &root.join(WRITER_CASE_FIXTURE_NAME),
        fixture_bytes.as_ref(),
        true,
    )?;
    write_owned_file(
        &root.join(VERIFIER_CASE_FIXTURE_NAME),
        fixture_bytes.as_ref(),
        true,
    )?;
    write_owned_file(&root.join(WRITER_KEY_NAME), key.as_slice(), true)?;

    let mut writer = ManagedChild::spawn(executable, "writer", root, true)?;
    if config.probe == L2HarnessProbe::MissingAcknowledgement {
        let encoded = writer
            .stdout
            .read_exact_frame(CONTROL_FRAME_BYTES, FRAME_WAIT)?;
        let first = ControlFrame::decode(&encoded).map_err(|_| stage("L2 checkpoint"))?;
        if first == config.target || first.scenario() != config.target.scenario() {
            return Err(stage("L2 missing acknowledgement"));
        }
        let blocked = writer
            .stdout
            .read_exact_frame(CONTROL_FRAME_BYTES, FRAME_WAIT)
            .is_err();
        writer.terminate_and_reap()?;
        return if blocked {
            Err(stage("L2 missing acknowledgement"))
        } else {
            Err(stage("L2 checkpoint advanced without acknowledgement"))
        };
    }
    let trace = advance_writer_to_target(&mut writer, config.target)?;
    let observed = trace.target;

    match config.probe {
        L2HarnessProbe::GracefulContinue => {
            writer.write_stdin(&observed.acknowledgement().encode())?;
            writer.close_stdin();
            if !writer.wait(CHILD_WAIT)?.success() {
                return Err(stage("L2 writer"));
            }
        }
        L2HarnessProbe::KillWhileBlocked
        | L2HarnessProbe::AdvanceWithoutAcknowledgement
        | L2HarnessProbe::OversizedOutput
        | L2HarnessProbe::SecretDiagnostic
        | L2HarnessProbe::MixedFixture
        | L2HarnessProbe::IdentityLoss
        | L2HarnessProbe::ReservationSubstitution
        | L2HarnessProbe::DefectiveSchema
        | L2HarnessProbe::LingeringHandle
        | L2HarnessProbe::NonzeroLeaseGeneration
        | L2HarnessProbe::ChangedAttemptCeiling
        | L2HarnessProbe::InviterRetryMutation
        | L2HarnessProbe::JoinerRetryMutation
        | L2HarnessProbe::JoinerRetainedKeyPackage => {
            writer.terminate_and_reap()?;
        }
        L2HarnessProbe::MissingAcknowledgement => unreachable!("handled before target advance"),
        L2HarnessProbe::Stall => return Err(stage("L2 checkpoint timeout")),
        L2HarnessProbe::IoFault => return Err(stage("L2 process probe")),
    }
    writer.stdout.require_empty(CHILD_WAIT)?;
    writer.stderr.require_empty(CHILD_WAIT)?;
    if welcome_canary.is_none() {
        welcome_canary = read_optional_welcome_canary(root)?;
    }
    if root.join(WRITER_KEY_NAME).exists() {
        return Err(stage("L2 writer key cleanup"));
    }

    match config.probe {
        L2HarnessProbe::MixedFixture => inject_mixed_group(root, &key, &fixture)?,
        L2HarnessProbe::IdentityLoss => inject_identity_loss(root, &key)?,
        L2HarnessProbe::ReservationSubstitution => {
            inject_reservation_substitution(root, &key, &fixture)?;
        }
        L2HarnessProbe::DefectiveSchema => inject_defective_schema(root, &key)?,
        L2HarnessProbe::NonzeroLeaseGeneration => {
            inject_inviter_lifecycle_defect(root, &key, &fixture, "lease_generation")?;
        }
        L2HarnessProbe::ChangedAttemptCeiling => {
            inject_inviter_lifecycle_defect(root, &key, &fixture, "attempt_ceiling")?;
        }
        L2HarnessProbe::JoinerRetainedKeyPackage => {
            inject_joiner_retained_key_package(root, &key, &fixture)?;
        }
        _ => {}
    }

    write_owned_file(&root.join(VERIFIER_KEY_NAME), key.as_slice(), true)?;
    let mut verifier = ManagedChild::spawn(executable, "verifier", root, false)?;
    let status = match verifier.wait(CHILD_WAIT) {
        Ok(status) => status,
        Err(error) => {
            verifier.terminate_and_reap()?;
            return Err(error);
        }
    };
    if !status.success() {
        return Err(stage("L2 verifier"));
    }
    let stdout = verifier.stdout.collect(CHILD_WAIT)?;
    let stderr = verifier.stderr.collect(CHILD_WAIT)?;
    let expected = config.case()?.expected();
    if !stderr.is_empty() {
        return Err(stage("L2 verifier output"));
    }
    if root.join(VERIFIER_KEY_NAME).exists() {
        return Err(stage("L2 verifier key cleanup"));
    }
    let fixture_cleanup = !root.join(WRITER_CASE_FIXTURE_NAME).exists()
        && !root.join(VERIFIER_CASE_FIXTURE_NAME).exists()
        && !root.join(WELCOME_FIXTURE_NAME).exists();
    if !fixture_cleanup {
        return Err(stage("L2 fixture cleanup"));
    }
    let handle_cleanup = prove_database_handle_cleanup(root)?;
    if config.probe.is_retry_conflict() {
        parse_retry_conflict_evidence(&stdout, expected)?;
        if !handle_cleanup {
            return Err(stage("L2 handle cleanup"));
        }
        return Err(stage("L2 retry conflict confirmed"));
    }
    let verifier_evidence = parse_verifier_evidence(&stdout, expected)?;
    let control_frames = trace
        .cases
        .iter()
        .map(|case| {
            ControlFrame::new_checkpoint(config.target.case_id(), case.checkpoint, case.occurrence)
                .map(ControlFrame::encode)
                .map_err(|_| stage("L2 evidence control frame"))
        })
        .collect::<Result<Vec<_>, _>>()?
        .concat();
    let evidence_binding = collect_evidence_binding(
        root,
        &key,
        &fixture,
        welcome_canary.as_ref().map(|value| value.as_slice()),
        baseline_artifact,
        &[
            stdout.as_slice(),
            stderr.as_slice(),
            control_frames.as_slice(),
        ],
    )?;
    Ok(ControllerEvidence {
        observed: verifier_evidence.observed,
        trace: trace.cases,
        integrity: verifier_evidence.integrity,
        schema: verifier_evidence.schema,
        semantic_oracle: verifier_evidence.semantic_oracle,
        exact_retry: verifier_evidence.exact_retry,
        fixture_cleanup,
        writer_termination: true,
        fresh_verifier: true,
        redaction: true,
        handle_cleanup,
        child_cleanup: true,
        evidence_binding,
    })
}

fn parse_retry_conflict_evidence(
    bytes: &[u8],
    expected: OracleState,
) -> Result<(), SessionCtlError> {
    let text = std::str::from_utf8(bytes).map_err(|_| stage("L2 verifier output"))?;
    let expected_oracle = format!("oracle={}", oracle_label(expected));
    if text.lines().collect::<Vec<_>>()
        != [
            "role=verifier",
            "result=retry-conflict-rejected",
            expected_oracle.as_str(),
            "conflict=exact",
            "mutation_free=pass",
        ]
    {
        return Err(stage("L2 verifier output"));
    }
    Ok(())
}

struct VerifierEvidence {
    observed: OracleState,
    integrity: bool,
    schema: bool,
    semantic_oracle: bool,
    exact_retry: bool,
}

fn parse_verifier_evidence(
    bytes: &[u8],
    expected: OracleState,
) -> Result<VerifierEvidence, SessionCtlError> {
    let text = std::str::from_utf8(bytes).map_err(|_| stage("L2 verifier output"))?;
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != 8
        || lines[0] != "role=verifier"
        || lines[1] != "result=pass"
        || lines[3] != "integrity=pass"
        || lines[4] != "schema=pass"
        || lines[5] != "semantic_oracle=pass"
        || lines[6] != "exclusive_lock=pass"
        || lines[7] != "exact_retry=pass"
    {
        return Err(stage("L2 verifier output"));
    }
    let observed = match lines[2] {
        "oracle=I0" => OracleState::InviterOld,
        "oracle=I1" => OracleState::InviterNew,
        "oracle=J0" => OracleState::JoinerOld,
        "oracle=J1" => OracleState::JoinerNew,
        _ => return Err(stage("L2 verifier output")),
    };
    if observed != expected {
        return Err(stage("L2 verifier output"));
    }
    Ok(VerifierEvidence {
        observed,
        integrity: true,
        schema: true,
        semantic_oracle: true,
        exact_retry: true,
    })
}

fn parse_io_verifier_evidence(
    bytes: &[u8],
    scenario: Scenario,
) -> Result<VerifierEvidence, SessionCtlError> {
    let text = std::str::from_utf8(bytes).map_err(|_| stage("L2 I/O verifier output"))?;
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != 8
        || lines[0] != "role=verifier"
        || lines[1] != "result=pass"
        || lines[3] != "integrity=pass"
        || lines[4] != "schema=pass"
        || lines[5] != "semantic_oracle=pass"
        || lines[6] != "exclusive_lock=pass"
        || lines[7] != "exact_retry=pass"
    {
        return Err(stage("L2 I/O verifier output"));
    }
    let observed = match (scenario, lines[2]) {
        (Scenario::InviterTransaction, "oracle=I0") => OracleState::InviterOld,
        (Scenario::InviterTransaction, "oracle=I1") => OracleState::InviterNew,
        (Scenario::JoinerTransaction, "oracle=J0") => OracleState::JoinerOld,
        (Scenario::JoinerTransaction, "oracle=J1") => OracleState::JoinerNew,
        _ => return Err(stage("L2 I/O verifier output")),
    };
    Ok(VerifierEvidence {
        observed,
        integrity: true,
        schema: true,
        semantic_oracle: true,
        exact_retry: true,
    })
}
