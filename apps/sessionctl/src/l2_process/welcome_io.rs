//! Welcome commit-window kills through the existing named-VFS driver boundary.
use super::welcome::WelcomeWorkload;
use super::*;
use session_transport::WelcomeOutboxPort;

/// Complete baseline-derived Welcome SQLite commit-window evidence.
pub struct WelcomeEngineSweepReport {
    pub(super) cases: Vec<L2EvidenceCase>,
    expected: Vec<String>,
}
impl WelcomeEngineSweepReport {
    /// Bounded, non-public observation of the exact engine-window sweep.
    pub fn encode_v1(&self) -> String {
        format!(
            "version=1\nprotocol=l2-welcome-observation-v1\nscenario=E2E-MSG-002\npublication=prohibited\nstatus=validated\ncoverage=complete\nsweep=welcome-engine-process-kill\nfault_build=true\nstorage_scenario=welcome-delivery\ncompleted_cases={}\nintegrity=pass\nschema=pass\nsemantic_oracle=pass\nexact_retry=pass\nfixture_cleanup=pass\nhandle_cleanup=pass\nchild_cleanup=pass\ndirectory_cleanup=pass\n",
            self.cases.len()
        )
    }
    pub(super) fn validate_coverage(&self) -> Result<(), SessionCtlError> {
        if self.expected.is_empty()
            || self.cases.len() != self.expected.len()
            || self
                .cases
                .iter()
                .zip(&self.expected)
                .any(|(c, key)| &c.key != key || !c.binding.redaction)
        {
            return Err(stage("L2 Welcome engine coverage"));
        }
        Ok(())
    }
}

fn observed_open(root: &Path, key: &[u8; 32]) -> Result<SqlCipherStorage, SessionCtlError> {
    let observer = FaultObserver::new(
        CaseId::new([1; 16]).map_err(|_| stage("L2 Welcome case"))?,
        Scenario::InviterTransaction,
        std::sync::Arc::new(AutoContinueBarrier),
    );
    fault_testing::open_with_fault_vfs(
        &root.join(DATABASE_NAME),
        VaultKey::new(*key).map_err(|_| stage("L2 Welcome key"))?,
        observer,
    )
    .map_err(|_| stage("L2 Welcome engine open"))
}
fn workload(
    storage: &mut SqlCipherStorage,
    root: &Path,
    kind: WelcomeWorkload,
) -> Result<(), SessionCtlError> {
    match kind {
        WelcomeWorkload::Accepted => welcome::coordinate(storage, root, kind.now(), None, false),
        WelcomeWorkload::Failed | WelcomeWorkload::LastFailure => {
            welcome::coordinate(storage, root, kind.now(), None, true)
        }
        _ => storage
            .lease_next(kind.now(), 10)
            .map(|_| ())
            .map_err(|_| stage("L2 Welcome engine lease")),
    }
}
/// Runs only inside the supervised checked test executable with its named-VFS driver.
pub fn run_welcome_engine_child(
    root: &Path,
    driver: &mut impl L2IoPauseDriver,
) -> Result<(), SessionCtlError> {
    validate_root(root)?;
    let (kind, target, _) = welcome::read_config(root)?;
    if target != 254 || !driver.prepare_before_open() {
        return Err(stage("L2 Welcome engine prepare"));
    }
    let key = read_key(root, WRITER_KEY_NAME)?;
    let mut storage = observed_open(root, &key)?;
    if !driver.arm_after_open() {
        return Err(stage("L2 Welcome engine arm"));
    }
    workload(&mut storage, root, kind)?;
    Err(stage("L2 Welcome engine pause escaped"))
}
/// Discovers exact clean counts, then kills one direct child at each supported engine ordinal.
/// The test executable supplies the isolated named-VFS implementation; ordinary binaries do not link it.
pub fn run_welcome_engine_sweep(
    executable: &Path,
    test_executable: &Path,
    driver: &mut impl L2IoFaultDriver,
) -> Result<WelcomeEngineSweepReport, SessionCtlError> {
    let mut cases = Vec::new();
    let mut expected = Vec::new();
    for kind in WelcomeWorkload::ALL {
        let mut root = ProcessRoot::new()?;
        let key = Zeroizing::new(random_nonzero::<32>()?);
        welcome::prepare(root.path(), &key, kind)?;
        if !driver.prepare_before_open() {
            return Err(stage("L2 Welcome engine baseline"));
        }
        let mut storage = observed_open(root.path(), &key)?;
        if !driver.arm_after_open() {
            return Err(stage("L2 Welcome engine baseline"));
        }
        let result = workload(&mut storage, root.path(), kind);
        let observation = driver
            .disable_and_observe(result.is_ok())
            .ok_or_else(|| stage("L2 Welcome engine baseline"))?;
        result?;
        drop(storage);
        root.cleanup()?;
        let L2IoDriverObservation::Baseline(baseline) = observation else {
            return Err(stage("L2 Welcome engine baseline"));
        };
        let targets = baseline
            .targets
            .iter()
            .filter(|t| l2_io_pause_supported(t.file_role, t.operation))
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return Err(stage("L2 Welcome engine baseline empty"));
        }
        for target in targets {
            for ordinal in 0..target.observed_count {
                let case = kill_case(executable, test_executable, kind, *target, ordinal)?;
                expected.push(case.key.clone());
                cases.push(case);
                if cases.len() > 4096 {
                    return Err(stage("L2 Welcome engine matrix bound"));
                }
            }
        }
    }
    expected.sort();
    let cases = canonical_evidence_cases(cases)?;
    let report = WelcomeEngineSweepReport { cases, expected };
    report.validate_coverage()?;
    Ok(report)
}
fn kill_case(
    executable: &Path,
    test_executable: &Path,
    kind: WelcomeWorkload,
    target: L2IoSweepTarget,
    ordinal: u16,
) -> Result<L2EvidenceCase, SessionCtlError> {
    let mut root = ProcessRoot::new()?;
    let path = root.path();
    let key = Zeroizing::new(random_nonzero::<32>()?);
    let fixture = welcome::prepare(path, &key, kind)?;
    let welcome = read_optional_welcome_canary(path)?;
    let baseline = encrypted_artifact_snapshot(path)?;
    let mut config = vec![kind as u8, 254];
    config.extend_from_slice(&random_nonzero::<16>()?);
    write_owned_file(&path.join(welcome::CONFIG), &config, false)?;
    write_owned_file(&path.join(WRITER_KEY_NAME), key.as_slice(), false)?;
    write_owned_file(&path.join(VERIFIER_KEY_NAME), key.as_slice(), false)?;
    let mut command = Command::new(test_executable);
    command
        .args([
            "--exact",
            "checked::welcome_engine_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    sanitize_environment(&mut command);
    command
        .env("SESSION_CHAT_WELCOME_ROOT", path)
        .env("SESSION_CHAT_WELCOME_ROLE", target.file_role.label())
        .env("SESSION_CHAT_WELCOME_OPERATION", target.operation.label())
        .env("SESSION_CHAT_WELCOME_ORDINAL", ordinal.to_string());
    let mut child = ManagedChild::spawn_command(command)?;
    let marker = path.join("welcome.pause");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !marker.exists() {
        if Instant::now() >= deadline {
            return Err(stage("L2 Welcome engine pause timeout"));
        }
        thread::sleep(POLL_INTERVAL);
    }
    let expected = format!(
        "{}:{}:{}\n",
        target.file_role.label(),
        target.operation.label(),
        ordinal
    );
    if read_owned_file(&marker, expected.len())
        .map_err(|_| stage("L2 Welcome engine pause file"))?
        != expected.as_bytes()
    {
        return Err(stage("L2 Welcome engine pause target"));
    }
    child.terminate_and_reap()?;
    let stdout = child.stdout.collect(CHILD_WAIT)?;
    let stderr = child.stderr.collect(CHILD_WAIT)?;
    drop(child);
    if !stderr.is_empty() {
        return Err(stage("L2 Welcome engine diagnostic"));
    }
    let mut verifier = ManagedChild::spawn(executable, "welcome-verifier", path, false)?;
    if !verifier.wait(CASE_WAIT)?.success() {
        return Err(stage("L2 Welcome engine verifier"));
    }
    let output = verifier.stdout.collect(CHILD_WAIT)?;
    verifier.stderr.require_empty(CHILD_WAIT)?;
    drop(verifier);
    let observed = welcome::verified_state(&output)?;
    prove_database_handle_cleanup(path)?;
    let binding = collect_evidence_binding(
        path,
        &key,
        &fixture,
        welcome.as_ref().map(|v| v.as_slice()),
        baseline,
        &[&stdout, &stderr, &output],
    )?;
    let report = L2EvidenceCase {
        key: format!(
            "welcome-engine-{}-{}-{}-{ordinal:04}",
            kind as u8,
            target.file_role.label(),
            target.operation.label()
        ),
        target: L2EvidenceCaseTarget::CommitWindowProcessKill {
            file_role: target.file_role.label(),
            operation: target.operation.label(),
            ordinal,
            last_fully_explored_ordinal: target.observed_count - 1,
            expected: match kind {
                WelcomeWorkload::Accepted => "PENDING|LEASED|DELIVERED",
                WelcomeWorkload::Failed | WelcomeWorkload::Lease => "PENDING|LEASED",
                WelcomeWorkload::Release => "LEASED",
                WelcomeWorkload::Exhausted => "LEASED|EXHAUSTED",
                WelcomeWorkload::Expired => "LEASED|EXPIRED",
                WelcomeWorkload::LastFailure => "PENDING|LEASED|EXHAUSTED",
            },
            observed,
        },
        binding,
    };
    root.cleanup()?;
    Ok(report)
}
