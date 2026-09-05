//! Bounded Welcome-owner process-kill evidence; no production activation path.
use super::*;
use session_transport::{
    CoordinatorPolicy, DepositReceipt, DepositRequest, DepositRight, DispatchControl,
    EnvelopeDeposit, LocalV1DepositEndpointResolver, RetryAdvice, TransportFailure,
    TransportFailureCode, WelcomeDeliveryCoordinator, WelcomeOutboxPort,
};
use std::sync::{Arc, Mutex};
use storage_sqlcipher::fault_testing::{WelcomeBarrier, WelcomeCheckpoint};

pub(super) const CONFIG: &str = "welcome.config";
pub(super) const BASELINE: &str = "baseline.sqlite3";
const LEASE_SECONDS: u64 = 10;
pub(super) const FRAME_BYTES: usize = 24;
const MAX_STEPS: usize = 8;

/// Closed Welcome workloads. Time is supplied; no wall-clock sleeps decide leases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WelcomeWorkload {
    /// First lease acquisition.
    Lease = 1,
    /// Coordinator deposit acceptance and local result.
    Accepted = 2,
    /// Coordinator deposit failure and retryable result.
    Failed = 3,
    /// Expired first lease replaced once.
    Release = 4,
    /// Last attempt expires and acquisition terminalizes it.
    Exhausted = 5,
    /// Outbox lifetime expires and acquisition terminalizes it.
    Expired = 6,
    /// Last permitted adapter failure becomes terminal.
    LastFailure = 7,
}
impl WelcomeWorkload {
    /// Complete closed workload set for this evidence version.
    pub const ALL: [Self; 7] = [
        Self::Lease,
        Self::Accepted,
        Self::Failed,
        Self::Release,
        Self::Exhausted,
        Self::Expired,
        Self::LastFailure,
    ];
    fn decode(code: u8) -> Result<Self, SessionCtlError> {
        Self::ALL
            .into_iter()
            .find(|v| *v as u8 == code)
            .ok_or_else(|| stage("L2 Welcome workload"))
    }
    fn trace(self) -> &'static [u8] {
        match self {
            Self::Lease | Self::Release => &[1, 2, 3, 4, 5],
            Self::Accepted => &[1, 2, 3, 4, 5, 10, 6, 7],
            Self::Failed | Self::LastFailure => &[1, 2, 3, 4, 5, 11, 8, 9],
            Self::Exhausted | Self::Expired => &[1, 4, 5],
        }
    }
    pub(super) fn now(self) -> u64 {
        match self {
            Self::Release | Self::Exhausted => BASELINE_NOW + LEASE_SECONDS,
            Self::Expired => OUTBOX_EXPIRES_AT,
            _ => BASELINE_NOW,
        }
    }
}

/// Sealed report: only the complete controller sweep can construct it.
pub struct WelcomeSweepReport {
    pub(super) cases: Vec<L2EvidenceCase>,
}
impl WelcomeSweepReport {
    pub(super) fn validate_coverage(&self) -> Result<(), SessionCtlError> {
        let mut expected = WelcomeWorkload::ALL
            .iter()
            .flat_map(|w| (0..w.trace().len()).map(move |i| format!("welcome-{}-{i}", *w as u8)))
            .collect::<Vec<_>>();
        expected.sort();
        if self.cases.len() != expected.len()
            || self
                .cases
                .iter()
                .zip(expected)
                .any(|(case, key)| case.key != key || !case.binding.redaction)
        {
            return Err(stage("L2 Welcome matrix coverage"));
        }
        Ok(())
    }

    /// Number of verified, killed checkpoint occurrences.
    pub fn completed_cases(&self) -> usize {
        self.cases.len()
    }
    /// Bounded non-public aggregate; public promotion separately requires CI provenance.
    pub fn encode_v1(&self) -> String {
        format!(
            "version=1\nprotocol=l2-welcome-observation-v1\nscenario=E2E-MSG-002\npublication=prohibited\nstatus=validated\ncoverage=complete\nsweep=welcome-process-kill\nfault_build=true\nstorage_scenario=welcome-delivery\ncompleted_cases={}\nintegrity=pass\nschema=pass\nsemantic_oracle=pass\nexact_retry=pass\nfixture_cleanup=pass\nhandle_cleanup=pass\nchild_cleanup=pass\ndirectory_cleanup=pass\n",
            self.cases.len()
        )
    }
}

/// Discovers each clean workload trace, kills every observed barrier, and verifies afresh.
pub fn run_welcome_sweep(executable: &Path) -> Result<WelcomeSweepReport, SessionCtlError> {
    let mut cases = Vec::new();
    for workload in WelcomeWorkload::ALL {
        let baseline = run_case(executable, workload, None, false)?;
        if baseline.0 != workload.trace() || baseline.0.len() > MAX_STEPS {
            return Err(stage("L2 Welcome baseline coverage"));
        }
        for index in 0..baseline.0.len() {
            let (trace, case) = run_case(executable, workload, Some(index), false)?;
            if trace != baseline.0[..=index] {
                return Err(stage("L2 Welcome prefix coverage"));
            }
            cases.push(case);
        }
    }
    let cases = canonical_evidence_cases(cases)?;
    if cases.len()
        != WelcomeWorkload::ALL
            .iter()
            .map(|w| w.trace().len())
            .sum::<usize>()
    {
        return Err(stage("L2 Welcome matrix coverage"));
    }
    let report = WelcomeSweepReport { cases };
    report.validate_coverage()?;
    Ok(report)
}

/// Deliberately corrupts a valid-schema immutable row before the fresh verifier.
pub fn run_welcome_defective_oracle_probe(executable: &Path) -> Result<(), SessionCtlError> {
    run_case(executable, WelcomeWorkload::Accepted, Some(5), true).map(|_| ())
}

fn frame(
    case: &[u8; 16],
    workload: WelcomeWorkload,
    index: usize,
    event: u8,
    ack: bool,
) -> [u8; FRAME_BYTES] {
    let mut bytes = [0; FRAME_BYTES];
    bytes[..4].copy_from_slice(b"WLK1");
    bytes[4] = workload as u8;
    bytes[5] = index as u8;
    bytes[6] = event;
    bytes[7] = u8::from(ack);
    bytes[8..].copy_from_slice(case);
    bytes
}
pub(super) struct Barrier {
    case: [u8; 16],
    workload: WelcomeWorkload,
    index: Mutex<usize>,
}
impl Barrier {
    fn emit(&self, event: u8) -> Result<(), BarrierFailure> {
        let mut index = self.index.lock().map_err(|_| BarrierFailure::Rejected)?;
        if self.workload.trace().get(*index) != Some(&event) {
            return Err(BarrierFailure::Rejected);
        }
        let bytes = frame(&self.case, self.workload, *index, event, false);
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(&bytes)
            .and_then(|()| stdout.flush())
            .map_err(|_| BarrierFailure::Rejected)?;
        let mut reply = [0; FRAME_BYTES];
        std::io::stdin()
            .lock()
            .read_exact(&mut reply)
            .map_err(|_| BarrierFailure::Rejected)?;
        if reply != frame(&self.case, self.workload, *index, event, true) {
            return Err(BarrierFailure::Rejected);
        }
        *index += 1;
        Ok(())
    }
}
impl WelcomeBarrier for Barrier {
    fn checkpoint(&self, point: WelcomeCheckpoint) -> Result<(), BarrierFailure> {
        self.emit(point as u8)
    }
}
struct Control {
    now: u64,
    start: Instant,
}
impl DispatchControl for Control {
    fn monotonic_now(&self) -> Instant {
        self.start
    }
    fn wall_now_unix_seconds(&self) -> Option<u64> {
        Some(self.now)
    }
    fn is_cancelled(&self) -> bool {
        false
    }
}
// This test adapter compares the actual coordinator's output with the closed baseline.
// Acceptance is intentionally simulated; it is not an offline/network provider.
struct Adapter {
    expected: Zeroizing<Vec<u8>>,
    barrier: Option<Arc<Barrier>>,
    fail: bool,
}
impl EnvelopeDeposit for Adapter {
    type DepositEndpoint = LocalWelcomeDepositEndpoint;
    async fn deposit(
        &mut self,
        endpoint: &DepositRight<Self::DepositEndpoint>,
        request: DepositRequest,
        control: &dyn DispatchControl,
    ) -> Result<DepositReceipt, TransportFailure> {
        let failure = || TransportFailure::new(TransportFailureCode::Internal, RetryAdvice::Never);
        control.checkpoint(request.budget())?;
        if request.envelope().as_bytes() != self.expected.as_slice()
            || endpoint
                .provider()
                .encode_canonical()
                .map_err(|_| failure())?
                != fixture_endpoint().map_err(|_| failure())?
        {
            return Err(failure());
        }
        if let Some(barrier) = &self.barrier {
            barrier
                .emit(if self.fail { 11 } else { 10 })
                .map_err(|_| failure())?;
        }
        if self.fail {
            return Err(failure());
        }
        Ok(DepositReceipt::accepted(
            session_transport::DeliveryId::from_provider_bytes([1; 16]).ok_or_else(failure)?,
        ))
    }
}
pub(super) fn coordinate(
    storage: &mut SqlCipherStorage,
    root: &Path,
    now: u64,
    barrier: Option<Arc<Barrier>>,
    fail: bool,
) -> Result<(), SessionCtlError> {
    let expected = Zeroizing::new(read_bounded_owned_file(
        &root.join(WELCOME_FIXTURE_NAME),
        65_536,
    )?);
    let mut adapter = Adapter {
        expected,
        barrier,
        fail,
    };
    let control = Control {
        now,
        start: Instant::now(),
    };
    let coordinator = WelcomeDeliveryCoordinator::new(
        CoordinatorPolicy::new(Duration::from_secs(1), LEASE_SECONDS, 65_536)
            .map_err(|_| stage("L2 Welcome policy"))?,
    );
    let mut resolver = LocalV1DepositEndpointResolver;
    let mut future =
        std::pin::pin!(coordinator.run_once(storage, &mut resolver, &mut adapter, &control));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match std::future::Future::poll(future.as_mut(), &mut context) {
        std::task::Poll::Ready(Ok(session_transport::CoordinatorOutcome::Accepted)) if !fail => {
            Ok(())
        }
        std::task::Poll::Ready(Err(session_transport::CoordinatorError::Transport(_))) if fail => {
            Ok(())
        }
        _ => Err(stage("L2 Welcome coordinator")),
    }
}
fn open(root: &Path, key: &[u8; 32]) -> Result<SqlCipherStorage, SessionCtlError> {
    SqlCipherStorage::open(
        &root.join(DATABASE_NAME),
        VaultKey::new(*key).map_err(|_| stage("L2 Welcome key"))?,
    )
    .map_err(|_| stage("L2 Welcome open"))
}
pub(super) fn prepare(
    root: &Path,
    key: &Zeroizing<[u8; 32]>,
    workload: WelcomeWorkload,
) -> Result<CaseFixture, SessionCtlError> {
    let fixture = prepare_baseline(root, key, Scenario::InviterTransaction)?;
    let observer = FaultObserver::new(
        CaseId::new([1; 16]).map_err(|_| stage("L2 Welcome case"))?,
        Scenario::InviterTransaction,
        Arc::new(AutoContinueBarrier),
    );
    let storage = fault_testing::open(
        &root.join(DATABASE_NAME),
        VaultKey::new(**key).map_err(|_| stage("L2 Welcome key"))?,
        observer.clone(),
    )
    .map_err(|_| stage("L2 Welcome baseline open"))?;
    run_real_storage_transaction(
        &storage,
        observer,
        Scenario::InviterTransaction,
        &fixture,
        root,
    )?;
    let mut owner = storage.clone();
    let attempts = match workload {
        WelcomeWorkload::Release | WelcomeWorkload::Expired => 1,
        WelcomeWorkload::Exhausted => MAXIMUM_WELCOME_DELIVERY_ATTEMPTS,
        WelcomeWorkload::LastFailure => MAXIMUM_WELCOME_DELIVERY_ATTEMPTS - 1,
        _ => 0,
    };
    for attempt in 0..attempts {
        let lease = owner
            .lease_next(BASELINE_NOW, LEASE_SECONDS)
            .map_err(|_| stage("L2 Welcome setup"))?
            .ok_or_else(|| stage("L2 Welcome setup"))?
            .discard_payload();
        if attempt + 1 < attempts || workload == WelcomeWorkload::LastFailure {
            owner
                .report_failed(lease)
                .map_err(|_| stage("L2 Welcome setup"))?;
        }
    }
    drop(owner);
    drop(storage);
    let bytes = Zeroizing::new(read_bounded_owned_file(
        &root.join(DATABASE_NAME),
        MAX_DATABASE_BYTES,
    )?);
    write_bounded_owned_file(&root.join(BASELINE), &bytes, true, MAX_DATABASE_BYTES)?;
    Ok(fixture)
}
pub(super) fn read_config(
    root: &Path,
) -> Result<(WelcomeWorkload, usize, [u8; 16]), SessionCtlError> {
    let data = read_owned_file(&root.join(CONFIG), 18)?;
    let workload = WelcomeWorkload::decode(data[0])?;
    let target = usize::from(data[1]);
    if target != 255 && target != 254 && target >= workload.trace().len() {
        return Err(stage("L2 Welcome target"));
    }
    let id = data[2..]
        .try_into()
        .map_err(|_| stage("L2 Welcome config"))?;
    Ok((workload, target, id))
}
pub(super) fn writer(root: &Path) -> Result<(), SessionCtlError> {
    let (workload, _, case) = read_config(root)?;
    let key = read_key(root, WRITER_KEY_NAME)?;
    let mut storage = open(root, &key)?;
    let barrier = Arc::new(Barrier {
        case,
        workload,
        index: Mutex::new(0),
    });
    fault_testing::observe_welcome(&storage, barrier.clone())
        .map_err(|_| stage("L2 Welcome observer"))?;
    match workload {
        WelcomeWorkload::Accepted => {
            coordinate(&mut storage, root, workload.now(), Some(barrier), false)
        }
        WelcomeWorkload::Failed | WelcomeWorkload::LastFailure => {
            coordinate(&mut storage, root, workload.now(), Some(barrier), true)
        }
        _ => storage
            .lease_next(workload.now(), LEASE_SECONDS)
            .map(|_| ())
            .map_err(|_| stage("L2 Welcome lease")),
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Row {
    state: i64,
    attempts: i64,
    generation: i64,
    id: Option<Vec<u8>>,
    expiry: Option<i64>,
}
fn recovery_time(workload: WelcomeWorkload, actual: &Row) -> u64 {
    workload.now().max(actual.expiry.map_or(0, |v| v as u64))
}
fn expected_recovery(actual: &Row, now: u64) -> Row {
    let mut expected = actual.clone();
    if matches!(actual.state, 1 | 2) {
        expected.id = None;
        expected.expiry = None;
        if now >= OUTBOX_EXPIRES_AT {
            expected.state = 5;
        } else if actual.attempts >= i64::from(MAXIMUM_WELCOME_DELIVERY_ATTEMPTS) {
            expected.state = 4;
        } else {
            expected.state = 3;
            expected.attempts += 1;
            expected.generation += 1;
        }
    }
    expected
}
fn validate_recovery(actual: &Row, recovered: &Row, now: u64) -> Result<(), SessionCtlError> {
    if *recovered != expected_recovery(actual, now) {
        return Err(stage("L2 Welcome recovery transition"));
    }
    Ok(())
}
fn row(connection: &Connection) -> Result<Row, SessionCtlError> {
    if table_count(connection, "inviter_joins")? != 1 {
        return Err(stage("L2 Welcome cardinality"));
    }
    connection.query_row("SELECT outbox_state,delivery_attempts,lease_generation,lease_id,lease_expires_at FROM inviter_joins",[],|r|Ok(Row{state:r.get(0)?,attempts:r.get(1)?,generation:r.get(2)?,id:r.get(3)?,expiry:r.get(4)?})).map_err(|_|stage("L2 Welcome row"))
}
// Compare every stored field except the five explicitly mutable lease/result columns.
fn immutable(connection: &Connection) -> Result<Vec<Vec<rusqlite::types::Value>>, SessionCtlError> {
    let mut all = Vec::new();
    for table in [
        "storage_metadata",
        "reservations",
        "inviter_joins",
        "mls_groups",
        "mls_epochs",
        "key_packages",
        "joiner_commits",
        "mls_client_identity",
        "invitation_opening_contexts",
        "authorization_attempts",
    ] {
        let exists: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |r| r.get(0),
            )
            .map_err(|_| stage("L2 Welcome schema"))?;
        if exists == 0 {
            continue;
        }
        let mut info = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(|_| stage("L2 Welcome schema"))?;
        let names = info
            .query_map([], |r| r.get::<_, String>(1))
            .map_err(|_| stage("L2 Welcome schema"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| stage("L2 Welcome schema"))?;
        let names = names
            .into_iter()
            .filter(|name| {
                table != "inviter_joins"
                    || ![
                        "outbox_state",
                        "delivery_attempts",
                        "lease_generation",
                        "lease_id",
                        "lease_expires_at",
                    ]
                    .contains(&name.as_str())
            })
            .collect::<Vec<_>>();
        let mut statement = connection
            .prepare(&format!(
                "SELECT {} FROM {table} ORDER BY 1",
                names.join(",")
            ))
            .map_err(|_| stage("L2 Welcome immutable"))?;
        let rows = statement
            .query_map([], |r| {
                (0..names.len())
                    .map(|i| r.get(i))
                    .collect::<Result<Vec<rusqlite::types::Value>, _>>()
            })
            .map_err(|_| stage("L2 Welcome immutable"))?;
        for record in rows {
            all.push(record.map_err(|_| stage("L2 Welcome immutable"))?);
        }
        if all.len() > 256 {
            return Err(stage("L2 Welcome immutable bound"));
        }
    }
    Ok(all)
}
pub(super) fn verifier(root: &Path) -> Result<(), SessionCtlError> {
    let (workload, target, _) = read_config(root)?;
    let key = read_key(root, VERIFIER_KEY_NAME)?;
    let mut storage = open(root, &key)?;
    if storage
        .schema_version()
        .map_err(|_| stage("L2 Welcome schema"))?
        != EXPECTED_SCHEMA_VERSION
        || !storage
            .integrity_check()
            .map_err(|_| stage("L2 Welcome integrity"))?
    {
        return Err(stage("L2 Welcome integrity"));
    }
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), &key)?;
    let baseline = open_keyed_connection(&root.join(BASELINE), &key)?;
    if schema_fingerprint(&connection)? != SCHEMA_FINGERPRINT_SHA256
        || immutable(&connection)? != immutable(&baseline)?
    {
        return Err(stage("L2 Welcome immutable"));
    }
    let old = row(&baseline)?;
    let actual = row(&connection)?;
    let event = if target == 254 {
        match actual.state {
            3 => 7,
            1 if actual.attempts > old.attempts => 9,
            4 if workload == WelcomeWorkload::LastFailure => 9,
            _ => 5,
        }
    } else if target == 255 {
        *workload
            .trace()
            .last()
            .ok_or_else(|| stage("L2 Welcome trace"))?
    } else {
        workload.trace()[target]
    };
    let committed = if target == 254 {
        actual != old
    } else {
        target == 255
            || match workload {
                WelcomeWorkload::Accepted
                | WelcomeWorkload::Failed
                | WelcomeWorkload::LastFailure => target >= 4,
                _ => event == 5,
            }
    };
    if !committed {
        if actual != old {
            return Err(stage("L2 Welcome rollback"));
        }
    } else {
        // SQL values: Pending=1, Leased=2, Delivered=3, Exhausted=4, Expired=5.
        let state = match workload {
            WelcomeWorkload::Exhausted => 4,
            WelcomeWorkload::Expired => 5,
            WelcomeWorkload::Accepted if event == 7 => 3,
            WelcomeWorkload::Failed if event == 9 => 1,
            WelcomeWorkload::LastFailure if event == 9 => 4,
            _ => 2,
        };
        let terminal_housekeeping = matches!(
            workload,
            WelcomeWorkload::Exhausted | WelcomeWorkload::Expired
        );
        let increment = i64::from(!terminal_housekeeping);
        if actual.state != state
            || actual.attempts != old.attempts + increment
            || actual.generation != old.generation + increment
        {
            return Err(stage("L2 Welcome transition"));
        }
        if state == 2 {
            if actual
                .id
                .as_ref()
                .is_none_or(|id| id.len() != 16 || id.iter().all(|b| *b == 0))
                || actual.id == old.id
                || actual.expiry != Some((workload.now() + LEASE_SECONDS) as i64)
            {
                return Err(stage("L2 Welcome lease identity"));
            }
        } else if actual.id.is_some() || actual.expiry.is_some() {
            return Err(stage("L2 Welcome terminal lease"));
        }
    }
    let before = immutable(&connection)?;
    drop(connection);
    drop(baseline);
    if actual.state == 2
        && actual
            .expiry
            .is_some_and(|expiry| expiry as u64 > workload.now())
    {
        let snapshot = database_digest(root)?;
        if storage
            .lease_next(
                actual.expiry.ok_or_else(|| stage("L2 Welcome expiry"))? as u64 - 1,
                LEASE_SECONDS,
            )
            .map_err(|_| stage("L2 Welcome live lease"))?
            .is_some()
            || database_digest(root)? != snapshot
        {
            return Err(stage("L2 Welcome premature release"));
        }
    }
    let now = recovery_time(workload, &actual);
    if now < OUTBOX_EXPIRES_AT
        && actual.attempts < i64::from(MAXIMUM_WELCOME_DELIVERY_ATTEMPTS)
        && matches!(actual.state, 1 | 2)
    {
        coordinate(&mut storage, root, now, None, false)?;
    } else {
        if storage
            .lease_next(now, LEASE_SECONDS)
            .map_err(|_| stage("L2 Welcome terminal"))?
            .is_some()
        {
            return Err(stage("L2 Welcome resurrection"));
        }
    }
    if workload == WelcomeWorkload::Lease {
        reject_stale_results(root, &key, &mut storage)?;
    }
    drop(storage);
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), &key)?;
    validate_recovery(&actual, &row(&connection)?, now)?;
    if immutable(&connection)? != before {
        return Err(stage("L2 Welcome retry mutation"));
    }
    drop(connection);
    println!(
        "welcome=verified\nimmutable=pass\nretry=pass\nstate={}",
        state_label(actual.state)?
    );
    Ok(())
}

fn reject_stale_results(
    root: &Path,
    key: &Zeroizing<[u8; 32]>,
    other: &mut SqlCipherStorage,
) -> Result<(), SessionCtlError> {
    let path = root.join(BASELINE);
    let mut owner = SqlCipherStorage::open(
        &path,
        VaultKey::new(**key).map_err(|_| stage("L2 Welcome key"))?,
    )
    .map_err(|_| stage("L2 Welcome stale open"))?;
    let old = owner
        .lease_next(BASELINE_NOW, 10)
        .map_err(|_| stage("L2 Welcome stale lease"))?
        .ok_or_else(|| stage("L2 Welcome stale lease"))?
        .discard_payload();
    let current = owner
        .lease_next(BASELINE_NOW + 10, 10)
        .map_err(|_| stage("L2 Welcome release"))?
        .ok_or_else(|| stage("L2 Welcome release"))?
        .discard_payload();
    let snapshot = row(&open_keyed_connection(&path, key)?)?;
    if owner.report_accepted(old, BASELINE_NOW + 11).is_ok()
        || row(&open_keyed_connection(&path, key)?)? != snapshot
    {
        return Err(stage("L2 Welcome stale result"));
    }
    let other_before = database_digest(root)?;
    if other.report_failed(current).is_ok() || database_digest(root)? != other_before {
        return Err(stage("L2 Welcome foreign result"));
    }
    let late = owner
        .lease_next(BASELINE_NOW + 20, 10)
        .map_err(|_| stage("L2 Welcome lease"))?
        .ok_or_else(|| stage("L2 Welcome lease"))?
        .discard_payload();
    drop(owner);
    let mut reopened = SqlCipherStorage::open(
        &path,
        VaultKey::new(**key).map_err(|_| stage("L2 Welcome key"))?,
    )
    .map_err(|_| stage("L2 Welcome reopen"))?;
    let snapshot = row(&open_keyed_connection(&path, key)?)?;
    if reopened.report_failed(late).is_ok() || row(&open_keyed_connection(&path, key)?)? != snapshot
    {
        return Err(stage("L2 Welcome old open result"));
    }
    Ok(())
}

fn state_label(state: i64) -> Result<&'static str, SessionCtlError> {
    match state {
        1 => Ok("PENDING"),
        2 => Ok("LEASED"),
        3 => Ok("DELIVERED"),
        4 => Ok("EXHAUSTED"),
        5 => Ok("EXPIRED"),
        _ => Err(stage("L2 Welcome state")),
    }
}
pub(super) fn verified_state(output: &[u8]) -> Result<&'static str, SessionCtlError> {
    for state in 1..=5 {
        let label = state_label(state)?;
        if output
            == format!("welcome=verified\nimmutable=pass\nretry=pass\nstate={label}\n").as_bytes()
        {
            return Ok(label);
        }
    }
    Err(stage("L2 Welcome verifier output"))
}

fn run_case(
    executable: &Path,
    workload: WelcomeWorkload,
    target: Option<usize>,
    defect: bool,
) -> Result<(Vec<u8>, L2EvidenceCase), SessionCtlError> {
    let mut root = ProcessRoot::new()?;
    let path = root.path();
    let key = Zeroizing::new(random_nonzero::<32>()?);
    let case = random_nonzero::<16>()?;
    let fixture = prepare(path, &key, workload)?;
    let welcome = read_optional_welcome_canary(path)?;
    let baseline = encrypted_artifact_snapshot(path)?;
    let mut config = vec![workload as u8, target.map_or(255, |i| i as u8)];
    config.extend_from_slice(&case);
    write_owned_file(&path.join(CONFIG), &config, false)?;
    write_owned_file(&path.join(WRITER_KEY_NAME), key.as_slice(), false)?;
    write_owned_file(&path.join(VERIFIER_KEY_NAME), key.as_slice(), false)?;
    let mut writer = ManagedChild::spawn(executable, "welcome-writer", path, true)?;
    let mut trace = Vec::new();
    let mut transcript = Vec::new();
    for (index, event) in workload.trace().iter().copied().enumerate() {
        let bytes = writer.stdout.read_exact_frame(FRAME_BYTES, CASE_WAIT)?;
        if bytes != frame(&case, workload, index, event, false) {
            return Err(stage("L2 Welcome frame"));
        }
        trace.push(event);
        transcript.extend_from_slice(&bytes);
        if target == Some(index) {
            writer.terminate_and_reap()?;
            break;
        }
        writer.write_stdin(&frame(&case, workload, index, event, true))?;
    }
    if target.is_none() {
        writer.close_stdin();
        if !writer.wait(CHILD_WAIT)?.success() {
            return Err(stage("L2 Welcome writer"));
        }
    }
    writer.stdout.require_empty(CHILD_WAIT)?;
    writer.stderr.require_empty(CHILD_WAIT)?;
    drop(writer);
    if defect {
        inject_retry_mutation(path, &key, &fixture, Scenario::InviterTransaction)?;
    }
    let mut verifier = ManagedChild::spawn(executable, "welcome-verifier", path, false)?;
    if !verifier.wait(CASE_WAIT)?.success() {
        return Err(stage("L2 Welcome verifier"));
    }
    let output = verifier.stdout.collect(CHILD_WAIT)?;
    verifier.stderr.require_empty(CHILD_WAIT)?;
    let observed = verified_state(&output)?;
    let committed = target.is_none_or(|i| workload.trace()[..=i].contains(&5));
    let last = target.map_or(
        *workload
            .trace()
            .last()
            .ok_or_else(|| stage("L2 Welcome trace"))?,
        |i| workload.trace()[i],
    );
    let expected = if !committed {
        match workload {
            WelcomeWorkload::Release | WelcomeWorkload::Exhausted | WelcomeWorkload::Expired => {
                "LEASED"
            }
            _ => "PENDING",
        }
    } else {
        match workload {
            WelcomeWorkload::Exhausted => "EXHAUSTED",
            WelcomeWorkload::Expired => "EXPIRED",
            WelcomeWorkload::Accepted if last == 7 => "DELIVERED",
            WelcomeWorkload::Failed if last == 9 => "PENDING",
            WelcomeWorkload::LastFailure if last == 9 => "EXHAUSTED",
            _ => "LEASED",
        }
    };
    if observed != expected {
        return Err(stage("L2 Welcome observed state"));
    }
    drop(verifier);
    prove_database_handle_cleanup(path)?;
    let binding = collect_evidence_binding(
        path,
        &key,
        &fixture,
        welcome.as_ref().map(|v| v.as_slice()),
        baseline,
        &[&transcript, &output],
    )?;
    let evidence = L2EvidenceCase {
        key: format!("welcome-{}-{}", workload as u8, target.unwrap_or(255)),
        target: L2EvidenceCaseTarget::ApplicationCheckpoint {
            checkpoint: "WELCOME_OWNER",
            ordinal: target.unwrap_or(255) as u16,
            expected,
            observed,
        },
        binding,
    };
    root.cleanup()?;
    Ok((trace, evidence))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expired_recovery_rejects_delivery_attempts_and_clock_rewind() {
        let old = Row {
            state: 2,
            attempts: 1,
            generation: 1,
            id: Some(vec![1; 16]),
            expiry: Some((BASELINE_NOW + LEASE_SECONDS) as i64),
        };
        let now = recovery_time(WelcomeWorkload::Expired, &old);
        assert_eq!(now, OUTBOX_EXPIRES_AT);
        let expired = Row {
            state: 5,
            id: None,
            expiry: None,
            ..old.clone()
        };
        validate_recovery(&old, &expired, now).expect("expiry without another attempt");
        // The pre-fix oracle delivered at the old lease expiry. That complete
        // but incorrect tuple must fail against the workload's observed time.
        let delivered = Row {
            state: 3,
            attempts: 2,
            generation: 2,
            ..expired.clone()
        };
        assert!(validate_recovery(&old, &delivered, now).is_err());
        for invalid in [
            Row {
                attempts: 2,
                ..expired.clone()
            },
            Row {
                generation: 2,
                ..expired.clone()
            },
            Row {
                id: old.id.clone(),
                ..expired.clone()
            },
            Row {
                expiry: old.expiry,
                ..expired.clone()
            },
        ] {
            assert!(validate_recovery(&old, &invalid, now).is_err());
        }
        validate_recovery(
            &old,
            &delivered,
            recovery_time(WelcomeWorkload::Release, &old),
        )
        .expect("one eligible retry has an exact accepted tuple");
    }
    fn complete_fixture() -> WelcomeSweepReport {
        let cases = WelcomeWorkload::ALL
            .iter()
            .flat_map(|workload| {
                (0..workload.trace().len()).map(move |index| L2EvidenceCase {
                    key: format!("welcome-{}-{index}", *workload as u8),
                    target: L2EvidenceCaseTarget::ApplicationCheckpoint {
                        checkpoint: "WELCOME_OWNER",
                        ordinal: index as u16,
                        expected: "W1",
                        observed: "W1",
                    },
                    binding: L2EvidenceBinding {
                        sqlcipher_version: "4.0".into(),
                        sqlite_version: "3.0".into(),
                        baseline_artifact_digest: [1; 32],
                        post_recovery_artifact_digest: [2; 32],
                        redaction: true,
                    },
                })
            })
            .collect();
        WelcomeSweepReport {
            cases: canonical_evidence_cases(cases).expect("canonical"),
        }
    }
    #[test]
    fn welcome_coverage_rejects_missing_duplicate_and_unscanned_cases() {
        let mut report = complete_fixture();
        report.validate_coverage().expect("complete");
        report.cases.pop();
        assert!(report.validate_coverage().is_err());
        let mut report = complete_fixture();
        report.cases[1] = report.cases[0].clone();
        assert!(report.validate_coverage().is_err());
        let mut report = complete_fixture();
        report.cases[0].binding.redaction = false;
        assert!(report.validate_coverage().is_err());
    }
    #[test]
    fn welcome_control_frame_has_an_exact_versioned_fixture_and_acknowledgement() {
        let mut expected = [0x12; 24];
        expected[..8].copy_from_slice(&[b'W', b'L', b'K', b'1', 2, 5, 10, 0]);
        assert_eq!(
            frame(&[0x12; 16], WelcomeWorkload::Accepted, 5, 10, false),
            expected
        );
        expected[7] = 1;
        assert_eq!(
            frame(&[0x12; 16], WelcomeWorkload::Accepted, 5, 10, true),
            expected
        );
        assert!(WelcomeWorkload::decode(0).is_err());
        assert!(WelcomeWorkload::decode(8).is_err());
    }
}
