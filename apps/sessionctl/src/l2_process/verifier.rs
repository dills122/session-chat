//! Fresh-process L2 verifier and complete-state oracle.

use super::*;

pub(super) fn run_verifier(root: &Path) -> Result<(), SessionCtlError> {
    let config = read_case_config(root)?;
    let fixture = read_fixture(root, VERIFIER_CASE_FIXTURE_NAME)?;
    let key = read_key(root, VERIFIER_KEY_NAME)?;
    let expected = if config.probe == L2HarnessProbe::IoFault {
        classify_io_oracle_state(root, &key, config.target.scenario(), &fixture)?
    } else {
        config.case()?.expected()
    };
    let outcome = verify_complete_state(
        root,
        &key,
        expected,
        config.target.checkpoint(),
        &fixture,
        config.probe,
    )?;
    if config.probe == L2HarnessProbe::LingeringHandle {
        let _connection = open_keyed_connection(&root.join(DATABASE_NAME), &key)?;
        thread::sleep(Duration::from_secs(10));
        return Err(stage("L2 lingering verifier"));
    }
    match outcome {
        VerificationOutcome::Complete => print!(
            "role=verifier\nresult=pass\noracle={}\nintegrity=pass\nschema=pass\nsemantic_oracle=pass\nexclusive_lock=pass\nexact_retry=pass\n",
            oracle_label(expected)
        ),
        VerificationOutcome::RetryConflict => print!(
            "role=verifier\nresult=retry-conflict-rejected\noracle={}\nconflict=exact\nmutation_free=pass\n",
            oracle_label(expected)
        ),
    }
    Ok(())
}

fn classify_io_oracle_state(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    scenario: Scenario,
    fixture: &CaseFixture,
) -> Result<OracleState, SessionCtlError> {
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;
    let table = match scenario {
        Scenario::InviterTransaction => "inviter_joins",
        Scenario::JoinerTransaction => "joiner_commits",
    };
    let sql = format!("SELECT count(*) FROM {table} WHERE transaction_id = ?1");
    let count: i64 = connection
        .query_row(&sql, params![fixture.transaction_id], |row| row.get(0))
        .map_err(|_| stage("L2 I/O oracle classification"))?;
    match (scenario, count) {
        (Scenario::InviterTransaction, 0) => Ok(OracleState::InviterOld),
        (Scenario::InviterTransaction, 1) => Ok(OracleState::InviterNew),
        (Scenario::JoinerTransaction, 0) => Ok(OracleState::JoinerOld),
        (Scenario::JoinerTransaction, 1) => Ok(OracleState::JoinerNew),
        _ => Err(stage("L2 I/O oracle classification")),
    }
}

enum VerificationOutcome {
    Complete,
    RetryConflict,
}

fn verify_complete_state(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    expected: OracleState,
    checkpoint: Checkpoint,
    fixture: &CaseFixture,
    probe: L2HarnessProbe,
) -> Result<VerificationOutcome, SessionCtlError> {
    let storage = SqlCipherStorage::open(
        &root.join(DATABASE_NAME),
        VaultKey::new(**key).map_err(|_| stage("L2 production reopen"))?,
    )
    .map_err(|_| stage("L2 production reopen"))?;
    if storage.schema_version().map_err(|_| stage("L2 schema"))? != EXPECTED_SCHEMA_VERSION
        || storage
            .cipher_version()
            .map_err(|_| stage("L2 cipher"))?
            .is_empty()
        || !storage
            .integrity_check()
            .map_err(|_| stage("L2 cipher integrity"))?
    {
        return Err(stage("L2 production reopen"));
    }
    verify_production_semantics(&storage, expected, fixture)?;
    drop(storage);

    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;

    let mut cipher = connection
        .prepare("PRAGMA cipher_integrity_check;")
        .map_err(|_| stage("L2 cipher integrity"))?;
    let cipher_failure = {
        let mut rows = cipher.query([]).map_err(|_| stage("L2 cipher integrity"))?;
        rows.next()
            .map_err(|_| stage("L2 cipher integrity"))?
            .is_some()
    };
    if cipher_failure {
        return Err(stage("L2 cipher integrity"));
    }

    let quick: String = connection
        .query_row("PRAGMA quick_check;", [], |row| row.get(0))
        .map_err(|_| stage("L2 quick check"))?;
    if quick != "ok" {
        return Err(stage("L2 quick check"));
    }
    let mut foreign = connection
        .prepare("PRAGMA foreign_key_check;")
        .map_err(|_| stage("L2 foreign key check"))?;
    let foreign_key_failure = {
        let mut rows = foreign
            .query([])
            .map_err(|_| stage("L2 foreign key check"))?;
        rows.next()
            .map_err(|_| stage("L2 foreign key check"))?
            .is_some()
    };
    if foreign_key_failure {
        return Err(stage("L2 foreign key check"));
    }

    verify_connection_configuration(&connection)?;
    let user_version: i64 = connection
        .query_row("PRAGMA user_version;", [], |row| row.get(0))
        .map_err(|_| stage("L2 schema"))?;
    let metadata: (i64, i64, i64) = connection
        .query_row(
            "SELECT count(*), min(schema_version), max(schema_version) FROM storage_metadata",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| stage("L2 schema"))?;
    let expected_schema_version = i64::from(EXPECTED_SCHEMA_VERSION);
    if user_version != expected_schema_version
        || metadata != (1, expected_schema_version, expected_schema_version)
        || schema_fingerprint(&connection)? != SCHEMA_FINGERPRINT_SHA256
    {
        return Err(stage("L2 schema"));
    }
    let welcome_path = root.join(WELCOME_FIXTURE_NAME);
    let expected_welcome = if expected == OracleState::InviterNew {
        let bytes = if welcome_path.exists() {
            read_bounded_owned_file_once(&welcome_path, 65_536, "L2 Welcome fixture cleanup")?
        } else if checkpoint == Checkpoint::InviterAfterCommitReturn
            || probe == L2HarnessProbe::IoFault
        {
            committed_welcome(&connection, fixture)?
        } else {
            return Err(stage("L2 Welcome fixture"));
        };
        validate_committed_welcome(&bytes)?;
        Some(bytes)
    } else {
        if welcome_path.exists() {
            drop(read_bounded_owned_file_once(
                &welcome_path,
                65_536,
                "L2 Welcome fixture cleanup",
            )?);
        }
        None
    };
    let expected_welcome_bytes = expected_welcome.as_ref().map(|bytes| bytes.as_slice());
    verify_exact_sql_state(&connection, expected, fixture, expected_welcome_bytes)?;
    connection
        .execute_batch("BEGIN EXCLUSIVE; ROLLBACK;")
        .map_err(|_| stage("L2 exclusive lock"))?;
    drop(foreign);
    drop(cipher);
    drop(connection);

    let before_retry = database_digest(root)?;
    let retry_mutation = match probe {
        L2HarnessProbe::InviterRetryMutation => {
            inject_retry_mutation(root, key, fixture, Scenario::InviterTransaction)?;
            Some(Scenario::InviterTransaction)
        }
        L2HarnessProbe::JoinerRetryMutation => {
            inject_retry_mutation(root, key, fixture, Scenario::JoinerTransaction)?;
            Some(Scenario::JoinerTransaction)
        }
        _ => None,
    };
    if let Some(scenario) = retry_mutation {
        let injected_digest = database_digest(root)?;
        require_exact_retry_conflict(root, key, expected, fixture, expected_welcome_bytes)?;
        if database_digest(root)? != injected_digest {
            return Err(stage("L2 retry conflict mutation"));
        }
        verify_retry_mutation(root, key, fixture, scenario)?;
        return Ok(VerificationOutcome::RetryConflict);
    }
    perform_exact_retry(root, key, expected, fixture, expected_welcome_bytes)?;
    if database_digest(root)? != before_retry {
        return Err(stage("L2 exact retry digest"));
    }
    Ok(VerificationOutcome::Complete)
}

fn committed_welcome(
    connection: &Connection,
    fixture: &CaseFixture,
) -> Result<Zeroizing<Vec<u8>>, SessionCtlError> {
    let welcome = connection
        .query_row(
            "SELECT welcome FROM inviter_joins WHERE transaction_id = ?1",
            params![fixture.transaction_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|_| stage("L2 inviter Welcome oracle"))?
        .ok_or_else(|| stage("L2 inviter Welcome oracle"))?;
    if welcome.len() > 65_536 {
        return Err(stage("L2 inviter Welcome oracle"));
    }
    Ok(Zeroizing::new(welcome))
}

fn validate_committed_welcome(welcome: &[u8]) -> Result<(), SessionCtlError> {
    let envelope = OpaqueEnvelope::decode_canonical(welcome)
        .map_err(|_| stage("L2 inviter Welcome oracle"))?;
    if envelope.envelope_id() != &[0x81; 16]
        || envelope.expires_at_unix_seconds() != OUTBOX_EXPIRES_AT
        || WelcomeMessage::from_bytes(envelope.ciphertext()).is_err()
    {
        return Err(stage("L2 inviter Welcome oracle"));
    }
    Ok(())
}

pub(super) fn database_digest(root: &Path) -> Result<[u8; 32], SessionCtlError> {
    let bytes = Zeroizing::new(read_bounded_owned_file(
        &root.join(DATABASE_NAME),
        MAX_DATABASE_BYTES,
    )?);
    digest(&SHA256, &bytes)
        .as_ref()
        .try_into()
        .map_err(|_| stage("L2 database digest"))
}

pub(super) fn inject_retry_mutation(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    fixture: &CaseFixture,
    scenario: Scenario,
) -> Result<(), SessionCtlError> {
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;
    let (sql, value): (&str, &[u8]) = match scenario {
        Scenario::InviterTransaction => (
            "UPDATE inviter_joins SET approval_record = ?1 WHERE transaction_id = ?2",
            b"l2-retry-defect",
        ),
        Scenario::JoinerTransaction => (
            "UPDATE joiner_commits SET key_package_ref = ?1 WHERE transaction_id = ?2",
            &[0xD1; 32],
        ),
    };
    if connection
        .execute(sql, params![value, fixture.transaction_id])
        .map_err(|_| stage("L2 retry defect"))?
        != 1
    {
        return Err(stage("L2 retry defect"));
    }
    Ok(())
}

fn perform_exact_retry(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    expected: OracleState,
    fixture: &CaseFixture,
    expected_welcome: Option<&[u8]>,
) -> Result<(), SessionCtlError> {
    if matches!(expected, OracleState::InviterOld | OracleState::JoinerOld) {
        return Ok(());
    }
    let (mut storage, state) = prepare_exact_retry(root, key, expected, fixture, expected_welcome)?;
    GroupStateStorage::write(&mut storage, state, Vec::new(), Vec::new())
        .map_err(|_| stage("L2 exact retry"))?;
    if expected == OracleState::JoinerNew {
        KeyPackageStorage::delete(&mut storage, &fixture.key_package_reference)
            .map_err(|_| stage("L2 exact retry"))?;
    }
    verify_production_semantics(&storage, expected, fixture)
}

fn require_exact_retry_conflict(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    expected: OracleState,
    fixture: &CaseFixture,
    expected_welcome: Option<&[u8]>,
) -> Result<(), SessionCtlError> {
    let (mut storage, state) = prepare_exact_retry(root, key, expected, fixture, expected_welcome)?;
    if GroupStateStorage::write(&mut storage, state, Vec::new(), Vec::new())
        != Err(StoreError::Conflict)
    {
        return Err(stage("L2 retry conflict outcome"));
    }
    drop(storage);
    Ok(())
}

fn prepare_exact_retry(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    expected: OracleState,
    fixture: &CaseFixture,
    expected_welcome: Option<&[u8]>,
) -> Result<(SqlCipherStorage, GroupState), SessionCtlError> {
    let storage = SqlCipherStorage::open(
        &root.join(DATABASE_NAME),
        VaultKey::new(**key).map_err(|_| stage("L2 exact retry"))?,
    )
    .map_err(|_| stage("L2 exact retry"))?;
    let state = GroupState {
        id: fixture.group_id.to_vec(),
        data: GroupStateStorage::state(&storage, &fixture.group_id)
            .map_err(|_| stage("L2 exact retry"))?
            .ok_or_else(|| stage("L2 exact retry"))?,
    };
    match expected {
        OracleState::InviterNew => {
            let welcome = expected_welcome.ok_or_else(|| stage("L2 exact retry"))?;
            storage
                .stage_inviter(
                    InviterJoinTransaction::new(
                        fixture.transaction_id,
                        fixture.invitation_id,
                        fixture.invitation_generation,
                        fixture.join_request_id,
                        fixture.request_fingerprint,
                        fixture.group_id,
                        0,
                        1,
                        APPROVAL_RECORD.to_vec(),
                        welcome.to_vec(),
                        fixture_endpoint()?,
                        OUTBOX_EXPIRES_AT,
                    )
                    .map_err(|_| stage("L2 exact retry"))?,
                    BASELINE_NOW,
                    PersistenceFault::None,
                )
                .map_err(|_| stage("L2 exact retry"))?;
        }
        OracleState::JoinerNew => {
            storage
                .stage_joiner(
                    JoinerTransaction::new(
                        fixture.transaction_id,
                        fixture.group_id,
                        fixture.key_package_reference,
                    )
                    .map_err(|_| stage("L2 exact retry"))?,
                    PersistenceFault::None,
                )
                .map_err(|_| stage("L2 exact retry"))?;
        }
        OracleState::InviterOld | OracleState::JoinerOld => {
            return Err(stage("L2 exact retry oracle"));
        }
    }
    Ok((storage, state))
}

fn verify_retry_mutation(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    fixture: &CaseFixture,
    scenario: Scenario,
) -> Result<(), SessionCtlError> {
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;
    let retained = match scenario {
        Scenario::InviterTransaction => connection
            .query_row(
                "SELECT approval_record FROM inviter_joins WHERE transaction_id = ?1",
                params![fixture.transaction_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map(|value| value == b"l2-retry-defect")
            .map_err(|_| stage("L2 retry conflict state"))?,
        Scenario::JoinerTransaction => connection
            .query_row(
                "SELECT key_package_ref FROM joiner_commits WHERE transaction_id = ?1",
                params![fixture.transaction_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map(|value| value == [0xD1; 32])
            .map_err(|_| stage("L2 retry conflict state"))?,
    };
    if !retained {
        return Err(stage("L2 retry conflict state"));
    }
    Ok(())
}

pub(super) struct CheckpointTrace {
    pub(super) target: ControlFrame,
    pub(super) cases: Vec<L2ProcessCase>,
}

pub(super) fn advance_writer_to_target(
    writer: &mut ManagedChild,
    target: ControlFrame,
) -> Result<CheckpointTrace, SessionCtlError> {
    let mut traversal = CheckpointTraversal::new(target)?;
    let mut cases = Vec::new();
    let deadline = Instant::now()
        .checked_add(CASE_WAIT)
        .ok_or_else(|| stage("L2 case timeout"))?;
    for _ in 0..MAX_APPLICATION_CHECKPOINTS {
        let wait = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| stage("L2 case timeout"))?
            .min(FRAME_WAIT);
        let encoded = writer.stdout.read_exact_frame(CONTROL_FRAME_BYTES, wait)?;
        let observed = ControlFrame::decode(&encoded).map_err(|_| stage("L2 checkpoint"))?;
        let case = L2ProcessCase::new(observed.checkpoint(), observed.occurrence())?;
        if traversal.observe(observed)? {
            cases.push(case);
            return Ok(CheckpointTrace {
                target: observed,
                cases,
            });
        }
        cases.push(case);
        writer.write_stdin(&observed.acknowledgement().encode())?;
    }
    Err(stage("L2 checkpoint bound"))
}

pub(super) struct CheckpointTraversal {
    target: ControlFrame,
    checkpoints: &'static [Checkpoint],
    target_position: usize,
    previous: Option<(usize, u8)>,
}

impl CheckpointTraversal {
    pub(super) fn new(target: ControlFrame) -> Result<Self, SessionCtlError> {
        let checkpoints = scenario_checkpoints(target.scenario());
        let target_position = checkpoints
            .iter()
            .position(|checkpoint| *checkpoint == target.checkpoint())
            .ok_or_else(|| stage("L2 checkpoint"))?;
        Ok(Self {
            target,
            checkpoints,
            target_position,
            previous: None,
        })
    }

    pub(super) fn observe(&mut self, observed: ControlFrame) -> Result<bool, SessionCtlError> {
        if observed.case_id() != self.target.case_id()
            || observed.scenario() != self.target.scenario()
            || observed.role() != Role::Writer
        {
            return Err(stage("L2 checkpoint"));
        }
        let position = self
            .checkpoints
            .iter()
            .position(|checkpoint| *checkpoint == observed.checkpoint())
            .ok_or_else(|| stage("L2 checkpoint"))?;
        if let Some((previous_position, previous_occurrence)) = self.previous {
            let ordered = if position == previous_position {
                observed.occurrence() == previous_occurrence.saturating_add(1)
            } else {
                position > previous_position && observed.occurrence() == 0
            };
            if !ordered {
                return Err(stage("L2 checkpoint"));
            }
        } else if observed.occurrence() != 0 {
            return Err(stage("L2 checkpoint"));
        }
        self.previous = Some((position, observed.occurrence()));
        if observed == self.target {
            return Ok(true);
        }
        if position > self.target_position
            || (position == self.target_position
                && observed.occurrence() >= self.target.occurrence())
        {
            return Err(stage("L2 checkpoint"));
        }
        Ok(false)
    }
}

fn scenario_checkpoints(scenario: Scenario) -> &'static [Checkpoint] {
    match scenario {
        Scenario::InviterTransaction => &[
            Checkpoint::InviterBeforeBegin,
            Checkpoint::InviterAfterGroupUpsert,
            Checkpoint::InviterAfterEpochInsert,
            Checkpoint::InviterAfterEpochUpdate,
            Checkpoint::InviterAfterJoinInsert,
            Checkpoint::InviterAfterReservationConsumed,
            Checkpoint::InviterBeforeCommit,
            Checkpoint::InviterAfterCommitReturn,
            Checkpoint::InviterBeforeShadowFinalize,
        ],
        Scenario::JoinerTransaction => &[
            Checkpoint::JoinerBeforeBegin,
            Checkpoint::JoinerAfterGroupUpsert,
            Checkpoint::JoinerAfterEpochInsert,
            Checkpoint::JoinerAfterEpochUpdate,
            Checkpoint::JoinerAfterCommitInsert,
            Checkpoint::JoinerBeforeKeyPackageDelete,
            Checkpoint::JoinerAfterKeyPackageDelete,
            Checkpoint::JoinerBeforeCommit,
            Checkpoint::JoinerAfterCommitReturn,
        ],
    }
}

fn verify_production_semantics(
    storage: &SqlCipherStorage,
    expected: OracleState,
    fixture: &CaseFixture,
) -> Result<(), SessionCtlError> {
    let group_id = SessionGroupId::new(fixture.group_id).map_err(|_| stage("L2 oracle group"))?;
    match expected {
        OracleState::InviterOld => {
            if storage
                .invitation_state(&fixture.invitation_id)
                .map_err(|_| stage("L2 invitation oracle"))?
                != Some(InvitationState::Reserved)
                || storage
                    .recover_inviter(&fixture.transaction_id)
                    .map_err(|_| stage("L2 inviter oracle"))?
                    .is_some()
            {
                return Err(stage("L2 inviter oracle"));
            }
            let client = load_durable_client_with_storage(
                group_id,
                storage.clone(),
                storage.clone(),
                storage.clone(),
            )
            .map_err(|_| stage("L2 identity oracle"))?;
            if client.credential_identity().as_bytes() != &fixture.credential_identity {
                return Err(stage("L2 identity oracle"));
            }
        }
        OracleState::InviterNew => {
            let recovery = storage
                .recover_inviter(&fixture.transaction_id)
                .map_err(|_| stage("L2 inviter oracle"))?
                .ok_or_else(|| stage("L2 inviter oracle"))?;
            if recovery.epoch_after != 1
                || recovery.outbox_state != WelcomeOutboxState::Pending
                || recovery.delivery_attempts != 0
                || storage
                    .invitation_state(&fixture.invitation_id)
                    .map_err(|_| stage("L2 invitation oracle"))?
                    != Some(InvitationState::Consumed)
            {
                return Err(stage("L2 inviter oracle"));
            }
            let client = load_durable_client_with_storage(
                group_id,
                storage.clone(),
                storage.clone(),
                storage.clone(),
            )
            .map_err(|_| stage("L2 identity oracle"))?;
            if client.credential_identity().as_bytes() != &fixture.credential_identity {
                return Err(stage("L2 identity oracle"));
            }
            let group = client
                .load_group(group_id)
                .map_err(|_| stage("L2 MLS reload oracle"))?;
            if group.epoch() != 1 || group.member_count() != 2 {
                return Err(stage("L2 MLS reload oracle"));
            }
        }
        OracleState::JoinerOld => {
            if !storage
                .key_package_exists(&fixture.key_package_reference)
                .map_err(|_| stage("L2 KeyPackage oracle"))?
                || storage
                    .recover_joiner(&fixture.transaction_id)
                    .map_err(|_| stage("L2 joiner oracle"))?
                    .is_some()
            {
                return Err(stage("L2 joiner oracle"));
            }
            let client = load_durable_client_with_storage(
                group_id,
                storage.clone(),
                storage.clone(),
                storage.clone(),
            )
            .map_err(|_| stage("L2 identity oracle"))?;
            if client.credential_identity().as_bytes() != &fixture.credential_identity {
                return Err(stage("L2 identity oracle"));
            }
        }
        OracleState::JoinerNew => {
            let recovery = storage
                .recover_joiner(&fixture.transaction_id)
                .map_err(|_| stage("L2 joiner oracle"))?
                .ok_or_else(|| stage("L2 joiner oracle"))?;
            if recovery.group_id != fixture.group_id {
                return Err(stage("L2 joiner group oracle"));
            }
            if storage
                .key_package_exists(&fixture.key_package_reference)
                .map_err(|_| stage("L2 KeyPackage oracle"))?
            {
                return Err(stage("L2 joiner KeyPackage oracle"));
            }
            let client = load_durable_client_with_storage(
                group_id,
                storage.clone(),
                storage.clone(),
                storage.clone(),
            )
            .map_err(|_| stage("L2 identity oracle"))?;
            if client.credential_identity().as_bytes() != &fixture.credential_identity {
                return Err(stage("L2 identity oracle"));
            }
            let group = client
                .load_group(group_id)
                .map_err(|_| stage("L2 MLS reload oracle"))?;
            if group.epoch() != 1 || group.member_count() != 2 {
                return Err(stage("L2 MLS reload oracle"));
            }
        }
    }
    Ok(())
}

fn verify_exact_sql_state(
    connection: &Connection,
    expected: OracleState,
    fixture: &CaseFixture,
    expected_welcome: Option<&[u8]>,
) -> Result<(), SessionCtlError> {
    type InviterJoinRow = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
    );
    type DeliveryLifecycleRow = (i64, i64, i64, Option<Vec<u8>>, Option<i64>);
    let identity: Option<(Vec<u8>, i64)> = connection
        .query_row(
            "SELECT group_id, length(identity_record) FROM mls_client_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| stage("L2 identity oracle"))?;
    if identity != Some((fixture.group_id.to_vec(), 141)) {
        return Err(stage("L2 identity oracle"));
    }
    let counts = [
        table_count(connection, "reservations")?,
        table_count(connection, "inviter_joins")?,
        table_count(connection, "mls_groups")?,
        table_count(connection, "mls_epochs")?,
        table_count(connection, "key_packages")?,
        table_count(connection, "joiner_commits")?,
        table_count(connection, "mls_client_identity")?,
    ];
    match expected {
        OracleState::InviterOld => {
            let row: Option<(Vec<u8>, Vec<u8>, i64, i64)> = connection
                .query_row(
                    "SELECT generation, join_request_id, expires_at, state FROM reservations WHERE invitation_id = ?1",
                    params![fixture.invitation_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(|_| stage("L2 reservation oracle"))?;
            if row
                != Some((
                    fixture.invitation_generation.to_vec(),
                    fixture.join_request_id.to_vec(),
                    RESERVATION_EXPIRES_AT as i64,
                    1,
                ))
                || counts != [1, 0, 0, 0, 0, 0, 1]
            {
                return Err(stage("L2 inviter oracle"));
            }
        }
        OracleState::InviterNew => {
            let expected_welcome = expected_welcome.ok_or_else(|| stage("L2 inviter oracle"))?;
            let endpoint = fixture_endpoint()?;
            let reservation: Option<(Vec<u8>, Vec<u8>, i64, i64)> = connection
                .query_row(
                    "SELECT generation, join_request_id, expires_at, state FROM reservations WHERE invitation_id = ?1",
                    params![fixture.invitation_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(|_| stage("L2 reservation oracle"))?;
            let row: Option<InviterJoinRow> = connection
                .query_row(
                    "SELECT invitation_id, generation, join_request_id, request_fingerprint, group_id, approval_record, epoch_before, epoch_after, outbox_state FROM inviter_joins WHERE transaction_id = ?1",
                    params![fixture.transaction_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?)),
                )
                .optional()
                .map_err(|_| stage("L2 inviter oracle"))?;
            let payloads: Option<(Vec<u8>, Vec<u8>, i64)> = connection
                .query_row(
                    "SELECT welcome, endpoint, outbox_expires_at FROM inviter_joins WHERE transaction_id = ?1",
                    params![fixture.transaction_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(|_| stage("L2 inviter oracle"))?;
            let lifecycle: Option<DeliveryLifecycleRow> = connection
                .query_row(
                    "SELECT delivery_attempts, maximum_delivery_attempts, lease_generation, lease_id, lease_expires_at FROM inviter_joins WHERE transaction_id = ?1",
                    params![fixture.transaction_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                )
                .optional()
                .map_err(|_| stage("L2 inviter oracle"))?;
            if row
                != Some((
                    fixture.invitation_id.to_vec(),
                    fixture.invitation_generation.to_vec(),
                    fixture.join_request_id.to_vec(),
                    fixture.request_fingerprint.to_vec(),
                    fixture.group_id.to_vec(),
                    APPROVAL_RECORD.to_vec(),
                    0,
                    1,
                    1,
                ))
                || reservation
                    != Some((
                        fixture.invitation_generation.to_vec(),
                        fixture.join_request_id.to_vec(),
                        RESERVATION_EXPIRES_AT as i64,
                        2,
                    ))
                || payloads
                    != Some((
                        expected_welcome.to_vec(),
                        endpoint,
                        OUTBOX_EXPIRES_AT as i64,
                    ))
                || lifecycle
                    != Some((
                        0,
                        i64::from(MAXIMUM_WELCOME_DELIVERY_ATTEMPTS),
                        0,
                        None,
                        None,
                    ))
                || counts[0..2] != [1, 1]
                || counts[2] != 1
                || counts[3] == 0
                || counts[4..] != [0, 0, 1]
            {
                return Err(stage("L2 inviter oracle"));
            }
        }
        OracleState::JoinerOld => {
            let reference: Option<Vec<u8>> = connection
                .query_row(
                    "SELECT key_package_ref FROM key_packages WHERE key_package_ref = ?1",
                    params![fixture.key_package_reference],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| stage("L2 KeyPackage oracle"))?;
            if reference != Some(fixture.key_package_reference.to_vec())
                || counts != [0, 0, 0, 0, 1, 0, 1]
            {
                return Err(stage("L2 joiner oracle"));
            }
        }
        OracleState::JoinerNew => {
            let row: Option<(Vec<u8>, Vec<u8>)> = connection
                .query_row(
                    "SELECT group_id, key_package_ref FROM joiner_commits WHERE transaction_id = ?1",
                    params![fixture.transaction_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|_| stage("L2 joiner oracle"))?;
            if row
                != Some((
                    fixture.group_id.to_vec(),
                    fixture.key_package_reference.to_vec(),
                ))
                || counts[0..2] != [0, 0]
                || counts != [0, 0, 1, 0, 0, 1, 1]
            {
                return Err(stage("L2 joiner SQL oracle"));
            }
        }
    }
    Ok(())
}
