//! Inviter and joiner MLS transaction commit paths and validation.

#[cfg(session_chat_storage_fault_testing)]
use super::fault_testing;
use super::{
    AUTHORIZATION_COMMITTED, AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN, Connection, EpochRecord,
    GroupState, InviterJoinTransaction, LocalWelcomeDepositEndpoint, MAX_EPOCH_WRITES,
    MAX_GROUP_ID_BYTES, MAX_MLS_STATE_BYTES, MAXIMUM_WELCOME_DELIVERY_ATTEMPTS, OPENING_CONSUMED,
    OPENING_RESERVED, OpaqueEnvelope, OptionalExtension, PendingJoiner, PersistenceFault,
    StagedInviter, StagedJoiner, StorageInner, StoreError, TransactionBehavior, all_zero,
    authorization_matches_inviter, params, store_id_on, validate_delivery_material,
};

pub(super) fn commit_inviter(
    connection: &mut Connection,
    mut staged: StagedInviter,
    state: &GroupState,
    epoch_inserts: &[EpochRecord],
    epoch_updates: &[EpochRecord],
    #[cfg(session_chat_storage_fault_testing)] fault_observer: Option<
        &fault_testing::FaultObserver,
    >,
) -> Result<(), StoreError> {
    if let Some(addition) = &staged.addition {
        let bound = staged
            .transaction
            .bound_welcome
            .take()
            .ok_or(StoreError::Rejected)?;
        let welcome = addition
            .welcome_for_current_provider_write(state, epoch_inserts, epoch_updates)
            .ok_or(StoreError::Conflict)?;
        staged.transaction.welcome = OpaqueEnvelope::new(
            bound.envelope_id,
            bound.expires_at,
            welcome.as_bytes().to_vec(),
        )
        .and_then(|envelope| envelope.encode_canonical())
        .map_err(|_| StoreError::Rejected)?;
    } else if staged.transaction.bound_welcome.is_some() {
        return Err(StoreError::Rejected);
    }
    let commit = &staged.transaction;
    if state.id.as_slice() != commit.group_id || commit.epoch_after > i64::MAX as u64 {
        return Err(StoreError::Rejected);
    }
    #[cfg(session_chat_storage_fault_testing)]
    emit_fault_checkpoint(
        fault_observer,
        fault_testing::Checkpoint::InviterBeforeBegin,
        0,
    )?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let commit_now_unix_seconds = staged
        .now_unix_seconds
        .checked_add(staged.staged_at.elapsed().as_secs())
        .ok_or(StoreError::Rejected)?;
    validate_inviter(commit, commit_now_unix_seconds)?;
    if let Some(addition) = &staged.addition
        && !addition.authorizes_current_provider_write(state, epoch_inserts, epoch_updates)
    {
        return Err(StoreError::Conflict);
    }
    if let Some(authorization) = &staged.authorization {
        let addition = staged.addition.as_ref().ok_or(StoreError::Rejected)?;
        if store_id_on(&transaction)? != authorization.store_id
            || !authorization_matches_inviter(
                &transaction,
                authorization,
                addition,
                commit,
                AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN,
                commit_now_unix_seconds,
            )?
        {
            return Err(StoreError::Conflict);
        }
    } else {
        let durable_opening_exists = transaction
            .query_row(
                "SELECT 1 FROM invitation_opening_contexts
                 WHERE invitation_id = ?1 AND generation = ?2",
                params![commit.invitation_id, commit.invitation_generation],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if durable_opening_exists {
            return Err(StoreError::Conflict);
        }
    }
    let existing = transaction
        .query_row(
            "SELECT 1 FROM inviter_joins WHERE transaction_id = ?1",
            params![commit.transaction_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    if existing {
        let exact = transaction
            .query_row(
                "SELECT 1 FROM inviter_joins j
                 JOIN mls_groups g ON g.group_id = j.group_id
                 WHERE j.transaction_id = ?1 AND j.invitation_id = ?2
                   AND j.generation = ?3 AND j.join_request_id = ?4
                   AND j.request_fingerprint = ?5 AND j.group_id = ?6
                   AND j.epoch_before = ?7 AND j.epoch_after = ?8
                   AND j.approval_record = ?9 AND j.welcome = ?10
                   AND j.endpoint = ?11 AND j.outbox_expires_at = ?12
                   AND g.state = ?13",
                params![
                    commit.transaction_id,
                    commit.invitation_id,
                    commit.invitation_generation,
                    commit.join_request_id,
                    commit.request_fingerprint,
                    commit.group_id,
                    commit.epoch_before as i64,
                    commit.epoch_after as i64,
                    commit.approval_record,
                    commit.welcome,
                    commit.endpoint,
                    commit.outbox_expires_at as i64,
                    state.data.as_slice()
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        return if exact {
            Ok(())
        } else {
            Err(StoreError::Conflict)
        };
    }

    if staged.authorization.is_none() {
        let reservation_matches = transaction
            .query_row(
                "SELECT 1 FROM reservations
                 WHERE invitation_id = ?1 AND generation = ?2 AND join_request_id = ?3
                   AND expires_at > ?4 AND state = 1",
                params![
                    commit.invitation_id,
                    commit.invitation_generation,
                    commit.join_request_id,
                    commit_now_unix_seconds as i64
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if !reservation_matches {
            return Err(StoreError::Rejected);
        }
    }

    persist_mls(
        &transaction,
        state,
        epoch_inserts,
        epoch_updates,
        #[cfg(session_chat_storage_fault_testing)]
        fault_observer,
        #[cfg(session_chat_storage_fault_testing)]
        fault_testing::Scenario::InviterTransaction,
    )?;
    if let Some(authorization) = &staged.authorization {
        let invitation_expires_at: i64 = transaction.query_row(
            "SELECT invitation_expires_at FROM authorization_attempts
             WHERE attempt_id = ?1 AND transaction_id = ?2 AND state = ?3",
            params![
                authorization.attempt_id,
                authorization.transaction_id,
                AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN,
            ],
            |row| row.get(0),
        )?;
        transaction.execute(
            "INSERT INTO reservations(
                 invitation_id, generation, join_request_id, expires_at, state
             ) VALUES (?1, ?2, ?3, ?4, 2)",
            params![
                commit.invitation_id,
                commit.invitation_generation,
                commit.join_request_id,
                invitation_expires_at,
            ],
        )?;
    }
    transaction.execute(
        "INSERT INTO inviter_joins(
             transaction_id, invitation_id, generation, join_request_id,
             request_fingerprint, group_id, epoch_before, epoch_after,
             approval_record, welcome, endpoint, outbox_expires_at, outbox_state,
             delivery_attempts, maximum_delivery_attempts, lease_generation,
             lease_id, lease_expires_at
         ) VALUES (
             ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
             1, 0, ?13, 0, NULL, NULL
         )",
        params![
            commit.transaction_id,
            commit.invitation_id,
            commit.invitation_generation,
            commit.join_request_id,
            commit.request_fingerprint,
            commit.group_id,
            commit.epoch_before as i64,
            commit.epoch_after as i64,
            commit.approval_record,
            commit.welcome,
            commit.endpoint,
            commit.outbox_expires_at as i64,
            i64::from(MAXIMUM_WELCOME_DELIVERY_ATTEMPTS)
        ],
    )?;
    #[cfg(session_chat_storage_fault_testing)]
    emit_fault_checkpoint(
        fault_observer,
        fault_testing::Checkpoint::InviterAfterJoinInsert,
        0,
    )?;
    if let Some(authorization) = &staged.authorization {
        let changed = transaction.execute(
            "UPDATE authorization_attempts SET state = ?1
             WHERE attempt_id = ?2 AND transaction_id = ?3 AND state = ?4",
            params![
                AUTHORIZATION_COMMITTED,
                authorization.attempt_id,
                authorization.transaction_id,
                AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        let changed = transaction.execute(
            "UPDATE invitation_opening_contexts
             SET state = ?1, hpke_private_key = zeroblob(32)
             WHERE invitation_id = ?2 AND generation = ?3 AND state = ?4",
            params![
                OPENING_CONSUMED,
                commit.invitation_id,
                commit.invitation_generation,
                OPENING_RESERVED,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
    } else {
        let changed = transaction.execute(
            "UPDATE reservations SET state = 2
             WHERE invitation_id = ?1 AND generation = ?2
               AND join_request_id = ?3 AND state = 1",
            params![
                commit.invitation_id,
                commit.invitation_generation,
                commit.join_request_id
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Rejected);
        }
    }
    #[cfg(session_chat_storage_fault_testing)]
    emit_fault_checkpoint(
        fault_observer,
        fault_testing::Checkpoint::InviterAfterReservationConsumed,
        0,
    )?;
    #[cfg(session_chat_storage_fault_testing)]
    emit_fault_checkpoint(
        fault_observer,
        fault_testing::Checkpoint::InviterBeforeCommit,
        0,
    )?;
    if staged.fault == PersistenceFault::BeforeCommit {
        return Err(StoreError::InjectedFailure);
    }
    transaction.commit()?;
    #[cfg(session_chat_storage_fault_testing)]
    emit_fault_checkpoint(
        fault_observer,
        fault_testing::Checkpoint::InviterAfterCommitReturn,
        0,
    )
    .map_err(|_| StoreError::OutcomeUnknown)?;
    if staged.fault == PersistenceFault::AfterCommit {
        Err(StoreError::OutcomeUnknown)
    } else {
        Ok(())
    }
}

pub(super) fn begin_joiner(
    inner: &mut StorageInner,
    staged: StagedJoiner,
    state: &GroupState,
    epoch_inserts: &[EpochRecord],
    epoch_updates: &[EpochRecord],
    #[cfg(session_chat_storage_fault_testing)] fault_observer: Option<
        &fault_testing::FaultObserver,
    >,
) -> Result<(), StoreError> {
    if state.id.as_slice() != staged.transaction.group_id {
        return Err(StoreError::Rejected);
    }
    let existing = inner
        .connection
        .query_row(
            "SELECT 1 FROM joiner_commits WHERE transaction_id = ?1",
            params![staged.transaction.transaction_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    if existing {
        let exact = inner
            .connection
            .query_row(
                "SELECT 1 FROM joiner_commits j
                 JOIN mls_groups g ON g.group_id = j.group_id
                 WHERE j.transaction_id = ?1 AND j.group_id = ?2
                   AND j.key_package_ref = ?3 AND g.state = ?4",
                params![
                    staged.transaction.transaction_id,
                    staged.transaction.group_id,
                    staged.transaction.key_package_reference,
                    state.data.as_slice()
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if !exact
            || key_package_exists_on(&inner.connection, &staged.transaction.key_package_reference)?
        {
            return Err(StoreError::Conflict);
        }
        inner.pending_joiner = Some(PendingJoiner {
            transaction: staged.transaction,
            fault: staged.fault,
            already_committed: true,
        });
        return Ok(());
    }

    #[cfg(session_chat_storage_fault_testing)]
    emit_fault_checkpoint(
        fault_observer,
        fault_testing::Checkpoint::JoinerBeforeBegin,
        0,
    )?;
    inner.connection.execute_batch("BEGIN IMMEDIATE;")?;
    let result = (|| {
        if !key_package_exists_on(&inner.connection, &staged.transaction.key_package_reference)? {
            return Err(StoreError::Rejected);
        }
        persist_mls(
            &inner.connection,
            state,
            epoch_inserts,
            epoch_updates,
            #[cfg(session_chat_storage_fault_testing)]
            fault_observer,
            #[cfg(session_chat_storage_fault_testing)]
            fault_testing::Scenario::JoinerTransaction,
        )?;
        inner.connection.execute(
            "INSERT INTO joiner_commits(transaction_id, group_id, key_package_ref)
             VALUES (?1, ?2, ?3)",
            params![
                staged.transaction.transaction_id,
                staged.transaction.group_id,
                staged.transaction.key_package_reference
            ],
        )?;
        #[cfg(session_chat_storage_fault_testing)]
        emit_fault_checkpoint(
            fault_observer,
            fault_testing::Checkpoint::JoinerAfterCommitInsert,
            0,
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        rollback(&inner.connection);
        return Err(error);
    }
    inner.pending_joiner = Some(PendingJoiner {
        transaction: staged.transaction,
        fault: staged.fault,
        already_committed: false,
    });
    Ok(())
}

fn persist_mls(
    transaction: &Connection,
    state: &GroupState,
    epoch_inserts: &[EpochRecord],
    epoch_updates: &[EpochRecord],
    #[cfg(session_chat_storage_fault_testing)] fault_observer: Option<
        &fault_testing::FaultObserver,
    >,
    #[cfg(session_chat_storage_fault_testing)] scenario: fault_testing::Scenario,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO mls_groups(group_id, state) VALUES (?1, ?2)
         ON CONFLICT(group_id) DO UPDATE SET state = excluded.state",
        params![state.id, state.data.as_slice()],
    )?;
    #[cfg(session_chat_storage_fault_testing)]
    emit_fault_checkpoint(
        fault_observer,
        match scenario {
            fault_testing::Scenario::InviterTransaction => {
                fault_testing::Checkpoint::InviterAfterGroupUpsert
            }
            fault_testing::Scenario::JoinerTransaction => {
                fault_testing::Checkpoint::JoinerAfterGroupUpsert
            }
        },
        0,
    )?;
    #[cfg(session_chat_storage_fault_testing)]
    let mut insert_occurrence = 0_u8;
    for epoch in epoch_inserts {
        transaction.execute(
            "INSERT INTO mls_epochs(group_id, epoch_id, data) VALUES (?1, ?2, ?3)",
            params![state.id, epoch.id as i64, epoch.data.as_slice()],
        )?;
        #[cfg(session_chat_storage_fault_testing)]
        emit_fault_checkpoint(
            fault_observer,
            match scenario {
                fault_testing::Scenario::InviterTransaction => {
                    fault_testing::Checkpoint::InviterAfterEpochInsert
                }
                fault_testing::Scenario::JoinerTransaction => {
                    fault_testing::Checkpoint::JoinerAfterEpochInsert
                }
            },
            insert_occurrence,
        )?;
        #[cfg(session_chat_storage_fault_testing)]
        {
            insert_occurrence = insert_occurrence
                .checked_add(1)
                .ok_or(StoreError::Rejected)?;
        }
    }
    #[cfg(session_chat_storage_fault_testing)]
    let mut update_occurrence = 0_u8;
    for epoch in epoch_updates {
        let changed = transaction.execute(
            "UPDATE mls_epochs SET data = ?3 WHERE group_id = ?1 AND epoch_id = ?2",
            params![state.id, epoch.id as i64, epoch.data.as_slice()],
        )?;
        if changed != 1 {
            return Err(StoreError::Rejected);
        }
        #[cfg(session_chat_storage_fault_testing)]
        emit_fault_checkpoint(
            fault_observer,
            match scenario {
                fault_testing::Scenario::InviterTransaction => {
                    fault_testing::Checkpoint::InviterAfterEpochUpdate
                }
                fault_testing::Scenario::JoinerTransaction => {
                    fault_testing::Checkpoint::JoinerAfterEpochUpdate
                }
            },
            update_occurrence,
        )?;
        #[cfg(session_chat_storage_fault_testing)]
        {
            update_occurrence = update_occurrence
                .checked_add(1)
                .ok_or(StoreError::Rejected)?;
        }
    }
    Ok(())
}

pub(super) fn key_package_exists_on(
    connection: &Connection,
    reference: &[u8],
) -> Result<bool, StoreError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM key_packages WHERE key_package_ref = ?1",
            params![reference],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
}

pub(super) fn rollback(connection: &Connection) {
    let _ = connection.execute_batch("ROLLBACK;");
}

#[cfg(session_chat_storage_fault_testing)]
pub(super) fn emit_fault_checkpoint(
    observer: Option<&fault_testing::FaultObserver>,
    checkpoint: fault_testing::Checkpoint,
    occurrence: u8,
) -> Result<(), StoreError> {
    observer
        .map(|observer| observer.checkpoint(checkpoint, occurrence))
        .transpose()
        .map(|_| ())
        .map_err(|_| StoreError::Rejected)
}

pub(super) fn validate_inviter(
    transaction: &InviterJoinTransaction,
    now_unix_seconds: u64,
) -> Result<(), StoreError> {
    if all_zero(&transaction.transaction_id)
        || all_zero(&transaction.invitation_id)
        || all_zero(&transaction.invitation_generation)
        || all_zero(&transaction.join_request_id)
        || all_zero(&transaction.request_fingerprint)
        || all_zero(&transaction.group_id)
        || transaction.epoch_before.checked_add(1) != Some(transaction.epoch_after)
        || transaction.epoch_after > i64::MAX as u64
        || transaction.approval_record.is_empty()
        || transaction.approval_record.len() > 4_096
        || transaction.welcome.len() > 65_536
        || transaction.endpoint.is_empty()
        || transaction.endpoint.len() > 4_096
        || transaction.outbox_expires_at <= now_unix_seconds
        || transaction.outbox_expires_at > i64::MAX as u64
        || now_unix_seconds > i64::MAX as u64
    {
        return Err(StoreError::Rejected);
    }
    match &transaction.bound_welcome {
        Some(bound) if transaction.welcome.is_empty() => validate_delivery_metadata(
            &bound.envelope_id,
            bound.expires_at,
            &transaction.endpoint,
            transaction.outbox_expires_at,
        ),
        None if !transaction.welcome.is_empty() => validate_delivery_material(
            &transaction.welcome,
            &transaction.endpoint,
            transaction.outbox_expires_at,
        ),
        _ => Err(StoreError::Rejected),
    }
}

pub(super) fn validate_delivery_metadata(
    envelope_id: &[u8; 16],
    welcome_expires_at: u64,
    endpoint: &[u8],
    outbox_expires_at: u64,
) -> Result<(), StoreError> {
    let endpoint = LocalWelcomeDepositEndpoint::decode_canonical(endpoint)
        .map_err(|_| StoreError::Rejected)?;
    if all_zero(envelope_id)
        || outbox_expires_at > welcome_expires_at
        || welcome_expires_at > endpoint.expires_at_unix_seconds()
    {
        return Err(StoreError::Rejected);
    }
    Ok(())
}

pub(super) fn validate_mls_write(
    state: &GroupState,
    epoch_inserts: &[EpochRecord],
    epoch_updates: &[EpochRecord],
) -> Result<(), StoreError> {
    if state.id.is_empty()
        || state.id.len() > MAX_GROUP_ID_BYTES
        || state.data.is_empty()
        || state.data.len() > MAX_MLS_STATE_BYTES
        || epoch_inserts.len() > MAX_EPOCH_WRITES
        || epoch_updates.len() > MAX_EPOCH_WRITES
        || epoch_inserts.iter().chain(epoch_updates).any(|epoch| {
            epoch.id > i64::MAX as u64
                || epoch.data.is_empty()
                || epoch.data.len() > MAX_MLS_STATE_BYTES
        })
    {
        return Err(StoreError::Rejected);
    }
    Ok(())
}
