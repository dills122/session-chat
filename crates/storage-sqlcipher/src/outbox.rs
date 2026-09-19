//! Durable Welcome outbox leasing and result settlement.

use std::sync::Arc;

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use session_transport::{LeasedWelcome, OutboxPortError, WelcomeOutboxPort};

#[cfg(session_chat_storage_fault_testing)]
use super::fault_testing;
use super::{
    MAXIMUM_LEASE_SECONDS, OUTBOX_ATTEMPTS_EXHAUSTED, OUTBOX_DELIVERED, OUTBOX_EXPIRED,
    OUTBOX_LEASED, OUTBOX_PENDING, SqlCipherStorage, SqlCipherWelcomeLease, map_outbox_store_error,
    random_nonzero_identifier, store_id_on, validate_delivery_material,
};

impl WelcomeOutboxPort for SqlCipherStorage {
    type Lease = SqlCipherWelcomeLease;

    fn lease_next(
        &mut self,
        now_unix_seconds: u64,
        lease_seconds: u64,
    ) -> Result<Option<LeasedWelcome<Self::Lease>>, OutboxPortError> {
        if now_unix_seconds > i64::MAX as u64
            || lease_seconds == 0
            || lease_seconds > MAXIMUM_LEASE_SECONDS
        {
            return Err(OutboxPortError::Conflict);
        }
        let lease_expires_at = now_unix_seconds
            .checked_add(lease_seconds)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(OutboxPortError::Conflict)?;
        let mut inner = self.lock().map_err(map_outbox_store_error)?;
        #[cfg(session_chat_storage_fault_testing)]
        let observer = inner.welcome_observer.clone();
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OutboxPortError::Internal)?;
        transaction
            .execute(
                "UPDATE inviter_joins
                 SET outbox_state = ?1, lease_id = NULL, lease_expires_at = NULL
                 WHERE outbox_state IN (?2, ?3) AND outbox_expires_at <= ?4",
                params![
                    OUTBOX_EXPIRED,
                    OUTBOX_PENDING,
                    OUTBOX_LEASED,
                    now_unix_seconds as i64
                ],
            )
            .map_err(|_| OutboxPortError::Internal)?;
        transaction
            .execute(
                "UPDATE inviter_joins
                 SET outbox_state = ?1, lease_id = NULL, lease_expires_at = NULL
                 WHERE delivery_attempts >= maximum_delivery_attempts
                   AND outbox_expires_at > ?2
                   AND (
                       outbox_state = ?3
                       OR (outbox_state = ?4 AND lease_expires_at <= ?2)
                   )",
                params![
                    OUTBOX_ATTEMPTS_EXHAUSTED,
                    now_unix_seconds as i64,
                    OUTBOX_PENDING,
                    OUTBOX_LEASED
                ],
            )
            .map_err(|_| OutboxPortError::Internal)?;

        #[cfg(session_chat_storage_fault_testing)]
        fault_testing::welcome_checkpoint(
            &observer,
            fault_testing::WelcomeCheckpoint::Housekeeping,
        )?;
        let candidate = transaction
            .query_row(
                "SELECT transaction_id, welcome, endpoint, outbox_expires_at, lease_generation
                 FROM inviter_joins
                 WHERE outbox_expires_at >= ?1
                   AND delivery_attempts < maximum_delivery_attempts
                   AND (
                       outbox_state = ?2
                       OR (outbox_state = ?3 AND lease_expires_at <= ?4)
                   )
                 ORDER BY transaction_id
                 LIMIT 1",
                params![
                    lease_expires_at as i64,
                    OUTBOX_PENDING,
                    OUTBOX_LEASED,
                    now_unix_seconds as i64
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| OutboxPortError::Internal)?;
        let Some((transaction_id, welcome, endpoint, outbox_expires_at, generation)) = candidate
        else {
            #[cfg(session_chat_storage_fault_testing)]
            fault_testing::welcome_checkpoint(
                &observer,
                fault_testing::WelcomeCheckpoint::LeaseBeforeCommit,
            )?;
            transaction
                .commit()
                .map_err(|_| OutboxPortError::Internal)?;
            #[cfg(session_chat_storage_fault_testing)]
            fault_testing::welcome_checkpoint(
                &observer,
                fault_testing::WelcomeCheckpoint::LeaseAfterCommit,
            )?;
            return Ok(None);
        };
        #[cfg(session_chat_storage_fault_testing)]
        fault_testing::welcome_checkpoint(&observer, fault_testing::WelcomeCheckpoint::Selected)?;
        let transaction_id: [u8; 16] = transaction_id
            .try_into()
            .map_err(|_| OutboxPortError::Internal)?;
        let outbox_expires_at =
            u64::try_from(outbox_expires_at).map_err(|_| OutboxPortError::Internal)?;
        validate_delivery_material(&welcome, &endpoint, outbox_expires_at)
            .map_err(map_outbox_store_error)?;
        let generation = u64::try_from(generation)
            .ok()
            .and_then(|value| value.checked_add(1))
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(OutboxPortError::Internal)?;
        let lease_id = random_nonzero_identifier(&transaction).map_err(map_outbox_store_error)?;
        let store_id = store_id_on(&transaction).map_err(map_outbox_store_error)?;
        let changed = transaction
            .execute(
                "UPDATE inviter_joins
                 SET outbox_state = ?1,
                     delivery_attempts = delivery_attempts + 1,
                     lease_generation = ?2,
                     lease_id = ?3,
                     lease_expires_at = ?4
                 WHERE transaction_id = ?5 AND lease_generation = ?6
                   AND outbox_expires_at >= ?4
                   AND delivery_attempts < maximum_delivery_attempts
                   AND (
                       outbox_state = ?7
                       OR (outbox_state = ?8 AND lease_expires_at <= ?9)
                   )",
                params![
                    OUTBOX_LEASED,
                    generation as i64,
                    lease_id,
                    lease_expires_at as i64,
                    transaction_id,
                    (generation - 1) as i64,
                    OUTBOX_PENDING,
                    OUTBOX_LEASED,
                    now_unix_seconds as i64
                ],
            )
            .map_err(|_| OutboxPortError::Internal)?;
        if changed != 1 {
            return Err(OutboxPortError::Conflict);
        }
        #[cfg(session_chat_storage_fault_testing)]
        fault_testing::welcome_checkpoint(
            &observer,
            fault_testing::WelcomeCheckpoint::LeaseUpdated,
        )?;
        #[cfg(session_chat_storage_fault_testing)]
        fault_testing::welcome_checkpoint(
            &observer,
            fault_testing::WelcomeCheckpoint::LeaseBeforeCommit,
        )?;
        transaction
            .commit()
            .map_err(|_| OutboxPortError::Internal)?;
        #[cfg(session_chat_storage_fault_testing)]
        fault_testing::welcome_checkpoint(
            &observer,
            fault_testing::WelcomeCheckpoint::LeaseAfterCommit,
        )?;
        Ok(Some(LeasedWelcome::from_owner(
            SqlCipherWelcomeLease {
                open_scope: Arc::clone(&self.lease_scope),
                store_id,
                transaction_id,
                generation,
                lease_id,
            },
            welcome,
            endpoint,
            outbox_expires_at,
        )))
    }

    fn report_accepted(
        &mut self,
        lease: Self::Lease,
        now_unix_seconds: u64,
    ) -> Result<(), OutboxPortError> {
        if now_unix_seconds > i64::MAX as u64 {
            return Err(OutboxPortError::Conflict);
        }
        if !Arc::ptr_eq(&self.lease_scope, &lease.open_scope) {
            return Err(OutboxPortError::Conflict);
        }
        let mut inner = self.lock().map_err(map_outbox_store_error)?;
        #[cfg(session_chat_storage_fault_testing)]
        let observer = inner.welcome_observer.clone();
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OutboxPortError::Internal)?;
        if store_id_on(&transaction).map_err(map_outbox_store_error)? != lease.store_id {
            return Err(OutboxPortError::Conflict);
        }
        let changed = transaction
            .execute(
                "UPDATE inviter_joins
                 SET outbox_state = ?1, lease_id = NULL, lease_expires_at = NULL
                 WHERE transaction_id = ?2 AND outbox_state = ?3
                   AND lease_generation = ?4 AND lease_id = ?5
                   AND lease_expires_at > ?6 AND outbox_expires_at > ?6",
                params![
                    OUTBOX_DELIVERED,
                    lease.transaction_id,
                    OUTBOX_LEASED,
                    lease.generation as i64,
                    lease.lease_id,
                    now_unix_seconds as i64
                ],
            )
            .map_err(|_| OutboxPortError::Internal)?;
        if changed == 1 {
            #[cfg(session_chat_storage_fault_testing)]
            fault_testing::welcome_checkpoint(
                &observer,
                fault_testing::WelcomeCheckpoint::AcceptedUpdated,
            )?;
            transaction
                .commit()
                .map_err(|_| OutboxPortError::Internal)?;
            #[cfg(session_chat_storage_fault_testing)]
            fault_testing::welcome_checkpoint(
                &observer,
                fault_testing::WelcomeCheckpoint::AcceptedAfterCommit,
            )?;
            return Ok(());
        }
        transaction
            .execute(
                "UPDATE inviter_joins
                 SET outbox_state = ?1, lease_id = NULL, lease_expires_at = NULL
                 WHERE transaction_id = ?2 AND outbox_state = ?3
                   AND lease_generation = ?4 AND lease_id = ?5
                   AND outbox_expires_at <= ?6",
                params![
                    OUTBOX_EXPIRED,
                    lease.transaction_id,
                    OUTBOX_LEASED,
                    lease.generation as i64,
                    lease.lease_id,
                    now_unix_seconds as i64
                ],
            )
            .map_err(|_| OutboxPortError::Internal)?;
        transaction
            .commit()
            .map_err(|_| OutboxPortError::Internal)?;
        Err(OutboxPortError::Conflict)
    }

    fn report_failed(&mut self, lease: Self::Lease) -> Result<(), OutboxPortError> {
        if !Arc::ptr_eq(&self.lease_scope, &lease.open_scope) {
            return Err(OutboxPortError::Conflict);
        }
        let mut inner = self.lock().map_err(map_outbox_store_error)?;
        #[cfg(session_chat_storage_fault_testing)]
        let observer = inner.welcome_observer.clone();
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| OutboxPortError::Internal)?;
        if store_id_on(&transaction).map_err(map_outbox_store_error)? != lease.store_id {
            return Err(OutboxPortError::Conflict);
        }
        let changed = transaction
            .execute(
                "UPDATE inviter_joins
                 SET outbox_state = CASE
                         WHEN delivery_attempts >= maximum_delivery_attempts THEN ?1
                         ELSE ?2
                     END,
                     lease_id = NULL,
                     lease_expires_at = NULL
                 WHERE transaction_id = ?3 AND outbox_state = ?4
                   AND lease_generation = ?5 AND lease_id = ?6",
                params![
                    OUTBOX_ATTEMPTS_EXHAUSTED,
                    OUTBOX_PENDING,
                    lease.transaction_id,
                    OUTBOX_LEASED,
                    lease.generation as i64,
                    lease.lease_id
                ],
            )
            .map_err(|_| OutboxPortError::Internal)?;
        if changed != 1 {
            return Err(OutboxPortError::Conflict);
        }
        #[cfg(session_chat_storage_fault_testing)]
        fault_testing::welcome_checkpoint(
            &observer,
            fault_testing::WelcomeCheckpoint::FailedUpdated,
        )?;
        transaction
            .commit()
            .map_err(|_| OutboxPortError::Internal)?;
        #[cfg(session_chat_storage_fault_testing)]
        fault_testing::welcome_checkpoint(
            &observer,
            fault_testing::WelcomeCheckpoint::FailedAfterCommit,
        )?;
        Ok(())
    }
}
