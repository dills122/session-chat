//! MLS provider storage trait adapters.

use super::*;

impl DurableClientIdentityStorage for SqlCipherStorage {
    type Error = StoreError;

    fn load_client_identity(
        &self,
        group_id: &SessionGroupId,
    ) -> Result<Option<DurableClientIdentityRecord>, Self::Error> {
        let retained = self
            .lock()?
            .connection
            .query_row(
                "SELECT group_id, identity_record FROM mls_client_identity
                 WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(StoreError::from)?;
        let Some((stored_group_id, encoded)) = retained else {
            return Ok(None);
        };
        let encoded = DurableClientIdentityRecord::from_storage_bytes(encoded)
            .map_err(|_| StoreError::Rejected)?;
        if stored_group_id.as_slice() != group_id.as_bytes() {
            return Err(StoreError::Conflict);
        }
        Ok(Some(encoded))
    }

    fn insert_client_identity(
        &self,
        group_id: &SessionGroupId,
        encoded: DurableClientIdentityRecord,
    ) -> Result<(), Self::Error> {
        let encoded = encoded.into_storage_bytes();
        self.lock()?.connection.execute(
            "INSERT INTO mls_client_identity(singleton, group_id, identity_record)
             VALUES (1, ?1, ?2)",
            params![group_id.as_bytes(), encoded.as_slice()],
        )?;
        Ok(())
    }
}

impl GroupStateStorage for SqlCipherStorage {
    type Error = StoreError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        self.lock()?
            .connection
            .query_row(
                "SELECT state FROM mls_groups WHERE group_id = ?1",
                params![group_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map(|value| value.map(Zeroizing::new))
            .map_err(Into::into)
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        if epoch_id > i64::MAX as u64 {
            return Err(StoreError::Rejected);
        }
        self.lock()?
            .connection
            .query_row(
                "SELECT data FROM mls_epochs WHERE group_id = ?1 AND epoch_id = ?2",
                params![group_id, epoch_id as i64],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map(|value| value.map(Zeroizing::new))
            .map_err(Into::into)
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        validate_mls_write(&state, &epoch_inserts, &epoch_updates)?;
        let mut inner = self.lock()?;
        #[cfg(session_chat_storage_fault_testing)]
        let fault_observer = inner.fault_observer.clone();
        if let Some(staged) = inner.staged_inviter.take() {
            let authorization_attempt = staged
                .authorization
                .as_ref()
                .map(|authorization| authorization.attempt_id);
            let result = commit_inviter(
                &mut inner.connection,
                staged,
                &state,
                &epoch_inserts,
                &epoch_updates,
                #[cfg(session_chat_storage_fault_testing)]
                fault_observer.as_ref(),
            );
            if let Some(attempt_id) = authorization_attempt {
                inner
                    .live_membership_attempts
                    .retain(|live| live != &attempt_id);
            }
            return result;
        }
        let staged = inner.staged_joiner.take().ok_or(StoreError::Rejected)?;
        begin_joiner(
            &mut inner,
            staged,
            &state,
            &epoch_inserts,
            &epoch_updates,
            #[cfg(session_chat_storage_fault_testing)]
            fault_observer.as_ref(),
        )
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        let value = self.lock()?.connection.query_row(
            "SELECT max(epoch_id) FROM mls_epochs WHERE group_id = ?1",
            params![group_id],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        value
            .map(|epoch| u64::try_from(epoch).map_err(|_| StoreError::Rejected))
            .transpose()
    }
}

impl KeyPackageStorage for SqlCipherStorage {
    type Error = StoreError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        if id.len() != 32 {
            return Err(StoreError::Rejected);
        }
        let mut inner = self.lock_for_joiner_completion()?;
        #[cfg(session_chat_storage_fault_testing)]
        let fault_observer = inner.fault_observer.clone();
        let pending = inner.pending_joiner.take().ok_or(StoreError::Rejected)?;
        if id != pending.transaction.key_package_reference {
            rollback(&inner.connection);
            return Err(StoreError::Rejected);
        }
        if pending.already_committed {
            return if key_package_exists_on(&inner.connection, id)? {
                Err(StoreError::Conflict)
            } else {
                Ok(())
            };
        }
        #[cfg(session_chat_storage_fault_testing)]
        if emit_fault_checkpoint(
            fault_observer.as_ref(),
            fault_testing::Checkpoint::JoinerBeforeKeyPackageDelete,
            0,
        )
        .is_err()
        {
            rollback(&inner.connection);
            return Err(StoreError::Rejected);
        }
        let changed = match inner.connection.execute(
            "DELETE FROM key_packages WHERE key_package_ref = ?1",
            params![id],
        ) {
            Ok(changed) => changed,
            Err(_) => {
                rollback(&inner.connection);
                return Err(StoreError::Rejected);
            }
        };
        if changed != 1 {
            rollback(&inner.connection);
            return Err(StoreError::Rejected);
        }
        #[cfg(session_chat_storage_fault_testing)]
        if emit_fault_checkpoint(
            fault_observer.as_ref(),
            fault_testing::Checkpoint::JoinerAfterKeyPackageDelete,
            0,
        )
        .is_err()
        {
            rollback(&inner.connection);
            return Err(StoreError::Rejected);
        }
        #[cfg(session_chat_storage_fault_testing)]
        if emit_fault_checkpoint(
            fault_observer.as_ref(),
            fault_testing::Checkpoint::JoinerBeforeCommit,
            0,
        )
        .is_err()
        {
            rollback(&inner.connection);
            return Err(StoreError::Rejected);
        }
        if pending.fault == PersistenceFault::BeforeCommit {
            rollback(&inner.connection);
            return Err(StoreError::InjectedFailure);
        }
        if inner.connection.execute_batch("COMMIT;").is_err() {
            rollback(&inner.connection);
            return Err(StoreError::Rejected);
        }
        #[cfg(session_chat_storage_fault_testing)]
        emit_fault_checkpoint(
            fault_observer.as_ref(),
            fault_testing::Checkpoint::JoinerAfterCommitReturn,
            0,
        )
        .map_err(|_| StoreError::OutcomeUnknown)?;
        if pending.fault == PersistenceFault::AfterCommit {
            Err(StoreError::OutcomeUnknown)
        } else {
            Ok(())
        }
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        if id.len() != 32
            || pkg.key_package_bytes.is_empty()
            || pkg.key_package_bytes.len() > MAX_KEY_PACKAGE_BYTES
            || pkg.init_key.is_empty()
            || pkg.init_key.len() > MAX_SECRET_KEY_BYTES
            || pkg.leaf_node_key.is_empty()
            || pkg.leaf_node_key.len() > MAX_SECRET_KEY_BYTES
            || pkg.expiration == 0
            || pkg.expiration > i64::MAX as u64
        {
            return Err(StoreError::Rejected);
        }
        self.lock()?.connection.execute(
            "INSERT INTO key_packages(
                 key_package_ref, key_package, init_key, leaf_key, expires_at
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id,
                pkg.key_package_bytes,
                pkg.init_key.as_ref(),
                pkg.leaf_node_key.as_ref(),
                pkg.expiration as i64
            ],
        )?;
        Ok(())
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        if id.len() != 32 {
            return Err(StoreError::Rejected);
        }
        self.lock()?
            .connection
            .query_row(
                "SELECT key_package, init_key, leaf_key, expires_at
                 FROM key_packages WHERE key_package_ref = ?1",
                params![id],
                |row| {
                    let expiration = row.get::<_, i64>(3)?;
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        expiration,
                    ))
                },
            )
            .optional()?
            .map(|(key_package, init_key, leaf_key, expiration)| {
                if key_package.is_empty()
                    || key_package.len() > MAX_KEY_PACKAGE_BYTES
                    || init_key.is_empty()
                    || init_key.len() > MAX_SECRET_KEY_BYTES
                    || leaf_key.is_empty()
                    || leaf_key.len() > MAX_SECRET_KEY_BYTES
                    || expiration <= 0
                {
                    return Err(StoreError::Rejected);
                }
                Ok(KeyPackageData::new(
                    key_package,
                    HpkeSecretKey::from(init_key),
                    HpkeSecretKey::from(leaf_key),
                    expiration as u64,
                ))
            })
            .transpose()
    }
}
