//! Invitation and admission authorization lifecycle.

use super::*;

impl SqlCipherStorage {
    /// Generates and atomically persists one opening context before returning it for publication.
    pub fn issue_capability_invitation(
        &self,
        protector: &dyn InvitationJoinProtector,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<GeneratedCapabilityInvitationV2, StoreError> {
        if issued_at_unix_seconds == 0
            || issued_at_unix_seconds > now_unix_seconds
            || expires_at_unix_seconds <= now_unix_seconds
            || expires_at_unix_seconds > i64::MAX as u64
            || now_unix_seconds > i64::MAX as u64
        {
            return Err(StoreError::Rejected);
        }
        let generated = protector
            .generate_capability_invitation(issued_at_unix_seconds, expires_at_unix_seconds)
            .map_err(map_join_protection_error)?;
        let mut sink = SqlCipherInvitationOpeningSink {
            storage: self,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            now_unix_seconds,
        };
        generated
            .persist_opening_context(&mut sink)
            .map_err(|error| match error {
                InvitationOpeningContextPersistenceError::Protection(error) => {
                    map_join_protection_error(error)
                }
                InvitationOpeningContextPersistenceError::Storage(error) => error,
            })?;
        Ok(generated)
    }

    /// Reloads one available opening context after revalidating every stored binding.
    pub fn load_capability_invitation(
        &self,
        protector: &dyn InvitationJoinProtector,
        invitation_id: &[u8; 16],
        now_unix_seconds: u64,
    ) -> Result<Option<GeneratedCapabilityInvitationV2>, StoreError> {
        if all_zero(invitation_id) || now_unix_seconds > i64::MAX as u64 {
            return Err(StoreError::Rejected);
        }
        let mut inner = self.lock()?;
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = transaction
            .query_row(
                "SELECT generation, signed_invitation, hpke_private_key,
                        issued_at, expires_at, state
                 FROM invitation_opening_contexts WHERE invitation_id = ?1",
                params![invitation_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((generation, canonical_invitation, private_key, issued_at, expires_at, state)) =
            stored
        else {
            return Ok(None);
        };
        let canonical_invitation = Zeroizing::new(canonical_invitation);
        let private_key = Zeroizing::new(private_key);
        if state != OPENING_AVAILABLE {
            return Err(StoreError::Rejected);
        }
        if expires_at <= now_unix_seconds as i64 {
            terminalize_opening_context(&transaction, invitation_id)?;
            transaction.commit()?;
            return Err(StoreError::Rejected);
        }
        let private_key = match stored_invitation_private_key(private_key.as_slice()) {
            Ok(private_key) => private_key,
            Err(_) => {
                terminalize_opening_context(&transaction, invitation_id)?;
                transaction.commit()?;
                return Err(StoreError::Rejected);
            }
        };
        let restoration =
            protector.restore_capability_invitation(canonical_invitation.as_slice(), private_key);
        let restored = match restoration {
            Ok(restored) => restored,
            Err(_) => {
                terminalize_opening_context(&transaction, invitation_id)?;
                transaction.commit()?;
                return Err(StoreError::Rejected);
            }
        };
        let bindings_match = generation == restored.invitation().signature()
            && restored.invitation().invitation_id() == invitation_id
            && issued_at >= 0
            && issued_at as u64 == restored.invitation().issued_at_unix_seconds()
            && expires_at > 0
            && expires_at as u64 == restored.invitation().expires_at_unix_seconds();
        if !bindings_match {
            terminalize_opening_context(&transaction, invitation_id)?;
            transaction.commit()?;
            return Err(StoreError::Rejected);
        }
        transaction.commit()?;
        Ok(Some(restored))
    }

    /// Returns the secret-free lifecycle of one stored opening context.
    pub fn invitation_opening_state(
        &self,
        invitation_id: &[u8; 16],
    ) -> Result<Option<InvitationOpeningState>, StoreError> {
        self.lock()?
            .connection
            .query_row(
                "SELECT state FROM invitation_opening_contexts WHERE invitation_id = ?1",
                params![invitation_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|state| match state {
                OPENING_AVAILABLE => Ok(InvitationOpeningState::Available),
                OPENING_RESERVED => Ok(InvitationOpeningState::Reserved),
                OPENING_CONSUMED => Ok(InvitationOpeningState::Consumed),
                OPENING_UNUSABLE => Ok(InvitationOpeningState::Unusable),
                _ => Err(StoreError::Rejected),
            })
            .transpose()
    }

    /// Atomically retains one verified, non-authorizing request shadow and reserves its invitation.
    pub fn reserve_authorization(
        &self,
        protector: &dyn InvitationJoinProtector,
        input: AuthorizationShadowInput,
        now_unix_seconds: u64,
    ) -> Result<PendingAuthorization, StoreError> {
        if now_unix_seconds > i64::MAX as u64
            || input.request_issued_at > now_unix_seconds
            || input.request_expires_at <= now_unix_seconds
            || input.invitation_expires_at <= now_unix_seconds
        {
            return Err(StoreError::Rejected);
        }
        let mut inner = self.lock()?;
        if inner.live_pre_membership_attempts.len()
            >= self.authorization_policy.maximum_retained_attempts
        {
            return Err(StoreError::CapacityExceeded);
        }
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        compact_expired_authorization_state(&transaction, now_unix_seconds as i64)?;
        let replayed = transaction
            .query_row(
                "SELECT 1 FROM authorization_attempts
                 WHERE generation = ?1 AND invitation_expires_at > ?2
                   AND (join_request_id = ?3 OR request_nonce = ?4 OR request_fingerprint = ?5)",
                params![
                    &input.invitation_generation,
                    now_unix_seconds as i64,
                    &input.join_request_id,
                    &input.request_nonce,
                    &input.request_fingerprint,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if replayed {
            return Err(StoreError::Replay);
        }
        let live_attempts: i64 = transaction.query_row(
            "SELECT count(*) FROM authorization_attempts WHERE state IN (?1, ?2, ?3)",
            params![
                AUTHORIZATION_PENDING_APPROVAL,
                AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
                AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN,
            ],
            |row| row.get(0),
        )?;
        let generation_attempts: i64 = transaction.query_row(
            "SELECT count(*) FROM authorization_attempts
             WHERE invitation_id = ?1 AND generation = ?2",
            params![&input.invitation_id, &input.invitation_generation],
            |row| row.get(0),
        )?;
        if live_attempts < 0
            || live_attempts as usize >= self.authorization_policy.maximum_retained_attempts
            || generation_attempts < 0
            || generation_attempts as usize >= self.authorization_policy.maximum_retained_attempts
        {
            return Err(StoreError::CapacityExceeded);
        }
        let opening = transaction
            .query_row(
                "SELECT signed_invitation, hpke_private_key, expires_at, state
                 FROM invitation_opening_contexts
                 WHERE invitation_id = ?1 AND generation = ?2",
                params![&input.invitation_id, &input.invitation_generation],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::Conflict)?;
        let canonical_invitation = Zeroizing::new(opening.0);
        let private_key = Zeroizing::new(opening.1);
        if opening.2 <= now_unix_seconds as i64
            || opening.2 as u64 != input.invitation_expires_at
            || opening.3 != OPENING_AVAILABLE
        {
            return Err(StoreError::Conflict);
        }
        let private_key = match stored_invitation_private_key(private_key.as_slice()) {
            Ok(private_key) => private_key,
            Err(_) => {
                terminalize_opening_context(&transaction, &input.invitation_id)?;
                transaction.commit()?;
                return Err(StoreError::Rejected);
            }
        };
        let restoration =
            protector.restore_capability_invitation(canonical_invitation.as_slice(), private_key);
        let restored = match restoration {
            Ok(restored) => restored,
            Err(_) => {
                terminalize_opening_context(&transaction, &input.invitation_id)?;
                transaction.commit()?;
                return Err(StoreError::Rejected);
            }
        };
        if restored.invitation().invitation_id() != &input.invitation_id
            || restored.invitation().signature() != &input.invitation_generation
            || restored.invitation().join_challenge() != &input.invitation_challenge
            || restored.invitation().inviter_verifying_key() != &input.intended_verifier
            || restored.invitation().expires_at_unix_seconds() != input.invitation_expires_at
        {
            return Err(StoreError::Conflict);
        }
        let attempt_id = random_nonzero_identifier(&transaction)?;
        transaction.execute(
            "INSERT INTO authorization_attempts(
                 attempt_id, invitation_id, generation, invitation_challenge,
                 join_request_id, request_nonce, intended_verifier,
                 key_package_reference, mls_protocol_version, mls_ciphersuite,
                 credential_type, credential_identity, leaf_signature_key,
                 admission_proof_version, request_fingerprint, request_issued_at,
                 request_expires_at, invitation_expires_at, state, transaction_id
             ) VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, 1, 1, ?9, ?10, 1,
                 ?11, ?12, ?13, ?14, ?15, NULL
             )",
            params![
                attempt_id,
                &input.invitation_id,
                &input.invitation_generation,
                &input.invitation_challenge,
                &input.join_request_id,
                &input.request_nonce,
                &input.intended_verifier,
                &input.key_package_reference,
                &input.credential_identity,
                &input.leaf_signature_key,
                &input.request_fingerprint,
                input.request_issued_at as i64,
                input.request_expires_at as i64,
                input.invitation_expires_at as i64,
                AUTHORIZATION_PENDING_APPROVAL,
            ],
        )?;
        let changed = transaction.execute(
            "UPDATE invitation_opening_contexts SET state = ?1
             WHERE invitation_id = ?2 AND generation = ?3 AND state = ?4",
            params![
                OPENING_RESERVED,
                &input.invitation_id,
                &input.invitation_generation,
                OPENING_AVAILABLE,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        let store_id = store_id_on(&transaction)?;
        transaction.commit()?;
        inner.live_pre_membership_attempts.push(attempt_id);
        Ok(PendingAuthorization(AuthorizationHandle {
            open_scope: Arc::clone(&self.lease_scope),
            store_id,
            attempt_id,
            invitation_id: input.invitation_id,
            invitation_generation: input.invitation_generation,
        }))
    }

    /// Returns the secret-free retained state for one authorization attempt.
    pub fn authorization_state(
        &self,
        attempt_id: &[u8; 16],
    ) -> Result<Option<AuthorizationState>, StoreError> {
        self.lock()?
            .connection
            .query_row(
                "SELECT state FROM authorization_attempts WHERE attempt_id = ?1",
                params![attempt_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(decode_authorization_state)
            .transpose()
    }

    /// Records one explicit approval without reconstructing membership authority.
    pub fn approve_authorization(
        &self,
        pending: PendingAuthorization,
        protector: &dyn InvitationJoinProtector,
        now_unix_seconds: u64,
    ) -> Result<ApprovedAuthorization, StoreError> {
        if now_unix_seconds > i64::MAX as u64
            || !Arc::ptr_eq(&self.lease_scope, &pending.0.open_scope)
        {
            return Err(StoreError::Conflict);
        }
        let mut inner = self.lock()?;
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_authorization_handle(&transaction, &pending.0, AUTHORIZATION_PENDING_APPROVAL)?;
        if authorization_is_expired(&transaction, &pending.0, now_unix_seconds)? {
            abandon_expired_authorization(
                &transaction,
                &pending.0,
                AUTHORIZATION_PENDING_APPROVAL,
                protector,
                now_unix_seconds,
            )?;
            transaction.commit()?;
            inner
                .live_pre_membership_attempts
                .retain(|attempt| attempt != &pending.0.attempt_id);
            return Err(StoreError::Rejected);
        }
        let changed = transaction.execute(
            "UPDATE authorization_attempts SET state = ?1
             WHERE attempt_id = ?2 AND state = ?3
               AND request_expires_at > ?4 AND invitation_expires_at > ?4",
            params![
                AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
                pending.0.attempt_id,
                AUTHORIZATION_PENDING_APPROVAL,
                now_unix_seconds as i64,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        transaction.commit()?;
        Ok(ApprovedAuthorization(pending.0))
    }

    /// Persists the exact transaction ID before membership storage may begin.
    pub fn begin_membership_authorization(
        &self,
        approved: ApprovedAuthorization,
        transaction_id: [u8; 16],
        protector: &dyn InvitationJoinProtector,
        now_unix_seconds: u64,
    ) -> Result<MembershipAuthorization, StoreError> {
        if all_zero(&transaction_id)
            || now_unix_seconds > i64::MAX as u64
            || !Arc::ptr_eq(&self.lease_scope, &approved.0.open_scope)
        {
            return Err(StoreError::Conflict);
        }
        let mut inner = self.lock()?;
        if inner.live_membership_attempts.len()
            >= self.authorization_policy.maximum_retained_attempts
        {
            return Err(StoreError::CapacityExceeded);
        }
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_authorization_handle(
            &transaction,
            &approved.0,
            AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
        )?;
        if authorization_is_expired(&transaction, &approved.0, now_unix_seconds)? {
            abandon_expired_authorization(
                &transaction,
                &approved.0,
                AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
                protector,
                now_unix_seconds,
            )?;
            transaction.commit()?;
            inner
                .live_pre_membership_attempts
                .retain(|attempt| attempt != &approved.0.attempt_id);
            return Err(StoreError::Rejected);
        }
        let changed = transaction.execute(
            "UPDATE authorization_attempts
             SET state = ?1, transaction_id = ?2
             WHERE attempt_id = ?3 AND state = ?4
               AND request_expires_at > ?5 AND invitation_expires_at > ?5",
            params![
                AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN,
                transaction_id,
                approved.0.attempt_id,
                AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
                now_unix_seconds as i64,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        transaction.commit()?;
        inner.live_membership_attempts.push(approved.0.attempt_id);
        inner
            .live_pre_membership_attempts
            .retain(|attempt| attempt != &approved.0.attempt_id);
        Ok(MembershipAuthorization {
            open_scope: approved.0.open_scope,
            store_id: approved.0.store_id,
            attempt_id: approved.0.attempt_id,
            transaction_id,
        })
    }

    /// Abandons one pending pre-approval attempt while retaining replay state.
    pub fn abandon_pending_authorization(
        &self,
        pending: PendingAuthorization,
        protector: &dyn InvitationJoinProtector,
        now_unix_seconds: u64,
    ) -> Result<(), StoreError> {
        if now_unix_seconds > i64::MAX as u64
            || !Arc::ptr_eq(&self.lease_scope, &pending.0.open_scope)
        {
            return Err(StoreError::Conflict);
        }
        let mut inner = self.lock()?;
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_authorization_handle(&transaction, &pending.0, AUTHORIZATION_PENDING_APPROVAL)?;
        let changed = transaction.execute(
            "UPDATE authorization_attempts SET state = ?1
             WHERE attempt_id = ?2 AND state = ?3",
            params![
                AUTHORIZATION_ABANDONED,
                pending.0.attempt_id,
                AUTHORIZATION_PENDING_APPROVAL,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        release_opening_context(
            &transaction,
            protector,
            &pending.0.invitation_id,
            &pending.0.invitation_generation,
            now_unix_seconds,
        )?;
        transaction.commit()?;
        inner
            .live_pre_membership_attempts
            .retain(|attempt| attempt != &pending.0.attempt_id);
        Ok(())
    }

    /// Records one explicit rejection, retaining replay while releasing only its invitation.
    pub fn reject_authorization(
        &self,
        pending: PendingAuthorization,
        protector: &dyn InvitationJoinProtector,
        now_unix_seconds: u64,
    ) -> Result<(), StoreError> {
        if now_unix_seconds > i64::MAX as u64
            || !Arc::ptr_eq(&self.lease_scope, &pending.0.open_scope)
        {
            return Err(StoreError::Conflict);
        }
        let mut inner = self.lock()?;
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_authorization_handle(&transaction, &pending.0, AUTHORIZATION_PENDING_APPROVAL)?;
        let changed = transaction.execute(
            "UPDATE authorization_attempts SET state = ?1
             WHERE attempt_id = ?2 AND state = ?3",
            params![
                AUTHORIZATION_REJECTED,
                pending.0.attempt_id,
                AUTHORIZATION_PENDING_APPROVAL,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        release_opening_context(
            &transaction,
            protector,
            &pending.0.invitation_id,
            &pending.0.invitation_generation,
            now_unix_seconds,
        )?;
        transaction.commit()?;
        inner
            .live_pre_membership_attempts
            .retain(|attempt| attempt != &pending.0.attempt_id);
        Ok(())
    }

    /// Abandons one approved pre-membership attempt while retaining replay state.
    pub fn abandon_approved_authorization(
        &self,
        approved: ApprovedAuthorization,
        protector: &dyn InvitationJoinProtector,
        now_unix_seconds: u64,
    ) -> Result<(), StoreError> {
        if now_unix_seconds > i64::MAX as u64
            || !Arc::ptr_eq(&self.lease_scope, &approved.0.open_scope)
        {
            return Err(StoreError::Conflict);
        }
        let mut inner = self.lock()?;
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_authorization_handle(
            &transaction,
            &approved.0,
            AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
        )?;
        let changed = transaction.execute(
            "UPDATE authorization_attempts SET state = ?1
             WHERE attempt_id = ?2 AND state = ?3",
            params![
                AUTHORIZATION_ABANDONED,
                approved.0.attempt_id,
                AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        release_opening_context(
            &transaction,
            protector,
            &approved.0.invitation_id,
            &approved.0.invitation_generation,
            now_unix_seconds,
        )?;
        transaction.commit()?;
        inner
            .live_pre_membership_attempts
            .retain(|attempt| attempt != &approved.0.attempt_id);
        Ok(())
    }

    /// Abandons every live pre-membership shadow after process restart.
    pub fn recover_pre_membership_authorizations(
        &self,
        protector: &dyn InvitationJoinProtector,
        now_unix_seconds: u64,
    ) -> Result<usize, StoreError> {
        if now_unix_seconds > i64::MAX as u64 {
            return Err(StoreError::Rejected);
        }
        let mut inner = self.lock()?;
        let live_attempts = inner.live_pre_membership_attempts.clone();
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let attempts = {
            let mut statement = transaction.prepare(
                "SELECT attempt_id, invitation_id, generation
                 FROM authorization_attempts
                 WHERE state IN (?1, ?2)
                 ORDER BY attempt_id",
            )?;
            let rows = statement.query_map(
                params![
                    AUTHORIZATION_PENDING_APPROVAL,
                    AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        if attempts.iter().any(|(attempt_id, _, _)| {
            live_attempts
                .iter()
                .any(|live| live.as_slice() == attempt_id)
        }) {
            return Err(StoreError::Conflict);
        }
        for (attempt_id, invitation_id, generation) in &attempts {
            let attempt_id: [u8; 16] = attempt_id
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Rejected)?;
            let invitation_id: [u8; 16] = invitation_id
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Rejected)?;
            let generation: [u8; 64] = generation
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Rejected)?;
            let changed = transaction.execute(
                "UPDATE authorization_attempts SET state = ?1
                 WHERE attempt_id = ?2 AND state IN (?3, ?4)",
                params![
                    AUTHORIZATION_ABANDONED,
                    attempt_id,
                    AUTHORIZATION_PENDING_APPROVAL,
                    AUTHORIZATION_APPROVED_PENDING_MEMBERSHIP,
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::Conflict);
            }
            release_opening_context(
                &transaction,
                protector,
                &invitation_id,
                &generation,
                now_unix_seconds,
            )?;
        }
        transaction.commit()?;
        Ok(attempts.len())
    }

    /// Resolves one outcome-unknown authorization from the exact retained inviter transaction.
    ///
    /// Recovery is rejected while the originating open scope still owns the live membership
    /// attempt. A fresh scope treats a missing exact inviter transaction as proven uncommitted.
    pub fn recover_authorization_outcome(
        &self,
        attempt_id: &[u8; 16],
        transaction_id: &[u8; 16],
        protector: &dyn InvitationJoinProtector,
        now_unix_seconds: u64,
    ) -> Result<AuthorizationState, StoreError> {
        if all_zero(attempt_id) || all_zero(transaction_id) || now_unix_seconds > i64::MAX as u64 {
            return Err(StoreError::Rejected);
        }
        let mut inner = self.lock()?;
        if inner
            .live_membership_attempts
            .iter()
            .any(|live| live == attempt_id)
        {
            return Err(StoreError::Conflict);
        }
        let transaction = inner
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authorization = transaction
            .query_row(
                "SELECT invitation_id, generation, join_request_id,
                        request_fingerprint, transaction_id, state
                 FROM authorization_attempts
                 WHERE attempt_id = ?1 AND transaction_id = ?2",
                params![attempt_id, transaction_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::Conflict)?;
        let invitation_id: [u8; 16] = authorization
            .0
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Rejected)?;
        let generation: [u8; 64] = authorization
            .1
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Rejected)?;
        let join_request_id: [u8; 16] = authorization
            .2
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Rejected)?;
        let request_fingerprint: [u8; 32] = authorization
            .3
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Rejected)?;
        if authorization.4.as_slice() != transaction_id {
            return Err(StoreError::Conflict);
        }
        let authorization_state = decode_authorization_state(authorization.5)?;
        let committed = transaction
            .query_row(
                "SELECT invitation_id, generation, join_request_id, request_fingerprint
                 FROM inviter_joins WHERE transaction_id = ?1",
                params![transaction_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some(committed) = &committed
            && (committed.0.as_slice() != invitation_id
                || committed.1.as_slice() != generation
                || committed.2.as_slice() != join_request_id
                || committed.3.as_slice() != request_fingerprint)
        {
            return Err(StoreError::Conflict);
        }
        match authorization_state {
            AuthorizationState::Committed => {
                if committed.is_none() {
                    return Err(StoreError::Conflict);
                }
                let opening_state = transaction
                    .query_row(
                        "SELECT state FROM invitation_opening_contexts
                         WHERE invitation_id = ?1 AND generation = ?2",
                        params![invitation_id, generation],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?;
                if opening_state != Some(OPENING_CONSUMED) {
                    return Err(StoreError::Conflict);
                }
                transaction.commit()?;
                return Ok(AuthorizationState::Committed);
            }
            AuthorizationState::Abandoned => {
                if committed.is_some() {
                    return Err(StoreError::Conflict);
                }
                transaction.commit()?;
                return Ok(AuthorizationState::Abandoned);
            }
            AuthorizationState::MembershipOutcomeUnknown => {}
            AuthorizationState::PendingApproval
            | AuthorizationState::ApprovedPendingMembership
            | AuthorizationState::Rejected => {
                return Err(StoreError::Conflict);
            }
        }
        let resolved = if committed.is_some() {
            let changed = transaction.execute(
                "UPDATE invitation_opening_contexts
                 SET state = ?1, hpke_private_key = zeroblob(32)
                 WHERE invitation_id = ?2 AND generation = ?3 AND state = ?4",
                params![
                    OPENING_CONSUMED,
                    invitation_id,
                    generation,
                    OPENING_RESERVED,
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::Conflict);
            }
            AUTHORIZATION_COMMITTED
        } else {
            release_opening_context(
                &transaction,
                protector,
                &invitation_id,
                &generation,
                now_unix_seconds,
            )?;
            AUTHORIZATION_ABANDONED
        };
        let changed = transaction.execute(
            "UPDATE authorization_attempts SET state = ?1
             WHERE attempt_id = ?2 AND transaction_id = ?3 AND state = ?4",
            params![
                resolved,
                attempt_id,
                transaction_id,
                AUTHORIZATION_MEMBERSHIP_OUTCOME_UNKNOWN,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        transaction.commit()?;
        decode_authorization_state(resolved)
    }
}

struct SqlCipherInvitationOpeningSink<'a> {
    storage: &'a SqlCipherStorage,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    now_unix_seconds: u64,
}

impl InvitationOpeningContextSink for SqlCipherInvitationOpeningSink<'_> {
    type Error = StoreError;

    fn persist_opening_context(
        &mut self,
        invitation: &SignedCapabilityInvitationV2,
        canonical_invitation: &[u8],
        private_key: InvitationHpkePrivateKeyStorageRef<'_>,
    ) -> Result<(), Self::Error> {
        private_key.persist_with(|private_key| {
            let mut inner = self.storage.lock()?;
            let transaction = inner
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            compact_expired_authorization_state(&transaction, self.now_unix_seconds as i64)?;
            let live_count: i64 = transaction.query_row(
                "SELECT count(*) FROM invitation_opening_contexts",
                [],
                |row| row.get(0),
            )?;
            if live_count < 0
                || live_count as usize >= self.storage.authorization_policy.maximum_live_invitations
            {
                return Err(StoreError::CapacityExceeded);
            }
            transaction.execute(
                "INSERT INTO invitation_opening_contexts(
                     invitation_id, generation, signed_invitation, hpke_private_key,
                     issued_at, expires_at, state
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    invitation.invitation_id(),
                    invitation.signature(),
                    canonical_invitation,
                    private_key,
                    self.issued_at_unix_seconds as i64,
                    self.expires_at_unix_seconds as i64,
                    OPENING_AVAILABLE,
                ],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }
}

fn map_join_protection_error(_: JoinProtectionError) -> StoreError {
    StoreError::Rejected
}

fn stored_invitation_private_key(
    bytes: &[u8],
) -> Result<StoredInvitationHpkePrivateKey, StoreError> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| StoreError::Rejected)?;
    StoredInvitationHpkePrivateKey::from_bytes(Zeroizing::new(bytes))
        .map_err(map_join_protection_error)
}

fn compact_expired_authorization_state(
    connection: &Connection,
    now_unix_seconds: i64,
) -> Result<(), StoreError> {
    connection.execute(
        "UPDATE invitation_opening_contexts
         SET state = ?1, hpke_private_key = zeroblob(32)
         WHERE state = ?2 AND expires_at <= ?3
           AND EXISTS (
               SELECT 1 FROM authorization_attempts AS a
               WHERE a.invitation_id = invitation_opening_contexts.invitation_id
                 AND a.generation = invitation_opening_contexts.generation
                 AND a.invitation_expires_at <= ?3
                 AND a.state IN (?4, ?5, ?6)
           )",
        params![
            OPENING_UNUSABLE,
            OPENING_RESERVED,
            now_unix_seconds,
            AUTHORIZATION_COMMITTED,
            AUTHORIZATION_REJECTED,
            AUTHORIZATION_ABANDONED,
        ],
    )?;
    connection.execute(
        "DELETE FROM authorization_attempts
         WHERE invitation_expires_at <= ?1 AND state IN (?2, ?3, ?4)",
        params![
            now_unix_seconds,
            AUTHORIZATION_COMMITTED,
            AUTHORIZATION_REJECTED,
            AUTHORIZATION_ABANDONED,
        ],
    )?;
    connection.execute(
        "UPDATE invitation_opening_contexts
         SET state = ?1, hpke_private_key = zeroblob(32)
         WHERE state = ?2 AND expires_at <= ?3",
        params![OPENING_UNUSABLE, OPENING_AVAILABLE, now_unix_seconds],
    )?;
    connection.execute(
        "DELETE FROM invitation_opening_contexts
         WHERE state IN (?1, ?2) AND expires_at <= ?3",
        params![OPENING_UNUSABLE, OPENING_CONSUMED, now_unix_seconds],
    )?;
    Ok(())
}

fn terminalize_opening_context(
    connection: &Connection,
    invitation_id: &[u8; 16],
) -> Result<(), StoreError> {
    let changed = connection.execute(
        "UPDATE invitation_opening_contexts
         SET state = ?1, hpke_private_key = zeroblob(32)
         WHERE invitation_id = ?2 AND state = ?3",
        params![OPENING_UNUSABLE, invitation_id, OPENING_AVAILABLE],
    )?;
    if changed != 1 {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

fn validate_authorization_handle(
    connection: &Connection,
    handle: &AuthorizationHandle,
    expected_state: i64,
) -> Result<(), StoreError> {
    if store_id_on(connection)? != handle.store_id {
        return Err(StoreError::Conflict);
    }
    let exact = connection
        .query_row(
            "SELECT 1 FROM authorization_attempts AS a
             JOIN invitation_opening_contexts AS i
               ON i.invitation_id = a.invitation_id AND i.generation = a.generation
             WHERE a.attempt_id = ?1 AND a.invitation_id = ?2
               AND a.generation = ?3 AND a.state = ?4 AND i.state = ?5",
            params![
                handle.attempt_id,
                handle.invitation_id,
                handle.invitation_generation,
                expected_state,
                OPENING_RESERVED,
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    if !exact {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

pub(super) fn authorization_matches_inviter(
    connection: &Connection,
    authorization: &MembershipAuthorization,
    addition: &CommittedAdditionStorageBinding,
    inviter: &InviterJoinTransaction,
    expected_state: i64,
    now_unix_seconds: u64,
) -> Result<bool, StoreError> {
    if addition.group_id() != &inviter.group_id
        || addition.epoch_before() != inviter.epoch_before
        || addition.epoch_after() != inviter.epoch_after
    {
        return Ok(false);
    }
    Ok(connection
        .query_row(
            "SELECT 1 FROM authorization_attempts AS a
             JOIN invitation_opening_contexts AS i
               ON i.invitation_id = a.invitation_id AND i.generation = a.generation
             WHERE a.attempt_id = ?1 AND a.transaction_id = ?2
               AND a.invitation_id = ?3 AND a.generation = ?4
               AND a.join_request_id = ?5 AND a.request_fingerprint = ?6
               AND a.key_package_reference = ?7 AND a.credential_identity = ?8
               AND a.leaf_signature_key = ?9 AND a.state = ?10
               AND a.request_expires_at > ?11
               AND a.invitation_expires_at > ?11 AND i.state = ?12",
            params![
                authorization.attempt_id,
                authorization.transaction_id,
                inviter.invitation_id,
                inviter.invitation_generation,
                inviter.join_request_id,
                inviter.request_fingerprint,
                addition.key_package_reference(),
                addition.credential_identity(),
                addition.leaf_signature_key(),
                expected_state,
                now_unix_seconds as i64,
                OPENING_RESERVED,
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
}

fn authorization_is_expired(
    connection: &Connection,
    handle: &AuthorizationHandle,
    now_unix_seconds: u64,
) -> Result<bool, StoreError> {
    connection
        .query_row(
            "SELECT request_expires_at <= ?1 OR invitation_expires_at <= ?1
             FROM authorization_attempts WHERE attempt_id = ?2",
            params![now_unix_seconds as i64, handle.attempt_id],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn abandon_expired_authorization(
    connection: &Connection,
    handle: &AuthorizationHandle,
    expected_state: i64,
    protector: &dyn InvitationJoinProtector,
    now_unix_seconds: u64,
) -> Result<(), StoreError> {
    let changed = connection.execute(
        "UPDATE authorization_attempts SET state = ?1
         WHERE attempt_id = ?2 AND state = ?3",
        params![AUTHORIZATION_ABANDONED, handle.attempt_id, expected_state],
    )?;
    if changed != 1 {
        return Err(StoreError::Conflict);
    }
    release_opening_context(
        connection,
        protector,
        &handle.invitation_id,
        &handle.invitation_generation,
        now_unix_seconds,
    )
}

fn release_opening_context(
    connection: &Connection,
    protector: &dyn InvitationJoinProtector,
    invitation_id: &[u8; 16],
    generation: &[u8; 64],
    now_unix_seconds: u64,
) -> Result<(), StoreError> {
    let opening = connection
        .query_row(
            "SELECT signed_invitation, hpke_private_key, expires_at, state
             FROM invitation_opening_contexts
             WHERE invitation_id = ?1 AND generation = ?2",
            params![invitation_id, generation],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::Conflict)?;
    if opening.3 != OPENING_RESERVED {
        return Err(StoreError::Conflict);
    }
    let canonical_invitation = Zeroizing::new(opening.0);
    let private_key = Zeroizing::new(opening.1);
    let restored = stored_invitation_private_key(private_key.as_slice())
        .ok()
        .and_then(|private_key| {
            protector
                .restore_capability_invitation(canonical_invitation.as_slice(), private_key)
                .ok()
        });
    let usable = opening.2 > now_unix_seconds as i64
        && restored.as_ref().is_some_and(|restored| {
            restored.invitation().invitation_id() == invitation_id
                && restored.invitation().signature() == generation
                && restored.invitation().expires_at_unix_seconds() == opening.2 as u64
        });
    let changed = if usable {
        connection.execute(
            "UPDATE invitation_opening_contexts SET state = ?1
             WHERE invitation_id = ?2 AND generation = ?3 AND state = ?4",
            params![
                OPENING_AVAILABLE,
                invitation_id,
                generation,
                OPENING_RESERVED,
            ],
        )?
    } else {
        connection.execute(
            "UPDATE invitation_opening_contexts
             SET state = ?1, hpke_private_key = zeroblob(32)
             WHERE invitation_id = ?2 AND generation = ?3 AND state = ?4",
            params![
                OPENING_UNUSABLE,
                invitation_id,
                generation,
                OPENING_RESERVED,
            ],
        )?
    };
    if changed != 1 {
        return Err(StoreError::Conflict);
    }
    Ok(())
}
