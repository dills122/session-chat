use session_protocol::{MAX_ENVELOPE_CIPHERTEXT_BYTES, OpaqueEnvelope};
use session_storage::{
    DeterministicClock, DeterministicKeyProtector, InboxAppendOutcome,
    MAX_ENCODED_OPAQUE_ENVELOPE_BYTES, OpaqueInboxPolicy, SessionId, SessionVaultModel, VaultError,
    VaultPolicy, VaultState,
};

const NOW: u64 = 2_000_000_000;

fn session_id() -> SessionId {
    SessionId::new([0x11; 32]).expect("nonzero session ID")
}

fn model(
    maximum_envelopes: usize,
    maximum_total_encoded_bytes: usize,
) -> SessionVaultModel<DeterministicClock, DeterministicKeyProtector> {
    SessionVaultModel::new(
        VaultPolicy::new(30, 60).expect("valid vault policy"),
        OpaqueInboxPolicy::new(300, maximum_envelopes, maximum_total_encoded_bytes)
            .expect("valid inbox policy"),
        DeterministicClock::new(NOW),
        DeterministicKeyProtector::new(session_id(), [0x21; 32])
            .expect("valid deterministic protector"),
    )
}

fn encoded_envelope(id: u8, ciphertext: u8, expires_at: u64) -> Vec<u8> {
    OpaqueEnvelope::new([id; 16], expires_at, vec![ciphertext; 32])
        .expect("bounded envelope")
        .encode_canonical()
        .expect("canonical envelope")
}

fn unlock(vault: &mut SessionVaultModel<DeterministicClock, DeterministicKeyProtector>) {
    let attempt = vault.begin_unlock(session_id()).expect("begin unlock");
    vault.complete_unlock(attempt).expect("complete unlock");
}

#[test]
fn bounded_opaque_append_is_the_only_operation_available_in_every_vault_state() {
    let mut vault = model(4, 256 * 1024);

    assert_eq!(
        vault.append_opaque(&encoded_envelope(0x31, 0x41, NOW + 120)),
        Ok(InboxAppendOutcome::Stored)
    );
    assert_eq!(vault.state(), VaultState::Sealed);

    let unlock = vault.begin_unlock(session_id()).expect("begin unlock");
    assert_eq!(
        vault.append_opaque(&encoded_envelope(0x32, 0x42, NOW + 120)),
        Ok(InboxAppendOutcome::Stored)
    );
    assert_eq!(vault.state(), VaultState::Unlocking);

    vault.complete_unlock(unlock).expect("complete unlock");
    assert_eq!(
        vault.append_opaque(&encoded_envelope(0x33, 0x43, NOW + 120)),
        Ok(InboxAppendOutcome::Stored)
    );
    assert_eq!(vault.state(), VaultState::Open);

    let _relock = vault.begin_relock(session_id()).expect("begin relock");
    assert_eq!(
        vault.append_opaque(&encoded_envelope(0x34, 0x44, NOW + 120)),
        Ok(InboxAppendOutcome::Stored)
    );
    assert_eq!(vault.state(), VaultState::Relocking);
    assert_eq!(vault.inbox_count(), 4);
}

#[test]
fn malformed_noncanonical_expired_oversized_and_zero_id_inputs_fail_before_storage() {
    let mut vault = model(4, 256 * 1024);
    let canonical = encoded_envelope(0x41, 0x51, NOW + 120);
    let mut trailing = canonical.clone();
    trailing.push(0);
    let zero_id = OpaqueEnvelope::new([0; 16], NOW + 120, vec![0x52; 32])
        .expect("protocol framing permits untrusted zero ID")
        .encode_canonical()
        .expect("encode zero ID fixture");

    for rejected in [
        Vec::new(),
        vec![0xff],
        trailing,
        zero_id,
        encoded_envelope(0x42, 0x52, NOW),
        encoded_envelope(0x43, 0x53, NOW + 301),
        vec![0; MAX_ENCODED_OPAQUE_ENVELOPE_BYTES + 1],
    ] {
        assert_eq!(vault.append_opaque(&rejected), Err(VaultError::Rejected));
        assert_eq!(vault.inbox_count(), 0);
        assert_eq!(vault.inbox_total_encoded_bytes(), 0);
    }
}

#[test]
fn maximum_canonical_envelope_is_accepted_at_the_pre_parser_boundary() {
    let maximum = OpaqueEnvelope::new(
        [0x49; 16],
        NOW + 120,
        vec![0x59; MAX_ENVELOPE_CIPHERTEXT_BYTES],
    )
    .expect("maximum protocol envelope")
    .encode_canonical()
    .expect("encode maximum envelope");
    assert!(maximum.len() <= MAX_ENCODED_OPAQUE_ENVELOPE_BYTES);
    let mut vault = model(1, maximum.len());

    assert_eq!(
        vault.append_opaque(&maximum),
        Ok(InboxAppendOutcome::Stored)
    );
    assert_eq!(vault.inbox_total_encoded_bytes(), maximum.len());
}

#[test]
fn exact_retry_is_idempotent_but_changed_bytes_and_capacity_fail_closed() {
    let exact = encoded_envelope(0x51, 0x61, NOW + 120);
    let changed = encoded_envelope(0x51, 0x62, NOW + 120);
    let other = encoded_envelope(0x52, 0x63, NOW + 120);
    let mut vault = model(1, exact.len());

    assert_eq!(vault.append_opaque(&exact), Ok(InboxAppendOutcome::Stored));
    assert_eq!(
        vault.append_opaque(&exact),
        Ok(InboxAppendOutcome::AlreadyStored)
    );
    assert_eq!(vault.append_opaque(&changed), Err(VaultError::Rejected));
    assert_eq!(
        vault.append_opaque(&other),
        Err(VaultError::CapacityExceeded)
    );
    assert_eq!(vault.inbox_count(), 1);
    assert_eq!(vault.inbox_total_encoded_bytes(), exact.len());

    let mut byte_limited = model(2, exact.len() - 1);
    assert_eq!(
        byte_limited.append_opaque(&exact),
        Err(VaultError::CapacityExceeded)
    );
    assert_eq!(byte_limited.inbox_count(), 0);
}

#[test]
fn import_requires_the_exact_open_generation_and_completion_is_local_only() {
    let encoded = encoded_envelope(0x61, 0x71, NOW + 120);
    let expected = OpaqueEnvelope::decode_canonical(&encoded).expect("decode fixture");
    let mut vault = model(2, 256 * 1024);
    vault.append_opaque(&encoded).expect("store while sealed");

    assert!(matches!(
        vault.begin_opaque_import(session_id()),
        Err(VaultError::Rejected)
    ));
    unlock(&mut vault);
    let stale = vault
        .begin_opaque_import(session_id())
        .expect("open session may inspect bounded opaque work")
        .expect("one stored item");
    assert_eq!(stale.envelope(), &expected);

    let relock = vault.begin_relock(session_id()).expect("begin relock");
    assert_eq!(
        vault.complete_opaque_import(stale),
        Err(VaultError::ReservationMismatch)
    );
    assert_eq!(vault.inbox_count(), 1);
    vault.complete_relock(relock).expect("complete relock");

    unlock(&mut vault);
    let current = vault
        .begin_opaque_import(session_id())
        .expect("reopened session can retry import")
        .expect("item survived stale completion");
    vault
        .complete_opaque_import(current)
        .expect("consume exact local import");
    assert_eq!(vault.inbox_count(), 0);
    assert_eq!(vault.inbox_total_encoded_bytes(), 0);
}

#[test]
fn expired_items_are_pruned_and_stale_import_tokens_cannot_delete_reused_ids() {
    let first = encoded_envelope(0x71, 0x81, NOW + 10);
    let replacement = encoded_envelope(0x71, 0x82, NOW + 120);
    let mut vault = model(1, 256 * 1024);
    vault.append_opaque(&first).expect("store first generation");
    unlock(&mut vault);
    let stale = vault
        .begin_opaque_import(session_id())
        .expect("begin first import")
        .expect("first generation exists");

    vault.clock_mut().advance(10).expect("expire first item");
    assert_eq!(
        vault.append_opaque(&replacement),
        Ok(InboxAppendOutcome::Stored)
    );
    assert_eq!(vault.inbox_count(), 1);
    assert_eq!(
        vault.complete_opaque_import(stale),
        Err(VaultError::ReservationMismatch)
    );

    let current = vault
        .begin_opaque_import(session_id())
        .expect("begin replacement import")
        .expect("replacement survives stale token");
    assert_eq!(current.envelope().ciphertext(), &[0x82; 32]);
}
