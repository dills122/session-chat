use ed25519_dalek::SigningKey;
use session_core::{
    InvitationLifecycle, InvitationLifecycleError, InvitationPolicy, InvitationRegistry,
};
use session_protocol::{CapabilityInvitationClaims, SecretCapability, SignedCapabilityInvitation};

const NOW: u64 = 1_700_000_000;

fn claims(id_byte: u8, issued_at: u64, expires_at: u64) -> CapabilityInvitationClaims {
    CapabilityInvitationClaims::new(
        [id_byte; 16],
        issued_at,
        expires_at,
        [id_byte.wrapping_add(1); 32],
        SecretCapability::new([id_byte.wrapping_add(2); 32]).expect("test capability is nonzero"),
    )
    .expect("test claims are structurally valid")
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn encoded_remote_invitation(
    id_byte: u8,
    signing_seed: u8,
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    SignedCapabilityInvitation::sign(
        claims(id_byte, issued_at, expires_at),
        &signing_key(signing_seed),
    )
    .expect("test invitation signs")
    .encode_canonical()
    .expect("test invitation encodes")
}

fn registry(capacity: usize) -> InvitationRegistry {
    let policy = InvitationPolicy::new(3_600, 30, capacity).expect("test policy is valid");
    InvitationRegistry::new(policy)
}

#[test]
fn validating_an_invitation_is_read_only_and_does_not_consume_it() {
    let mut registry = registry(4);
    let issued = registry
        .issue(claims(0x11, NOW - 10, NOW + 300), &signing_key(0xa1), NOW)
        .expect("local issuance succeeds");
    let encoded = issued
        .encode_canonical()
        .expect("issued invitation encodes");

    let first = registry
        .validate_descriptor(&encoded, NOW)
        .expect("first validation succeeds");
    let second = registry
        .validate_descriptor(&encoded, NOW)
        .expect("repeated validation remains safe");

    assert_eq!(first.invitation_id(), &[0x11; 16]);
    assert_eq!(second.invitation_id(), &[0x11; 16]);
    assert_eq!(first.expires_at_unix_seconds(), NOW + 300);
    assert_eq!(first.invitation().invitation_id(), &[0x11; 16]);
    assert_eq!(
        registry.lifecycle(&[0x11; 16]),
        Some(InvitationLifecycle::Available)
    );
    assert_eq!(registry.record_count(), 1);
}

#[test]
fn a_valid_remote_descriptor_cannot_create_inviter_owned_state() {
    let registry = registry(4);
    let encoded = encoded_remote_invitation(0x22, 0xb2, NOW - 10, NOW + 300);
    let validated = registry
        .validate_descriptor(&encoded, NOW)
        .expect("self-contained descriptor is valid");
    let mut registry = registry;

    assert_eq!(
        registry
            .reserve_after_admission(&validated, [0x71; 16], NOW)
            .err(),
        Some(InvitationLifecycleError::UnknownInvitation)
    );
    assert_eq!(registry.record_count(), 0);
}

#[test]
fn reservation_can_be_released_and_consumption_requires_the_matching_reservation() {
    let mut registry = registry(4);
    let issued = registry
        .issue(claims(0x33, NOW - 10, NOW + 300), &signing_key(0xa3), NOW)
        .expect("local issuance succeeds");
    let encoded = issued
        .encode_canonical()
        .expect("issued invitation encodes");
    let validated = registry
        .validate_descriptor(&encoded, NOW)
        .expect("descriptor validates");

    let first = registry
        .reserve_after_admission(&validated, [0x81; 16], NOW)
        .expect("validated admission reserves the invitation");
    assert_eq!(
        registry.lifecycle(&[0x33; 16]),
        Some(InvitationLifecycle::Reserved)
    );
    assert_eq!(
        registry
            .reserve_after_admission(&validated, [0x82; 16], NOW)
            .err(),
        Some(InvitationLifecycleError::AlreadyReserved)
    );

    registry
        .release(first, NOW)
        .expect("failed or rejected admission releases its reservation");
    assert_eq!(
        registry.lifecycle(&[0x33; 16]),
        Some(InvitationLifecycle::Available)
    );

    let second = registry
        .reserve_after_admission(&validated, [0x82; 16], NOW)
        .expect("a later validated request can reserve the invitation");
    registry
        .consume_after_membership(second, NOW)
        .expect("successful membership consumes the invitation");
    assert_eq!(
        registry.lifecycle(&[0x33; 16]),
        Some(InvitationLifecycle::Consumed)
    );
    assert_eq!(
        registry
            .reserve_after_admission(&validated, [0x83; 16], NOW)
            .err(),
        Some(InvitationLifecycleError::AlreadyConsumed)
    );
}

#[test]
fn descriptor_substitution_cannot_reserve_a_locally_issued_identifier() {
    let mut registry = registry(4);
    registry
        .issue(claims(0x44, NOW - 10, NOW + 300), &signing_key(0xa4), NOW)
        .expect("local issuance succeeds");
    let substituted = encoded_remote_invitation(0x44, 0xb4, NOW - 10, NOW + 300);
    let validated = registry
        .validate_descriptor(&substituted, NOW)
        .expect("substituted descriptor is independently valid");

    assert_eq!(
        registry
            .reserve_after_admission(&validated, [0x91; 16], NOW)
            .err(),
        Some(InvitationLifecycleError::DescriptorMismatch)
    );
    assert_eq!(
        registry.lifecycle(&[0x44; 16]),
        Some(InvitationLifecycle::Available)
    );
}

#[test]
fn malformed_expired_future_and_overlong_descriptors_never_mutate_state() {
    let registry = registry(4);
    let mut malformed = encoded_remote_invitation(0x51, 0xa1, NOW - 10, NOW + 300);
    let last = malformed.len() - 1;
    malformed[last] ^= 0x01;
    assert!(matches!(
        registry.validate_descriptor(&malformed, NOW),
        Err(InvitationLifecycleError::Protocol(_))
    ));

    let expired = encoded_remote_invitation(0x52, 0xa2, NOW - 60, NOW);
    assert_eq!(
        registry.validate_descriptor(&expired, NOW).err(),
        Some(InvitationLifecycleError::Expired {
            expires_at: NOW,
            now: NOW,
        })
    );

    let future = encoded_remote_invitation(0x53, 0xa3, NOW + 31, NOW + 300);
    assert_eq!(
        registry.validate_descriptor(&future, NOW).err(),
        Some(InvitationLifecycleError::IssuedTooFarInFuture {
            issued_at: NOW + 31,
            latest_allowed: NOW + 30,
        })
    );

    let overlong = encoded_remote_invitation(0x54, 0xa4, NOW, NOW + 3_601);
    assert_eq!(
        registry.validate_descriptor(&overlong, NOW).err(),
        Some(InvitationLifecycleError::LifetimeExceedsPolicy {
            actual_seconds: 3_601,
            maximum_seconds: 3_600,
        })
    );

    assert_eq!(registry.record_count(), 0);
}

#[test]
fn only_locally_issued_live_records_consume_capacity() {
    let mut registry = registry(1);
    registry
        .issue(claims(0x61, NOW - 10, NOW + 1), &signing_key(0xa1), NOW)
        .expect("first local invitation fits");

    let remote = encoded_remote_invitation(0x62, 0xa2, NOW, NOW + 300);
    registry
        .validate_descriptor(&remote, NOW)
        .expect("remote validation does not consume capacity");
    assert_eq!(registry.record_count(), 1);

    assert_eq!(
        registry
            .issue(claims(0x63, NOW, NOW + 300), &signing_key(0xa3), NOW,)
            .err(),
        Some(InvitationLifecycleError::CapacityExceeded { maximum: 1 })
    );

    registry
        .issue(
            claims(0x64, NOW + 1, NOW + 301),
            &signing_key(0xa4),
            NOW + 1,
        )
        .expect("expired local state is pruned during later issuance");
    assert_eq!(registry.record_count(), 1);
    assert_eq!(registry.lifecycle(&[0x61; 16]), None);
}

#[test]
fn accepts_exact_time_boundaries_and_rejects_duplicate_local_identifiers() {
    let mut registry = registry(2);
    registry
        .issue(
            claims(0x68, NOW + 30, NOW + 30 + 3_600),
            &signing_key(0xa8),
            NOW,
        )
        .expect("exact future-skew and lifetime limits are accepted");

    assert_eq!(
        registry
            .issue(claims(0x68, NOW, NOW + 300), &signing_key(0xb8), NOW,)
            .err(),
        Some(InvitationLifecycleError::DuplicateInvitationId)
    );
    assert_eq!(registry.record_count(), 1);
}

#[test]
fn invalid_transition_tokens_and_policy_fail_closed() {
    assert_eq!(
        InvitationPolicy::new(0, 30, 4).err(),
        Some(InvitationLifecycleError::InvalidMaximumLifetime)
    );
    assert_eq!(
        InvitationPolicy::new(3_600, 30, 0).err(),
        Some(InvitationLifecycleError::InvalidCapacity)
    );

    let mut registry = registry(1);
    let issued = registry
        .issue(claims(0x71, NOW - 10, NOW + 300), &signing_key(0xa1), NOW)
        .expect("local issuance succeeds");
    let encoded = issued
        .encode_canonical()
        .expect("issued invitation encodes");
    let validated = registry
        .validate_descriptor(&encoded, NOW)
        .expect("descriptor validates");

    assert_eq!(
        registry
            .reserve_after_admission(&validated, [0; 16], NOW)
            .err(),
        Some(InvitationLifecycleError::ZeroJoinRequestId)
    );
}

#[test]
fn stale_reservation_cannot_mutate_a_reissued_invitation_instance() {
    for stale_action in ["release", "consume"] {
        let mut registry = registry(2);
        let first = registry
            .issue(claims(0x79, NOW, NOW + 1), &signing_key(0xa9), NOW)
            .expect("first invitation issues");
        let first_encoded = first.encode_canonical().expect("first invitation encodes");
        let first_validated = registry
            .validate_descriptor(&first_encoded, NOW)
            .expect("first invitation validates");
        let stale = registry
            .reserve_after_admission(&first_validated, [0xd1; 16], NOW)
            .expect("first reservation succeeds");

        let second = registry
            .issue(
                claims(0x79, NOW + 1, NOW + 301),
                &signing_key(0xb9),
                NOW + 1,
            )
            .expect("expired identifier can be deliberately reissued");
        let second_encoded = second
            .encode_canonical()
            .expect("second invitation encodes");
        let second_validated = registry
            .validate_descriptor(&second_encoded, NOW + 1)
            .expect("second invitation validates");
        let current = registry
            .reserve_after_admission(&second_validated, [0xd1; 16], NOW + 1)
            .expect("same request identifier can reserve the new instance");

        let stale_result = if stale_action == "release" {
            registry.release(stale, NOW + 1)
        } else {
            registry.consume_after_membership(stale, NOW + 1)
        };
        assert_eq!(
            stale_result.err(),
            Some(InvitationLifecycleError::ReservationMismatch)
        );
        assert_eq!(
            registry.lifecycle(&[0x79; 16]),
            Some(InvitationLifecycle::Reserved)
        );

        registry
            .consume_after_membership(current, NOW + 1)
            .expect("the current reservation remains authoritative");
    }
}
