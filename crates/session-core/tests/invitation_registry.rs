use ed25519_dalek::SigningKey;
use session_core::{
    AcceptedCapabilityInvitation, InvitationAcceptanceError, InvitationAcceptancePolicy,
    InvitationRegistry,
};
use session_protocol::{CapabilityInvitationClaims, SecretCapability, SignedCapabilityInvitation};

const NOW: u64 = 1_700_000_000;

fn encoded_invitation(id_byte: u8, signing_seed: u8, issued_at: u64, expires_at: u64) -> Vec<u8> {
    let claims = CapabilityInvitationClaims::new(
        [id_byte; 16],
        issued_at,
        expires_at,
        [id_byte.wrapping_add(1); 32],
        SecretCapability::new([id_byte.wrapping_add(2); 32]).expect("test capability is nonzero"),
    )
    .expect("test claims are structurally valid");
    let key = SigningKey::from_bytes(&[signing_seed; 32]);

    SignedCapabilityInvitation::sign(claims, &key)
        .expect("test invitation signs")
        .encode_canonical()
        .expect("test invitation encodes")
}

fn registry(capacity: usize) -> InvitationRegistry {
    let policy = InvitationAcceptancePolicy::new(3_600, 30, capacity)
        .expect("test acceptance policy is valid");
    InvitationRegistry::new(policy)
}

fn accept(
    registry: &mut InvitationRegistry,
    encoded: &[u8],
    now: u64,
) -> Result<AcceptedCapabilityInvitation, InvitationAcceptanceError> {
    registry.accept(encoded, now)
}

#[test]
fn accepts_an_authenticated_current_invitation_exactly_once() {
    let encoded = encoded_invitation(0x11, 0xa1, NOW - 10, NOW + 300);
    let mut registry = registry(4);

    let accepted = accept(&mut registry, &encoded, NOW).expect("first use is accepted");
    assert_eq!(accepted.invitation_id(), &[0x11; 16]);
    assert_eq!(accepted.expires_at_unix_seconds(), NOW + 300);
    assert_eq!(registry.consumed_count(), 1);

    assert_eq!(
        accept(&mut registry, &encoded, NOW).err(),
        Some(InvitationAcceptanceError::AlreadyConsumed)
    );
    assert_eq!(registry.consumed_count(), 1);
}

#[test]
fn rejects_the_same_id_even_when_another_key_signs_different_valid_claims() {
    let first = encoded_invitation(0x22, 0xa1, NOW - 10, NOW + 300);
    let second = encoded_invitation(0x22, 0xb2, NOW - 5, NOW + 600);
    let mut registry = registry(4);

    accept(&mut registry, &first, NOW).expect("first descriptor consumes the id");

    assert_eq!(
        accept(&mut registry, &second, NOW).err(),
        Some(InvitationAcceptanceError::AlreadyConsumed)
    );
    assert_eq!(registry.consumed_count(), 1);
}

#[test]
fn rejects_expired_future_and_overlong_invitations_without_mutation() {
    let mut registry = registry(4);

    let expired = encoded_invitation(0x31, 0xa1, NOW - 60, NOW);
    assert_eq!(
        accept(&mut registry, &expired, NOW).err(),
        Some(InvitationAcceptanceError::Expired {
            expires_at: NOW,
            now: NOW,
        })
    );

    let future = encoded_invitation(0x32, 0xa2, NOW + 31, NOW + 300);
    assert_eq!(
        accept(&mut registry, &future, NOW).err(),
        Some(InvitationAcceptanceError::IssuedTooFarInFuture {
            issued_at: NOW + 31,
            latest_allowed: NOW + 30,
        })
    );

    let overlong = encoded_invitation(0x33, 0xa3, NOW, NOW + 3_601);
    assert_eq!(
        accept(&mut registry, &overlong, NOW).err(),
        Some(InvitationAcceptanceError::LifetimeExceedsPolicy {
            actual_seconds: 3_601,
            maximum_seconds: 3_600,
        })
    );

    assert_eq!(registry.consumed_count(), 0);
}

#[test]
fn accepts_exact_future_skew_and_lifetime_boundaries() {
    let encoded = encoded_invitation(0x34, 0xa4, NOW + 30, NOW + 30 + 3_600);
    let mut registry = registry(1);

    let accepted = accept(&mut registry, &encoded, NOW).expect("exact policy limits are accepted");

    assert_eq!(accepted.invitation_id(), &[0x34; 16]);
    assert_eq!(registry.consumed_count(), 1);
}

#[test]
fn rejects_tampering_before_consuming_replay_state() {
    let mut encoded = encoded_invitation(0x41, 0xa1, NOW - 10, NOW + 300);
    let last = encoded.len() - 1;
    encoded[last] ^= 0x01;
    let mut registry = registry(4);

    assert!(matches!(
        accept(&mut registry, &encoded, NOW),
        Err(InvitationAcceptanceError::Protocol(_))
    ));
    assert_eq!(registry.consumed_count(), 0);
}

#[test]
fn bounds_capacity_without_mutating_on_rejection() {
    let first = encoded_invitation(0x51, 0xa1, NOW - 10, NOW + 300);
    let second = encoded_invitation(0x52, 0xa2, NOW - 10, NOW + 300);
    let mut registry = registry(1);

    accept(&mut registry, &first, NOW).expect("first invitation fits");
    assert_eq!(
        accept(&mut registry, &second, NOW).err(),
        Some(InvitationAcceptanceError::CapacityExceeded { maximum: 1 })
    );
    assert_eq!(registry.consumed_count(), 1);
}

#[test]
fn prunes_expired_entries_only_when_a_new_invitation_is_accepted() {
    let short = encoded_invitation(0x61, 0xa1, NOW - 10, NOW + 1);
    let later = encoded_invitation(0x62, 0xa2, NOW, NOW + 300);
    let rejected = encoded_invitation(0x63, 0xa3, NOW, NOW + 301);
    let mut registry = registry(1);

    accept(&mut registry, &short, NOW).expect("short invitation is initially current");
    assert_eq!(
        accept(&mut registry, &rejected, NOW).err(),
        Some(InvitationAcceptanceError::CapacityExceeded { maximum: 1 })
    );
    assert_eq!(registry.consumed_count(), 1);

    accept(&mut registry, &later, NOW + 1).expect("expired entry is replaced atomically");
    assert_eq!(registry.consumed_count(), 1);
}

#[test]
fn rejects_zero_lifetime_or_capacity_policy() {
    assert_eq!(
        InvitationAcceptancePolicy::new(0, 30, 4).err(),
        Some(InvitationAcceptanceError::InvalidMaximumLifetime)
    );
    assert_eq!(
        InvitationAcceptancePolicy::new(3_600, 30, 0).err(),
        Some(InvitationAcceptanceError::InvalidCapacity)
    );
}
