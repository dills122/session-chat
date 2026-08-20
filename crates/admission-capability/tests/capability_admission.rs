use admission_capability::{
    CapabilityAdmissionError, CapabilityAdmissionPolicy, CapabilityAdmissionVerifier,
};
use ed25519_dalek::SigningKey;
use session_crypto_hpke::{
    AwsLcInvitationJoinProtector, InvitationJoinProtector, OpenedCapabilityJoinRequest,
};
use session_crypto_mls::{
    KeyPackageReference, SessionGroupId, create_client, create_key_package_validator,
};
use session_protocol::{
    CapabilityInvitationClaims, CapabilityInvitationV2Claims, CapabilityJoinRequest,
    DepositCapability, InvitationJoinBinding, JoinRequestBinding, LocalWelcomeDepositEndpoint,
    MlsKeyPackageBinding, SecretCapability, SignedCapabilityInvitationV2,
};

const NOW: u64 = 1_700_000_000;
const INVITATION_ID: [u8; 16] = [0x11; 16];
const CHALLENGE: [u8; 32] = [0x22; 32];
const KEY_ID: [u8; 16] = [0x33; 16];
const REQUEST_ID: [u8; 16] = [0x44; 16];
const NONCE: [u8; 32] = [0x55; 32];

fn group_id() -> SessionGroupId {
    SessionGroupId::new([0xaa; 32]).expect("nonzero group identifier")
}

#[derive(Clone, Copy)]
struct FixtureOptions {
    invitation_id: [u8; 16],
    challenge: [u8; 32],
    key_id: [u8; 16],
    signing_seed: [u8; 32],
    request_id: [u8; 16],
    nonce: [u8; 32],
    request_issued_at: u64,
    request_expires_at: u64,
    reference_override: Option<[u8; 32]>,
    credential_override: Option<[u8; 32]>,
    leaf_override: Option<[u8; 32]>,
    substitute_key_package: bool,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            invitation_id: INVITATION_ID,
            challenge: CHALLENGE,
            key_id: KEY_ID,
            signing_seed: [0xa5; 32],
            request_id: REQUEST_ID,
            nonce: NONCE,
            request_issued_at: NOW + 1,
            request_expires_at: NOW + 3_600,
            reference_override: None,
            credential_override: None,
            leaf_override: None,
            substitute_key_package: false,
        }
    }
}

struct OpenedFixture {
    opened: OpenedCapabilityJoinRequest,
    key_package_reference: KeyPackageReference,
}

fn opened_fixture(options: FixtureOptions) -> OpenedFixture {
    let hpke = AwsLcInvitationJoinProtector::new();
    let generated_hpke = hpke
        .generate_invitation_key()
        .expect("generate invitation HPKE key");
    let invitation_signing_key = SigningKey::from_bytes(&options.signing_seed);
    let claims = CapabilityInvitationClaims::new(
        options.invitation_id,
        NOW,
        NOW + 3_600,
        options.challenge,
        SecretCapability::new([0x66; 32]).expect("nonzero capability"),
    )
    .expect("valid invitation claims");
    let claims =
        CapabilityInvitationV2Claims::new(claims, options.key_id, *generated_hpke.public_key())
            .expect("valid invitation v2 claims");
    let invitation = SignedCapabilityInvitationV2::sign(claims, &invitation_signing_key)
        .expect("sign invitation");
    let invitation_private_key = generated_hpke.into_private_key();

    let joiner = create_client().expect("create joiner");
    let key_package = joiner
        .generate_key_package(NOW)
        .expect("generate KeyPackage");
    let validator = create_key_package_validator();
    let expected = validator
        .validate_key_package(key_package.as_bytes(), NOW)
        .expect("validate fixture KeyPackage");
    let substituted_key_package = if options.substitute_key_package {
        let substitute = create_client().expect("create substitute joiner");
        Some(
            substitute
                .generate_key_package(NOW)
                .expect("generate substitute KeyPackage"),
        )
    } else {
        None
    };
    let encoded_key_package = substituted_key_package
        .as_ref()
        .map_or(key_package.as_bytes(), |substitute| substitute.as_bytes());
    let invitation_binding = InvitationJoinBinding::new(
        options.invitation_id,
        options.challenge,
        options.key_id,
        invitation_signing_key.verifying_key().to_bytes(),
    )
    .expect("valid invitation binding");
    let request_binding = JoinRequestBinding::new(
        options.request_id,
        options.request_issued_at,
        options.request_expires_at,
        options.nonce,
    )
    .expect("valid request binding");
    let mls_binding = MlsKeyPackageBinding::new(
        options
            .reference_override
            .unwrap_or(*expected.key_package_reference()),
        encoded_key_package.to_vec(),
        options
            .credential_override
            .unwrap_or(*expected.credential_identity()),
        options
            .leaf_override
            .unwrap_or(*expected.leaf_signature_key()),
    )
    .expect("valid MLS binding");
    let response_endpoint = LocalWelcomeDepositEndpoint::new(
        [0x77; 16],
        [0x88; 16],
        DepositCapability::new([0x99; 32]).expect("nonzero deposit capability"),
        options.request_expires_at,
    )
    .expect("valid response endpoint");
    let request = CapabilityJoinRequest::new(
        invitation_binding,
        request_binding,
        mls_binding,
        response_endpoint,
    )
    .expect("valid request");
    let protected = hpke
        .seal_capability_request(&invitation, &request)
        .expect("seal request");
    let opened = hpke
        .open_capability_request(&invitation_private_key, &invitation, &protected)
        .expect("open request");

    OpenedFixture {
        opened,
        key_package_reference: *expected.key_package_reference(),
    }
}

#[test]
fn hpke_opened_request_reserves_exact_validated_key_package() {
    let fixture = opened_fixture(FixtureOptions::default());
    let policy = CapabilityAdmissionPolicy::new(3_600, 5, 8).expect("valid policy");
    let mut verifier = CapabilityAdmissionVerifier::new(policy);

    let verified = verifier
        .verify_and_reserve(fixture.opened, NOW + 1)
        .expect("verify exact admission binding");

    assert_eq!(verified.invitation_id(), &INVITATION_ID);
    assert_eq!(verified.join_request_id(), &REQUEST_ID);
    assert_eq!(
        verified.key_package_reference(),
        &fixture.key_package_reference
    );
    assert_eq!(verifier.pending_count(), 1);
}

#[test]
fn zero_lifetime_or_capacity_policy_is_rejected() {
    assert!(matches!(
        CapabilityAdmissionPolicy::new(0, 5, 8),
        Err(CapabilityAdmissionError::InvalidPolicy)
    ));
    assert!(matches!(
        CapabilityAdmissionPolicy::new(3_600, 5, 0),
        Err(CapabilityAdmissionError::InvalidPolicy)
    ));
}

#[test]
fn verified_admission_is_consumed_directly_into_mls_prepare_and_apply() {
    let fixture = opened_fixture(FixtureOptions::default());
    let policy = CapabilityAdmissionPolicy::new(3_600, 5, 8).expect("valid policy");
    let mut verifier = CapabilityAdmissionVerifier::new(policy);
    let verified = verifier
        .verify_and_reserve(fixture.opened, NOW + 1)
        .expect("verify admission");
    let alice = create_client().expect("create inviter");
    let mut group = alice.create_group(group_id(), NOW).expect("create group");

    let prepared = verifier
        .prepare_add(verified, &mut group, NOW + 1)
        .expect("prepare exact owned KeyPackage");
    assert_eq!(
        prepared.key_package_reference(),
        &fixture.key_package_reference
    );
    assert_eq!(prepared.current_group_epoch(), 0);
    let committed = prepared.apply().expect("apply prepared Add");

    assert_eq!(
        committed.key_package_reference(),
        &fixture.key_package_reference
    );
    assert_eq!(group.epoch(), 1);
    assert_eq!(group.member_count(), 2);
    assert_eq!(verifier.pending_count(), 1);
}

#[test]
fn abandoning_prepared_add_clears_mls_pending_state_and_replay_reservation() {
    let policy = CapabilityAdmissionPolicy::new(3_600, 5, 8).expect("valid policy");
    let mut verifier = CapabilityAdmissionVerifier::new(policy);
    let alice = create_client().expect("create inviter");
    let mut group = alice.create_group(group_id(), NOW).expect("create group");
    let verified = verifier
        .verify_and_reserve(opened_fixture(FixtureOptions::default()).opened, NOW + 1)
        .expect("verify admission");

    drop(
        verifier
            .prepare_add(verified, &mut group, NOW + 1)
            .expect("prepare Add"),
    );

    assert_eq!(group.epoch(), 0);
    assert_eq!(group.member_count(), 1);
    assert_eq!(verifier.pending_count(), 0);
    let replacement = verifier
        .verify_and_reserve(opened_fixture(FixtureOptions::default()).opened, NOW + 1)
        .expect("released request values can be retried");
    verifier.release(replacement).expect("release replacement");
}

#[test]
fn failed_mls_prepare_releases_replay_without_changing_membership() {
    let alice = create_client().expect("create inviter");
    let bob = create_client().expect("create existing peer");
    let bob_key_package = bob.generate_key_package(NOW).expect("generate KeyPackage");
    let validated = create_key_package_validator()
        .validate_key_package(bob_key_package.as_bytes(), NOW)
        .expect("validate existing peer");
    let mut group = alice.create_group(group_id(), NOW).expect("create group");
    group
        .prepare_add(validated, NOW)
        .expect("prepare existing peer")
        .apply()
        .expect("apply existing peer");

    let policy = CapabilityAdmissionPolicy::new(3_600, 5, 8).expect("valid policy");
    let mut verifier = CapabilityAdmissionVerifier::new(policy);
    let verified = verifier
        .verify_and_reserve(opened_fixture(FixtureOptions::default()).opened, NOW + 1)
        .expect("verify admission");

    assert!(matches!(
        verifier.prepare_add(verified, &mut group, NOW + 1),
        Err(CapabilityAdmissionError::Rejected)
    ));
    assert_eq!(group.epoch(), 1);
    assert_eq!(group.member_count(), 2);
    assert_eq!(verifier.pending_count(), 0);
}

#[test]
fn request_expiry_before_mls_prepare_releases_replay_and_leaves_group_unchanged() {
    let policy = CapabilityAdmissionPolicy::new(3_600, 5, 8).expect("valid policy");
    let mut verifier = CapabilityAdmissionVerifier::new(policy);
    let verified = verifier
        .verify_and_reserve(
            opened_fixture(FixtureOptions {
                request_expires_at: NOW + 10,
                ..FixtureOptions::default()
            })
            .opened,
            NOW + 1,
        )
        .expect("request is initially valid");
    let alice = create_client().expect("create inviter");
    let mut group = alice.create_group(group_id(), NOW).expect("create group");

    assert!(matches!(
        verifier.prepare_add(verified, &mut group, NOW + 10),
        Err(CapabilityAdmissionError::Rejected)
    ));
    assert_eq!(group.epoch(), 0);
    assert_eq!(group.member_count(), 1);
    assert_eq!(verifier.pending_count(), 0);
}

#[test]
fn another_verifier_cannot_consume_a_foreign_replay_reservation() {
    let policy = CapabilityAdmissionPolicy::new(3_600, 5, 8).expect("valid policy");
    let mut owning_verifier = CapabilityAdmissionVerifier::new(policy);
    let verified = owning_verifier
        .verify_and_reserve(opened_fixture(FixtureOptions::default()).opened, NOW + 1)
        .expect("owning verifier reserves request");
    let mut foreign_verifier = CapabilityAdmissionVerifier::new(policy);
    let alice = create_client().expect("create inviter");
    let mut group = alice.create_group(group_id(), NOW).expect("create group");

    assert!(matches!(
        foreign_verifier.prepare_add(verified, &mut group, NOW + 1),
        Err(CapabilityAdmissionError::ReservationMismatch)
    ));
    assert_eq!(group.epoch(), 0);
    assert_eq!(group.member_count(), 1);
    assert_eq!(owning_verifier.pending_count(), 1);
    assert_eq!(foreign_verifier.pending_count(), 0);
}

#[test]
fn key_package_reference_credential_and_leaf_substitution_leave_no_replay_state() {
    let alternate_leaf = SigningKey::from_bytes(&[0xb7; 32])
        .verifying_key()
        .to_bytes();
    let mismatches = [
        FixtureOptions {
            reference_override: Some([0xa1; 32]),
            ..FixtureOptions::default()
        },
        FixtureOptions {
            credential_override: Some([0xa2; 32]),
            ..FixtureOptions::default()
        },
        FixtureOptions {
            leaf_override: Some(alternate_leaf),
            ..FixtureOptions::default()
        },
        FixtureOptions {
            substitute_key_package: true,
            ..FixtureOptions::default()
        },
    ];
    let policy = CapabilityAdmissionPolicy::new(3_600, 5, 8).expect("valid policy");
    let mut verifier = CapabilityAdmissionVerifier::new(policy);

    for mismatch in mismatches {
        let result = verifier.verify_and_reserve(opened_fixture(mismatch).opened, NOW + 1);
        assert!(matches!(result, Err(CapabilityAdmissionError::Rejected)));
        assert_eq!(verifier.pending_count(), 0);
    }
}

#[test]
fn capacity_rejection_does_not_evict_or_replace_a_live_reservation() {
    let policy = CapabilityAdmissionPolicy::new(3_600, 5, 1).expect("valid policy");
    let mut verifier = CapabilityAdmissionVerifier::new(policy);
    verifier
        .verify_and_reserve(opened_fixture(FixtureOptions::default()).opened, NOW + 1)
        .expect("first request reserves the only slot");
    let another_generation = opened_fixture(FixtureOptions {
        invitation_id: [0x12; 16],
        challenge: [0x23; 32],
        key_id: [0x34; 16],
        signing_seed: [0xa6; 32],
        request_id: [0x45; 16],
        nonce: [0x56; 32],
        ..FixtureOptions::default()
    });

    assert!(matches!(
        verifier.verify_and_reserve(another_generation.opened, NOW + 1),
        Err(CapabilityAdmissionError::CapacityExceeded)
    ));
    assert_eq!(verifier.pending_count(), 1);
}

#[test]
fn public_errors_are_coarse_and_do_not_echo_key_or_capability_material() {
    assert_eq!(
        CapabilityAdmissionError::Rejected.to_string(),
        "capability admission rejected"
    );
    assert_eq!(
        format!("{:?}", CapabilityAdmissionError::Rejected),
        "Rejected"
    );
    assert!(
        !CapabilityAdmissionError::Rejected
            .to_string()
            .contains("6666")
    );
}

#[test]
fn expired_future_and_overlong_requests_leave_no_replay_state() {
    let policy = CapabilityAdmissionPolicy::new(120, 5, 8).expect("valid policy");
    let mut verifier = CapabilityAdmissionVerifier::new(policy);
    let expired = opened_fixture(FixtureOptions {
        request_expires_at: NOW + 10,
        ..FixtureOptions::default()
    });
    let future = opened_fixture(FixtureOptions {
        request_issued_at: NOW + 10,
        ..FixtureOptions::default()
    });
    let overlong = opened_fixture(FixtureOptions::default());

    for (opened, now) in [
        (expired.opened, NOW + 10),
        (future.opened, NOW + 1),
        (overlong.opened, NOW + 1),
    ] {
        assert!(matches!(
            verifier.verify_and_reserve(opened, now),
            Err(CapabilityAdmissionError::Rejected)
        ));
        assert_eq!(verifier.pending_count(), 0);
    }
}

#[test]
fn request_id_and_nonce_replays_fail_within_one_invitation_generation() {
    let policy = CapabilityAdmissionPolicy::new(3_600, 5, 8).expect("valid policy");
    let mut verifier = CapabilityAdmissionVerifier::new(policy);
    verifier
        .verify_and_reserve(opened_fixture(FixtureOptions::default()).opened, NOW + 1)
        .expect("first request reserves replay state");

    for replay in [
        FixtureOptions {
            nonce: [0x56; 32],
            ..FixtureOptions::default()
        },
        FixtureOptions {
            request_id: [0x45; 16],
            ..FixtureOptions::default()
        },
    ] {
        assert!(matches!(
            verifier.verify_and_reserve(opened_fixture(replay).opened, NOW + 1),
            Err(CapabilityAdmissionError::Replay)
        ));
        assert_eq!(verifier.pending_count(), 1);
    }
}

#[test]
fn same_request_values_are_independent_after_fresh_invitation_reissue() {
    let policy = CapabilityAdmissionPolicy::new(3_600, 5, 8).expect("valid policy");
    let mut verifier = CapabilityAdmissionVerifier::new(policy);
    verifier
        .verify_and_reserve(opened_fixture(FixtureOptions::default()).opened, NOW + 1)
        .expect("first generation reserves replay state");
    let reissued = opened_fixture(FixtureOptions {
        challenge: [0x23; 32],
        key_id: [0x34; 16],
        signing_seed: [0xa6; 32],
        ..FixtureOptions::default()
    });

    verifier
        .verify_and_reserve(reissued.opened, NOW + 1)
        .expect("fresh invitation generation has independent replay state");

    assert_eq!(verifier.pending_count(), 2);
}

#[test]
fn release_is_one_shot_and_stale_release_cannot_remove_replacement() {
    let policy = CapabilityAdmissionPolicy::new(3_600, 5, 8).expect("valid policy");
    let mut verifier = CapabilityAdmissionVerifier::new(policy);
    let stale = verifier
        .verify_and_reserve(
            opened_fixture(FixtureOptions {
                request_expires_at: NOW + 10,
                ..FixtureOptions::default()
            })
            .opened,
            NOW + 1,
        )
        .expect("short request reserves replay state");
    let replacement = verifier
        .verify_and_reserve(
            opened_fixture(FixtureOptions {
                request_issued_at: NOW + 10,
                request_expires_at: NOW + 20,
                ..FixtureOptions::default()
            })
            .opened,
            NOW + 10,
        )
        .expect("expired replay state is replaced safely");

    assert!(matches!(
        verifier.release(stale),
        Err(CapabilityAdmissionError::ReservationMismatch)
    ));
    assert_eq!(verifier.pending_count(), 1);
    verifier
        .release(replacement)
        .expect("current reservation releases once");
    assert_eq!(verifier.pending_count(), 0);
}
