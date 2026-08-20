#![forbid(unsafe_code)]

//! Headless Phase 1 composition and conformance flow.

use admission_capability::{
    CapabilityAdmissionPolicy, CapabilityAdmissionVerifier, CapabilityApprovalOutcome,
    ManualApprovalDecision,
};
use aws_lc_rs::rand;
use session_admission::{AdmissionMethod, PendingAdmission};
use session_core::{InvitationPolicy, InvitationRegistry};
use session_crypto::{MessageEvent, MessageSession, ProtectedMessage};
use session_crypto_hpke::{AwsLcInvitationJoinProtector, InvitationJoinProtector};
use session_crypto_mls::{
    SessionGroupId, WelcomeMessage, create_client, create_key_package_validator,
};
use session_protocol::{
    CapabilityJoinRequest, InvitationJoinBinding, JoinRequestBinding, MlsKeyPackageBinding,
    OpaqueEnvelope,
};
use session_transport::{EnvelopeTransport, LocalMailboxPolicy, LocalMemoryWelcomeTransport};
use thiserror::Error;
use transport_memory::{
    DeterministicMemoryTransport, MemoryAcknowledgementCapability, MemoryDepositEndpoint,
    MemoryMailboxPolicy, MemoryReceiveCapability,
};

const NOW: u64 = 1_900_000_000;
const MAILBOX_EXPIRES_AT: u64 = NOW + 240;
const REQUEST_EXPIRES_AT: u64 = NOW + 120;
const INVITATION_EXPIRES_AT: u64 = NOW + 300;

/// Coarse failure from the headless protocol-conformance flow.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionCtlError {
    /// One named protocol stage rejected its input or contradicted the expected state.
    #[error("headless Phase 1 flow failed at {0}")]
    Stage(&'static str),
}

/// Non-sensitive milestones observed during one complete headless flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseOneReport {
    admission_approved: bool,
    welcome_delivered: bool,
    joined_epoch: u64,
    application_messages_received: usize,
    updated_epoch: u64,
    removed: bool,
    post_removal_rejected: bool,
}

impl PhaseOneReport {
    /// Reports that an exact verified request received an explicit approval.
    #[must_use]
    pub const fn admission_approved(&self) -> bool {
        self.admission_approved
    }

    /// Reports that the one-shot Welcome traversed its right-specific mailbox.
    #[must_use]
    pub const fn welcome_delivered(&self) -> bool {
        self.welcome_delivered
    }

    /// Returns the MLS epoch held by both clients immediately after joining.
    #[must_use]
    pub const fn joined_epoch(&self) -> u64 {
        self.joined_epoch
    }

    /// Returns the number of bidirectional application messages authenticated.
    #[must_use]
    pub const fn application_messages_received(&self) -> usize {
        self.application_messages_received
    }

    /// Returns the epoch held by both clients after the path update.
    #[must_use]
    pub const fn updated_epoch(&self) -> u64 {
        self.updated_epoch
    }

    /// Reports that Bob authenticated the Commit removing him.
    #[must_use]
    pub const fn removed(&self) -> bool {
        self.removed
    }

    /// Reports that Bob rejected an otherwise valid message created after removal.
    #[must_use]
    pub const fn post_removal_rejected(&self) -> bool {
        self.post_removal_rejected
    }
}

/// Runs the in-memory, two-client Phase 1 protocol-conformance scenario.
///
/// This composes reviewed local adapters; it is not a network, durability,
/// anonymity, or production-hosting claim.
pub fn run_phase_one_demo() -> Result<PhaseOneReport, SessionCtlError> {
    let protector = AwsLcInvitationJoinProtector::new();
    let generated = protector
        .generate_capability_invitation(NOW, INVITATION_EXPIRES_AT)
        .map_err(|_| stage("invitation generation"))?;
    let mut invitation_registry = InvitationRegistry::new(
        InvitationPolicy::new(3_600, 5, 8).map_err(|_| stage("invitation policy"))?,
    );
    let issued = invitation_registry
        .issue_v2(generated, NOW)
        .map_err(|_| stage("invitation issue"))?;
    let encoded_invitation = issued
        .encode_canonical()
        .map_err(|_| stage("invitation encoding"))?;
    let validated_invitation = invitation_registry
        .validate_descriptor_v2(&encoded_invitation, NOW)
        .map_err(|_| stage("invitation validation"))?;

    let mut welcome_transport = LocalMemoryWelcomeTransport::new(
        LocalMailboxPolicy::new(300, 1).map_err(|_| stage("Welcome mailbox policy"))?,
    )
    .map_err(|_| stage("Welcome transport"))?;
    let (welcome_deposit, welcome_receive, welcome_acknowledgement) = welcome_transport
        .create_welcome_mailbox(REQUEST_EXPIRES_AT, NOW)
        .map_err(|_| stage("Welcome mailbox"))?
        .into_parts();

    let alice = create_client().map_err(|_| stage("Alice client"))?;
    let bob = create_client().map_err(|_| stage("Bob client"))?;
    let bob_key_package = bob
        .generate_key_package(NOW)
        .map_err(|_| stage("Bob KeyPackage"))?;
    let validated_key_package = create_key_package_validator()
        .validate_key_package(bob_key_package.as_bytes(), NOW)
        .map_err(|_| stage("KeyPackage validation"))?;
    let expected_key_package_reference = *validated_key_package.key_package_reference();

    let invitation_binding = InvitationJoinBinding::new(
        *issued.invitation().invitation_id(),
        *issued.invitation().join_challenge(),
        *issued.invitation().invitation_key_id(),
        *issued.invitation().inviter_verifying_key(),
    )
    .map_err(|_| stage("invitation binding"))?;
    let request_binding = JoinRequestBinding::new(
        random_nonzero()?,
        NOW,
        REQUEST_EXPIRES_AT,
        random_nonzero()?,
    )
    .map_err(|_| stage("request binding"))?;
    let mls_binding = MlsKeyPackageBinding::new(
        expected_key_package_reference,
        bob_key_package.as_bytes().to_vec(),
        *validated_key_package.credential_identity(),
        *validated_key_package.leaf_signature_key(),
    )
    .map_err(|_| stage("MLS binding"))?;
    let request = CapabilityJoinRequest::new(
        invitation_binding,
        request_binding,
        mls_binding,
        welcome_deposit,
    )
    .map_err(|_| stage("join request"))?;
    let protected_request = protector
        .seal_capability_request(issued.invitation(), &request)
        .map_err(|_| stage("join request protection"))?;
    let opened_request = protector
        .open_capability_request(
            issued.private_key(),
            issued.invitation(),
            &protected_request,
        )
        .map_err(|_| stage("join request opening"))?;

    let mut admission = CapabilityAdmissionVerifier::new(
        CapabilityAdmissionPolicy::new(3_600, 5, 8).map_err(|_| stage("admission policy"))?,
    );
    let verified = admission
        .verify_and_reserve(opened_request, NOW)
        .map_err(|_| stage("admission verification"))?;
    let pending = admission
        .reserve_v2_for_approval(
            &mut invitation_registry,
            &validated_invitation,
            verified,
            NOW,
        )
        .map_err(|_| stage("approval reservation"))?;
    let approval_context = pending.approval_context();
    if approval_context.method() != AdmissionMethod::SecretCapability
        || approval_context.key_package_reference() != &expected_key_package_reference
    {
        return Err(stage("approval context"));
    }
    let CapabilityApprovalOutcome::Approved(approved) = admission
        .decide_v2(
            &mut invitation_registry,
            pending,
            ManualApprovalDecision::Approve,
            NOW,
        )
        .map_err(|_| stage("approval decision"))?
    else {
        return Err(stage("approval decision"));
    };

    let mut alice_group = alice
        .create_group(
            SessionGroupId::new(random_nonzero()?).map_err(|_| stage("group ID"))?,
            NOW,
        )
        .map_err(|_| stage("Alice group"))?;
    let committed_join = admission
        .prepare_approved_add(&mut invitation_registry, approved, &mut alice_group, NOW)
        .map_err(|_| stage("MLS Add preparation"))?
        .apply(NOW)
        .map_err(|_| stage("MLS Add apply"))?;
    if committed_join.key_package_reference() != &expected_key_package_reference {
        return Err(stage("Welcome ownership"));
    }
    let (addition, response_endpoint) = committed_join.into_parts();
    let welcome_envelope = OpaqueEnvelope::new(
        random_nonzero()?,
        REQUEST_EXPIRES_AT,
        addition.welcome().as_bytes().to_vec(),
    )
    .map_err(|_| stage("Welcome envelope"))?;
    let welcome_delivery = welcome_transport
        .deposit(&response_endpoint, welcome_envelope, NOW)
        .map_err(|_| stage("Welcome deposit"))?;
    let received_welcome = welcome_transport
        .receive(&welcome_receive, NOW)
        .map_err(|_| stage("Welcome receive"))?
        .ok_or_else(|| stage("Welcome receive"))?;
    if received_welcome.delivery_id() != &welcome_delivery {
        return Err(stage("Welcome delivery identity"));
    }
    let welcome = WelcomeMessage::from_bytes(received_welcome.envelope().ciphertext())
        .map_err(|_| stage("Welcome framing"))?;
    let mut bob_group = bob
        .join_group(welcome, NOW)
        .map_err(|_| stage("Bob join"))?;
    welcome_transport
        .acknowledge(&welcome_acknowledgement, welcome_delivery, NOW)
        .map_err(|_| stage("Welcome acknowledgement"))?;
    if alice_group.epoch() != 1 || bob_group.epoch() != 1 {
        return Err(stage("joined epoch"));
    }

    let mut message_transport = DeterministicMemoryTransport::new(
        MemoryMailboxPolicy::new(300, 2, 8, 3).map_err(|_| stage("message mailbox policy"))?,
    )
    .map_err(|_| stage("message transport"))?;
    let (to_alice, alice_receive, alice_acknowledgement) = message_transport
        .create_mailbox(MAILBOX_EXPIRES_AT, NOW)
        .map_err(|_| stage("Alice message mailbox"))?
        .into_parts();
    let (to_bob, bob_receive, bob_acknowledgement) = message_transport
        .create_mailbox(MAILBOX_EXPIRES_AT, NOW)
        .map_err(|_| stage("Bob message mailbox"))?
        .into_parts();

    let alice_plaintext = b"hello from Alice";
    let protected = alice_group
        .protect_application_message(alice_plaintext)
        .map_err(|_| stage("Alice message protection"))?;
    let delivered = deliver_message(
        &mut message_transport,
        &to_bob,
        &bob_receive,
        &bob_acknowledgement,
        protected,
    )?;
    assert_application(
        bob_group
            .process_protected_message(delivered)
            .map_err(|_| stage("Bob message processing"))?,
        alice_plaintext,
    )?;

    let bob_plaintext = b"hello from Bob";
    let protected = bob_group
        .protect_application_message(bob_plaintext)
        .map_err(|_| stage("Bob message protection"))?;
    let delivered = deliver_message(
        &mut message_transport,
        &to_alice,
        &alice_receive,
        &alice_acknowledgement,
        protected,
    )?;
    assert_application(
        alice_group
            .process_protected_message(delivered)
            .map_err(|_| stage("Alice message processing"))?,
        bob_plaintext,
    )?;

    let update = alice_group
        .prepare_epoch_update(NOW)
        .map_err(|_| stage("path update preparation"))?
        .apply()
        .map_err(|_| stage("path update apply"))?
        .into_commit();
    let delivered_update = deliver_message(
        &mut message_transport,
        &to_bob,
        &bob_receive,
        &bob_acknowledgement,
        ProtectedMessage::from_bytes(update.as_bytes())
            .map_err(|_| stage("path update framing"))?,
    )?;
    if bob_group
        .process_protected_message(delivered_update)
        .map_err(|_| stage("path update processing"))?
        != MessageEvent::EpochAdvanced
        || alice_group.epoch() != 2
        || bob_group.epoch() != 2
    {
        return Err(stage("path update outcome"));
    }

    let removal = alice_group
        .prepare_remove_peer(NOW)
        .map_err(|_| stage("removal preparation"))?
        .apply()
        .map_err(|_| stage("removal apply"))?
        .into_commit();
    let delivered_removal = deliver_message(
        &mut message_transport,
        &to_bob,
        &bob_receive,
        &bob_acknowledgement,
        ProtectedMessage::from_bytes(removal.as_bytes()).map_err(|_| stage("removal framing"))?,
    )?;
    let removed = bob_group
        .process_protected_message(delivered_removal)
        .map_err(|_| stage("removal processing"))?
        == MessageEvent::Removed;
    if !removed || alice_group.epoch() != 3 || alice_group.member_count() != 1 {
        return Err(stage("removal outcome"));
    }

    let after_removal = alice_group
        .protect_application_message(b"message after removal")
        .map_err(|_| stage("post-removal protection"))?;
    let delivered_after_removal = deliver_message(
        &mut message_transport,
        &to_bob,
        &bob_receive,
        &bob_acknowledgement,
        after_removal,
    )?;
    let post_removal_rejected = bob_group
        .process_protected_message(delivered_after_removal)
        .is_err();
    if !post_removal_rejected {
        return Err(stage("post-removal rejection"));
    }

    Ok(PhaseOneReport {
        admission_approved: true,
        welcome_delivered: true,
        joined_epoch: 1,
        application_messages_received: 2,
        updated_epoch: 2,
        removed,
        post_removal_rejected,
    })
}

fn deliver_message(
    transport: &mut DeterministicMemoryTransport,
    endpoint: &MemoryDepositEndpoint,
    receive: &MemoryReceiveCapability,
    acknowledgement: &MemoryAcknowledgementCapability,
    message: ProtectedMessage,
) -> Result<ProtectedMessage, SessionCtlError> {
    let envelope = OpaqueEnvelope::new(random_nonzero()?, REQUEST_EXPIRES_AT, message.into_bytes())
        .map_err(|_| stage("message envelope"))?;
    let delivery_id = transport
        .deposit(endpoint, envelope, NOW)
        .map_err(|_| stage("message deposit"))?;
    let received = transport
        .receive(receive, NOW)
        .map_err(|_| stage("message receive"))?
        .ok_or_else(|| stage("message receive"))?;
    if received.delivery_id() != &delivery_id {
        return Err(stage("message delivery identity"));
    }
    let protected = ProtectedMessage::from_bytes(received.envelope().ciphertext())
        .map_err(|_| stage("message framing"))?;
    transport
        .acknowledge(acknowledgement, delivery_id, NOW)
        .map_err(|_| stage("message acknowledgement"))?;
    Ok(protected)
}

fn assert_application(event: MessageEvent, expected: &[u8]) -> Result<(), SessionCtlError> {
    let MessageEvent::Application(application) = event else {
        return Err(stage("application event"));
    };
    if application.as_bytes() != expected {
        return Err(stage("application content"));
    }
    Ok(())
}

fn random_nonzero<const N: usize>() -> Result<[u8; N], SessionCtlError> {
    let mut bytes = [0; N];
    rand::fill(&mut bytes).map_err(|_| stage("random provider"))?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(stage("random provider"));
    }
    Ok(bytes)
}

const fn stage(name: &'static str) -> SessionCtlError {
    SessionCtlError::Stage(name)
}
