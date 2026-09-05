use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use session_protocol::{DepositCapability, LocalWelcomeDepositEndpoint, OpaqueEnvelope};
use session_transport::{
    AcknowledgementReceipt, AcknowledgementRequest, AcknowledgementRight, BindingFingerprint,
    BoundedDeliveryIds, CanonicalEnvelope, Cursor, CursorBindingV1, CursorSchemaVersion,
    DeliveryId, DepositReceipt, DepositRequest, DepositRight, DispatchControl, EnvelopeDelivery,
    LifecycleProviderContractV1, LocalMailboxPolicy, LocalMemoryWelcomeTransport,
    LocalTransportError, MailboxContinuityId, MailboxGeneration, MailboxIssueRequestV1,
    MailboxIssueResultV1, MailboxLifecycle, MailboxRotationResultV1, OperationBudget, PollRequest,
    PollWait, ProviderStateEpoch, ReceiveBatch, ReceiveRight, ReceiveScopeFingerprint, RetryAdvice,
    RotationId, RotationModeV1, RotationRequestV1, RotationRight, TransportFailure,
    TransportFailureCode, TransportProfileId,
};

const NOW: u64 = 1_700_000_000;

fn ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test provider unexpectedly remained pending"),
    }
}

struct TestControl(Instant);

impl DispatchControl for TestControl {
    fn monotonic_now(&self) -> Instant {
        self.0
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        Some(NOW)
    }

    fn is_cancelled(&self) -> bool {
        false
    }
}

struct RejectingLifecycle;

struct RejectingDelivery;

impl EnvelopeDelivery for RejectingDelivery {
    type DepositEndpoint = [u8; 32];
    type ReceiveCapability = [u8; 32];
    type AcknowledgementCapability = [u8; 32];

    fn deposit<'a>(
        &'a mut self,
        _endpoint: &'a DepositRight<Self::DepositEndpoint>,
        _request: DepositRequest,
        _control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<DepositReceipt, TransportFailure>> + Send + 'a {
        std::future::ready(Err(TransportFailure::new(
            TransportFailureCode::InvalidAuthority,
            RetryAdvice::Never,
        )))
    }

    fn poll<'a>(
        &'a mut self,
        _authority: &'a ReceiveRight<Self::ReceiveCapability>,
        _request: PollRequest,
        _control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<ReceiveBatch, TransportFailure>> + Send + 'a {
        std::future::ready(Err(TransportFailure::new(
            TransportFailureCode::InvalidAuthority,
            RetryAdvice::Never,
        )))
    }

    fn acknowledge<'a>(
        &'a mut self,
        _authority: &'a AcknowledgementRight<Self::AcknowledgementCapability>,
        _request: AcknowledgementRequest,
        _control: &'a dyn DispatchControl,
    ) -> impl Future<Output = Result<AcknowledgementReceipt, TransportFailure>> + Send + 'a {
        std::future::ready(Err(TransportFailure::new(
            TransportFailureCode::InvalidAuthority,
            RetryAdvice::Never,
        )))
    }
}

impl MailboxLifecycle for RejectingLifecycle {
    type DepositEndpoint = [u8; 32];
    type ReceiveCapability = [u8; 32];
    type AcknowledgementCapability = [u8; 32];
    type RotationCapability = [u8; 32];

    fn lifecycle_contract(&self) -> LifecycleProviderContractV1 {
        LifecycleProviderContractV1::new(
            TransportProfileId::FastV1,
            CursorSchemaVersion::new(1).expect("cursor schema"),
            60,
        )
        .expect("lifecycle contract")
    }

    fn issue<'a>(
        &'a mut self,
        _expected_contract: LifecycleProviderContractV1,
        _request: MailboxIssueRequestV1,
        _control: &'a dyn DispatchControl,
    ) -> impl Future<
        Output = Result<
            MailboxIssueResultV1<
                Self::DepositEndpoint,
                Self::ReceiveCapability,
                Self::AcknowledgementCapability,
                Self::RotationCapability,
            >,
            TransportFailure,
        >,
    > + Send
    + 'a {
        std::future::ready(Err(TransportFailure::new(
            TransportFailureCode::InvalidAuthority,
            RetryAdvice::Never,
        )))
    }

    fn rotate<'a>(
        &'a mut self,
        _expected_contract: LifecycleProviderContractV1,
        _authority: &'a RotationRight<Self::RotationCapability>,
        _request: RotationRequestV1,
        _control: &'a dyn DispatchControl,
    ) -> impl Future<
        Output = Result<
            MailboxRotationResultV1<
                Self::DepositEndpoint,
                Self::ReceiveCapability,
                Self::AcknowledgementCapability,
                Self::RotationCapability,
            >,
            TransportFailure,
        >,
    > + Send
    + 'a {
        std::future::ready(Err(TransportFailure::new(
            TransportFailureCode::InvalidAuthority,
            RetryAdvice::Never,
        )))
    }
}

#[test]
fn rejected_deposit_diagnostics_exclude_seeded_authority_and_envelope_bytes() {
    let policy = LocalMailboxPolicy::new(60, 1).expect("bounded policy");
    let mut transport = LocalMemoryWelcomeTransport::new(policy).expect("local transport");
    let seeded_authority = [b'S'; 32];
    let seeded_ciphertext = vec![b'C'; 48];
    let foreign_endpoint = LocalWelcomeDepositEndpoint::new(
        [0x41; 16],
        [0x42; 16],
        DepositCapability::new(seeded_authority).expect("nonzero deposit authority"),
        NOW + 60,
    )
    .expect("structurally valid foreign endpoint");
    let envelope = OpaqueEnvelope::new([0x43; 16], NOW + 30, seeded_ciphertext.clone())
        .expect("bounded opaque envelope");

    let failure = transport
        .deposit(&foreign_endpoint, envelope, NOW)
        .expect_err("foreign endpoint must fail closed");
    let diagnostics = format!("{failure:?} {failure}");

    assert_eq!(failure, LocalTransportError::Rejected);
    assert_eq!(diagnostics, "Rejected local mailbox operation rejected");
    assert!(
        !diagnostics
            .as_bytes()
            .windows(seeded_authority.len())
            .any(|window| window == seeded_authority)
    );
    assert!(
        !diagnostics
            .as_bytes()
            .windows(seeded_ciphertext.len())
            .any(|window| window == seeded_ciphertext)
    );
}

#[test]
fn generalized_delivery_failure_diagnostics_exclude_every_seeded_authority_type() {
    let start = Instant::now();
    let control = TestControl(start);
    let budget =
        OperationBudget::new(start + Duration::from_secs(30), 4_096, 1).expect("bounded operation");
    let seeded_deposit = [b'D'; 32];
    let seeded_receive = [b'R'; 32];
    let seeded_acknowledgement = [b'A'; 32];
    let seeded_ciphertext = vec![b'X'; 48];
    let deposit = DepositRight::from_provider(seeded_deposit);
    let receive = ReceiveRight::from_provider(seeded_receive);
    let acknowledgement = AcknowledgementRight::from_provider(seeded_acknowledgement);
    let envelope = OpaqueEnvelope::new([0x73; 16], NOW + 60, seeded_ciphertext.clone())
        .expect("opaque envelope");
    let deposit_request = DepositRequest::new(
        CanonicalEnvelope::from_opaque(envelope).expect("canonical envelope"),
        budget,
    )
    .expect("deposit request");
    let poll_request = PollRequest::new(
        Some(Cursor::new(vec![b'U'; 32]).expect("cursor")),
        1,
        4_096,
        PollWait::immediate(),
        budget,
    )
    .expect("poll request");
    let acknowledgement_request = AcknowledgementRequest::new(
        BoundedDeliveryIds::new(vec![
            DeliveryId::from_provider_bytes([b'I'; 16]).expect("delivery ID"),
        ])
        .expect("acknowledgement IDs"),
        budget,
    );
    let mut provider = RejectingDelivery;

    let deposit_failure = match ready(provider.deposit(&deposit, deposit_request, &control)) {
        Ok(_) => panic!("seeded deposit must fail closed"),
        Err(failure) => failure,
    };
    let poll_failure = match ready(provider.poll(&receive, poll_request, &control)) {
        Ok(_) => panic!("seeded poll must fail closed"),
        Err(failure) => failure,
    };
    let acknowledgement_failure =
        match ready(provider.acknowledge(&acknowledgement, acknowledgement_request, &control)) {
            Ok(_) => panic!("seeded acknowledgement must fail closed"),
            Err(failure) => failure,
        };
    let diagnostics = format!(
        "{deposit_failure:?} {deposit_failure} {poll_failure:?} {poll_failure} \
         {acknowledgement_failure:?} {acknowledgement_failure}"
    );

    for secret in [
        seeded_deposit.as_slice(),
        seeded_receive.as_slice(),
        seeded_acknowledgement.as_slice(),
        seeded_ciphertext.as_slice(),
    ] {
        assert!(
            !diagnostics
                .as_bytes()
                .windows(secret.len())
                .any(|window| window == secret)
        );
    }
}

#[test]
fn lifecycle_failure_diagnostics_exclude_seeded_scope_and_rotation_authority() {
    let start = Instant::now();
    let control = TestControl(start);
    let budget =
        OperationBudget::new(start + Duration::from_secs(30), 4_096, 1).expect("bounded operation");
    let seeded_binding = [b'B'; 32];
    let seeded_continuity = [b'C'; 16];
    let seeded_scope = [b'S'; 32];
    let seeded_rotation = [b'R'; 32];
    let predecessor = CursorBindingV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes(seeded_binding).expect("binding fingerprint"),
        MailboxContinuityId::from_provider_bytes(seeded_continuity).expect("continuity ID"),
        MailboxGeneration::new(1).expect("generation"),
        ReceiveScopeFingerprint::from_bytes(seeded_scope).expect("receive scope"),
        CursorSchemaVersion::new(1).expect("cursor schema"),
        ProviderStateEpoch::new(1).expect("provider epoch"),
        NOW + 60,
    )
    .expect("predecessor binding");
    let request = RotationRequestV1::new(
        RotationId::from_provider_bytes([b'I'; 16]).expect("rotation ID"),
        predecessor,
        RotationModeV1::Compromise,
        NOW + 120,
        budget,
    )
    .expect("rotation request");
    let authority = RotationRight::from_provider(seeded_rotation);
    let mut provider = RejectingLifecycle;

    let expected_contract = provider.lifecycle_contract();
    let failure = match ready(provider.rotate(expected_contract, &authority, request, &control)) {
        Ok(_) => panic!("seeded lifecycle request must fail closed"),
        Err(failure) => failure,
    };
    let diagnostics = format!("{failure:?} {failure}");

    for secret in [
        seeded_binding.as_slice(),
        seeded_continuity.as_slice(),
        seeded_scope.as_slice(),
        seeded_rotation.as_slice(),
    ] {
        assert!(
            !diagnostics
                .as_bytes()
                .windows(secret.len())
                .any(|window| window == secret)
        );
    }
}
