use std::time::{Duration, Instant};

use session_protocol::OpaqueEnvelope;
use session_transport::{
    AcknowledgementReceipt, AcknowledgementRequest, AdapterId, BoundedDeliveryIds,
    BoundedRetryDelay, CanonicalEnvelope, Cursor, DeliveryId, DepositReceipt, DepositRequest,
    MAX_ACKNOWLEDGEMENT_IDS, MAX_ADAPTER_ID_BYTES, MAX_CURSOR_BYTES, MAX_POLL_ENCODED_BYTES,
    MAX_POLL_ENVELOPES, MAX_POLL_WAIT_SECONDS, MAX_RETRY_DELAY_SECONDS, OperationBudget,
    PollRequest, PollWait, ReceiveBatch, ReceivedCanonicalEnvelope, RetryAdvice,
    TransportContractError, TransportFailure, TransportFailureCode, TransportProfileId,
};

#[test]
fn reserved_profile_ids_round_trip_and_unknown_values_fail_closed() {
    let profiles = [
        (
            TransportProfileId::LocalV1,
            "session-chat.transport.local.v1",
        ),
        (TransportProfileId::FastV1, "session-chat.transport.fast.v1"),
        (
            TransportProfileId::PrivateInteractiveV1,
            "session-chat.transport.private-interactive.v1",
        ),
        (
            TransportProfileId::PrivateMixnetV1,
            "session-chat.transport.private-mixnet.v1",
        ),
        (
            TransportProfileId::OffGridV1,
            "session-chat.transport.off-grid.v1",
        ),
    ];

    for (profile, encoded) in profiles {
        assert_eq!(profile.as_str(), encoded);
        assert_eq!(TransportProfileId::try_from(encoded), Ok(profile));
    }
    assert_eq!(
        TransportProfileId::try_from("session-chat.transport.private-mixnet.v2"),
        Err(TransportContractError::UnsupportedProfile)
    );
    assert_eq!(
        TransportProfileId::try_from("katzenpost"),
        Err(TransportContractError::UnsupportedProfile)
    );
}

#[test]
fn adapter_ids_accept_only_bounded_local_diagnostic_names() {
    let adapter = AdapterId::new("session-chat.adapter.memory.v1").expect("valid adapter ID");
    assert_eq!(adapter.as_str(), "session-chat.adapter.memory.v1");

    for invalid in [
        "",
        "Memory",
        "memory adapter",
        "memory/adapter",
        ".memory",
        "memory-",
    ] {
        assert_eq!(
            AdapterId::new(invalid),
            Err(TransportContractError::InvalidAdapterId)
        );
    }

    let maximum = "a".repeat(MAX_ADAPTER_ID_BYTES);
    assert!(AdapterId::new(&maximum).is_ok());
    let oversized = "a".repeat(MAX_ADAPTER_ID_BYTES + 1);
    assert_eq!(
        AdapterId::new(&oversized),
        Err(TransportContractError::InvalidAdapterId)
    );
}

#[test]
fn canonical_envelope_owns_the_exact_protocol_encoding() {
    let opaque = OpaqueEnvelope::new([0x11; 16], 1_700_000_060, vec![0x22; 32])
        .expect("bounded protocol envelope");
    let expected = opaque.encode_canonical().expect("canonical encoding");

    let canonical = CanonicalEnvelope::from_opaque(opaque).expect("transport view");

    assert_eq!(canonical.as_bytes(), expected);
    assert_eq!(canonical.envelope_id().as_bytes(), &[0x11; 16]);
    assert_eq!(canonical.expires_at_unix_seconds(), 1_700_000_060);

    let reparsed = CanonicalEnvelope::from_canonical_bytes(expected).expect("validated bytes");
    assert_eq!(reparsed.as_bytes(), canonical.as_bytes());
    assert_eq!(
        reparsed.envelope_id().as_bytes(),
        canonical.envelope_id().as_bytes()
    );
}

#[test]
fn canonical_envelope_rejects_invalid_or_zero_identifier_input() {
    let zero_id = OpaqueEnvelope::new([0; 16], 1_700_000_060, vec![0x22; 32])
        .expect("wire layer permits structural identifier bytes");
    assert_eq!(
        CanonicalEnvelope::from_opaque(zero_id).err(),
        Some(TransportContractError::InvalidEnvelope)
    );
    assert_eq!(
        CanonicalEnvelope::from_canonical_bytes(vec![0xff]).err(),
        Some(TransportContractError::InvalidEnvelope)
    );
}

#[test]
fn operation_budget_requires_nonzero_finite_work_limits() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let budget = OperationBudget::new(deadline, 65_536, 3).expect("bounded operation");

    assert_eq!(budget.deadline(), deadline);
    assert_eq!(budget.max_network_bytes(), 65_536);
    assert_eq!(budget.max_attempts(), 3);
    assert_eq!(
        OperationBudget::new(deadline, 0, 3),
        Err(TransportContractError::InvalidOperationBudget)
    );
    assert_eq!(
        OperationBudget::new(deadline, 65_536, 0),
        Err(TransportContractError::InvalidOperationBudget)
    );
}

#[test]
fn retry_delay_is_bounded_before_it_enters_retry_advice() {
    let delay = BoundedRetryDelay::new(Duration::from_secs(30)).expect("bounded delay");
    assert_eq!(delay.duration(), Duration::from_secs(30));
    assert_eq!(RetryAdvice::After(delay), RetryAdvice::After(delay));

    assert_eq!(
        BoundedRetryDelay::new(Duration::ZERO),
        Err(TransportContractError::InvalidRetryDelay)
    );
    assert_eq!(
        BoundedRetryDelay::new(Duration::from_secs(MAX_RETRY_DELAY_SECONDS + 1)),
        Err(TransportContractError::InvalidRetryDelay)
    );
}

#[test]
fn normalized_failures_expose_only_code_and_retry_advice() {
    let failure = TransportFailure::new(TransportFailureCode::Unavailable, RetryAdvice::Backoff);

    assert_eq!(failure.code(), TransportFailureCode::Unavailable);
    assert_eq!(failure.retry_advice(), RetryAdvice::Backoff);
    assert_eq!(failure.to_string(), "transport operation failed");
    assert_eq!(
        format!("{failure:?}"),
        "TransportFailure { code: Unavailable, retry: Backoff }"
    );
}

#[test]
fn cursor_is_an_opaque_bounded_non_authority_value() {
    let cursor = Cursor::new(vec![0x41; MAX_CURSOR_BYTES]).expect("maximum cursor");
    assert_eq!(cursor.as_bytes(), &[0x41; MAX_CURSOR_BYTES]);
    assert_eq!(
        Cursor::new(Vec::new()).err(),
        Some(TransportContractError::InvalidCursor)
    );
    assert_eq!(
        Cursor::new(vec![0x42; MAX_CURSOR_BYTES + 1]).err(),
        Some(TransportContractError::InvalidCursor)
    );
}

#[test]
fn poll_request_enforces_count_byte_wait_and_operation_bounds() {
    let deadline = Instant::now() + Duration::from_secs(120);
    let budget = OperationBudget::new(deadline, u64::from(MAX_POLL_ENCODED_BYTES), 2)
        .expect("bounded operation");
    let cursor = Cursor::new(vec![0x51; 16]).expect("bounded cursor");
    let wait = PollWait::up_to(Duration::from_secs(MAX_POLL_WAIT_SECONDS)).expect("maximum wait");
    let request = PollRequest::new(
        Some(cursor),
        MAX_POLL_ENVELOPES,
        MAX_POLL_ENCODED_BYTES,
        wait,
        budget,
    )
    .expect("bounded poll request");

    assert_eq!(request.cursor().expect("cursor").as_bytes(), &[0x51; 16]);
    assert_eq!(request.max_envelopes(), MAX_POLL_ENVELOPES);
    assert_eq!(request.max_encoded_bytes(), MAX_POLL_ENCODED_BYTES);
    assert_eq!(request.wait().duration(), Duration::from_secs(60));
    assert_eq!(request.budget(), budget);

    assert_eq!(
        PollWait::up_to(Duration::ZERO),
        Err(TransportContractError::InvalidPollWait)
    );
    assert_eq!(
        PollWait::up_to(Duration::from_secs(MAX_POLL_WAIT_SECONDS + 1)),
        Err(TransportContractError::InvalidPollWait)
    );
    assert_eq!(
        PollRequest::new(None, 0, 1, PollWait::immediate(), budget).err(),
        Some(TransportContractError::InvalidPollRequest)
    );
    assert_eq!(
        PollRequest::new(
            None,
            MAX_POLL_ENVELOPES + 1,
            1,
            PollWait::immediate(),
            budget,
        )
        .err(),
        Some(TransportContractError::InvalidPollRequest)
    );
    assert_eq!(
        PollRequest::new(
            None,
            1,
            MAX_POLL_ENCODED_BYTES + 1,
            PollWait::immediate(),
            budget,
        )
        .err(),
        Some(TransportContractError::InvalidPollRequest)
    );

    let smaller_budget = OperationBudget::new(deadline, 1_024, 1).expect("small budget");
    assert_eq!(
        PollRequest::new(None, 1, 1_025, PollWait::immediate(), smaller_budget).err(),
        Some(TransportContractError::InvalidPollRequest)
    );
}

#[test]
fn deposit_request_owns_one_canonical_envelope_and_finite_budget() {
    let opaque =
        OpaqueEnvelope::new([0x61; 16], 1_700_000_060, vec![0x62; 32]).expect("bounded envelope");
    let expected = opaque.encode_canonical().expect("canonical bytes");
    let budget = OperationBudget::new(Instant::now() + Duration::from_secs(5), 65_536, 1)
        .expect("bounded operation");
    let request = DepositRequest::new(
        CanonicalEnvelope::from_opaque(opaque).expect("canonical envelope"),
        budget,
    )
    .expect("envelope fits byte budget");

    assert_eq!(request.envelope().as_bytes(), expected);
    assert_eq!(request.budget(), budget);
    let (envelope, returned_budget) = request.into_parts();
    assert_eq!(envelope.as_bytes(), expected);
    assert_eq!(returned_budget, budget);

    let oversized_for_budget = OpaqueEnvelope::new([0x63; 16], 1_700_000_060, vec![0x64; 1_024])
        .expect("protocol-bounded envelope");
    let tiny_budget = OperationBudget::new(Instant::now() + Duration::from_secs(5), 128, 1)
        .expect("finite but insufficient budget");
    assert_eq!(
        DepositRequest::new(
            CanonicalEnvelope::from_opaque(oversized_for_budget).expect("canonical envelope"),
            tiny_budget,
        )
        .err(),
        Some(TransportContractError::InvalidDepositRequest)
    );
}

#[test]
fn acknowledgement_request_bounds_identifiers_without_turning_them_into_authority() {
    let ids = (1..=MAX_ACKNOWLEDGEMENT_IDS)
        .map(|value| {
            DeliveryId::from_provider_bytes([u8::try_from(value).expect("small bound"); 16])
                .expect("nonzero delivery ID")
        })
        .collect::<Vec<_>>();
    let bounded = BoundedDeliveryIds::new(ids).expect("maximum acknowledgement batch");
    assert_eq!(bounded.len(), usize::from(MAX_ACKNOWLEDGEMENT_IDS));
    assert!(!bounded.is_empty());
    assert_eq!(
        BoundedDeliveryIds::new(Vec::new()).err(),
        Some(TransportContractError::InvalidAcknowledgementBatch)
    );

    let oversized = (0..=MAX_ACKNOWLEDGEMENT_IDS)
        .map(|value| {
            DeliveryId::from_provider_bytes([u8::try_from(value + 1).expect("small bound"); 16])
                .expect("nonzero delivery ID")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        BoundedDeliveryIds::new(oversized).err(),
        Some(TransportContractError::InvalidAcknowledgementBatch)
    );

    let budget = OperationBudget::new(Instant::now() + Duration::from_secs(5), 4_096, 1)
        .expect("bounded operation");
    let request = AcknowledgementRequest::new(bounded, budget);
    assert_eq!(request.delivery_ids().len(), 64);
    assert_eq!(request.budget(), budget);
}

#[test]
fn receipts_reveal_only_normalized_non_authorizing_outcomes() {
    let delivery_id = DeliveryId::from_provider_bytes([0x71; 16]).expect("delivery ID");
    let deposit = DepositReceipt::accepted(delivery_id);
    assert_eq!(deposit.delivery_id(), &delivery_id);
    assert_eq!(
        AcknowledgementReceipt::accepted(),
        AcknowledgementReceipt::accepted()
    );
}

#[test]
fn receive_batch_enforces_request_count_bytes_and_post_receive_expiry() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let budget = OperationBudget::new(deadline, 256, 1).expect("bounded operation");
    let request = PollRequest::new(None, 2, 128, PollWait::immediate(), budget)
        .expect("bounded poll request");
    let first = ReceivedCanonicalEnvelope::new(
        DeliveryId::from_provider_bytes([0x81; 16]).expect("delivery ID"),
        CanonicalEnvelope::from_opaque(
            OpaqueEnvelope::new([0x82; 16], 1_700_000_060, vec![0x83; 16])
                .expect("bounded envelope"),
        )
        .expect("canonical envelope"),
    );
    let second = ReceivedCanonicalEnvelope::new(
        DeliveryId::from_provider_bytes([0x84; 16]).expect("delivery ID"),
        CanonicalEnvelope::from_opaque(
            OpaqueEnvelope::new([0x85; 16], 1_700_000_060, vec![0x86; 16])
                .expect("bounded envelope"),
        )
        .expect("canonical envelope"),
    );
    let expected_first_id = *first.delivery_id();
    let next_cursor = Cursor::new(vec![0x87; 16]).expect("bounded cursor");

    let batch = ReceiveBatch::new(
        vec![first, second],
        Some(next_cursor),
        &request,
        1_700_000_000,
    )
    .expect("batch fits request");
    assert_eq!(batch.len(), 2);
    assert!(!batch.is_empty());
    assert_eq!(batch.items()[0].delivery_id(), &expected_first_id);
    assert_eq!(
        batch.next_cursor().expect("continuation").as_bytes(),
        &[0x87; 16]
    );

    let empty = ReceiveBatch::new(Vec::new(), None, &request, 1_700_000_000)
        .expect("empty poll result is valid");
    assert!(empty.is_empty());
}

#[test]
fn receive_batch_rejects_excess_items_bytes_and_expired_envelopes() {
    fn item(id: u8, expires_at: u64, ciphertext_bytes: usize) -> ReceivedCanonicalEnvelope {
        ReceivedCanonicalEnvelope::new(
            DeliveryId::from_provider_bytes([id; 16]).expect("delivery ID"),
            CanonicalEnvelope::from_opaque(
                OpaqueEnvelope::new([id; 16], expires_at, vec![id; ciphertext_bytes])
                    .expect("bounded envelope"),
            )
            .expect("canonical envelope"),
        )
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    let budget = OperationBudget::new(deadline, 512, 1).expect("bounded operation");
    let one_item = PollRequest::new(None, 1, 512, PollWait::immediate(), budget)
        .expect("bounded poll request");
    assert_eq!(
        ReceiveBatch::new(
            vec![item(0x91, 1_700_000_060, 16), item(0x92, 1_700_000_060, 16),],
            None,
            &one_item,
            1_700_000_000,
        )
        .err(),
        Some(TransportContractError::InvalidReceiveBatch)
    );

    let tiny_bytes =
        PollRequest::new(None, 2, 32, PollWait::immediate(), budget).expect("bounded poll request");
    assert_eq!(
        ReceiveBatch::new(
            vec![item(0x93, 1_700_000_060, 32)],
            None,
            &tiny_bytes,
            1_700_000_000,
        )
        .err(),
        Some(TransportContractError::InvalidReceiveBatch)
    );

    assert_eq!(
        ReceiveBatch::new(
            vec![item(0x94, 1_700_000_000, 16)],
            None,
            &one_item,
            1_700_000_000,
        )
        .err(),
        Some(TransportContractError::ExpiredReceivedEnvelope)
    );
}
