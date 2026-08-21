use std::time::{Duration, Instant};

use session_protocol::OpaqueEnvelope;
use session_transport::{
    AdapterId, BoundedRetryDelay, CanonicalEnvelope, MAX_ADAPTER_ID_BYTES, MAX_RETRY_DELAY_SECONDS,
    OperationBudget, RetryAdvice, TransportContractError, TransportFailure, TransportFailureCode,
    TransportProfileId,
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
