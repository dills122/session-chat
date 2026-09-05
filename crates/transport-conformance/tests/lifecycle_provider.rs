use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use session_transport::{
    BindingFingerprint, CursorSchemaVersion, DispatchControl, LifecycleProviderContractV1,
    MailboxIssueRequestV1, MailboxLifecycle, OperationBudget, RotationId, RotationModeV1,
    RotationRequestV1, TransportFailureCode, TransportProfileId,
};
use transport_conformance::DeterministicLifecycleProviderV1;

const NOW: u64 = 1_700_000_000;

struct FixedControl {
    monotonic: Instant,
    wall: u64,
}

impl DispatchControl for FixedControl {
    fn monotonic_now(&self) -> Instant {
        self.monotonic
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        Some(self.wall)
    }

    fn is_cancelled(&self) -> bool {
        false
    }
}

fn operation() -> (FixedControl, OperationBudget) {
    let monotonic = Instant::now();
    let budget = OperationBudget::new(monotonic + Duration::from_secs(30), 65_536, 1)
        .expect("bounded operation");
    (
        FixedControl {
            monotonic,
            wall: NOW,
        },
        budget,
    )
}

fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("deterministic lifecycle operation must be immediately ready"),
    }
}

fn issue_request(fingerprint: u8, budget: OperationBudget) -> MailboxIssueRequestV1 {
    MailboxIssueRequestV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([fingerprint; 32]).expect("binding fingerprint"),
        NOW + 600,
        budget,
    )
    .expect("issue request")
}

#[test]
fn deterministic_provider_issues_and_rotates_one_exact_generation() {
    let mut provider = DeterministicLifecycleProviderV1::new();
    let contract = provider.lifecycle_contract();
    let (control, budget) = operation();
    let issued = ready(provider.issue(contract, issue_request(0x11, budget), &control))
        .expect("issue generation");
    let (predecessor, _deposit, _receive, _acknowledgement, rotation) =
        issued.into_authorities().into_parts();

    assert_eq!(predecessor.generation().get(), 1);
    assert_eq!(predecessor.profile(), TransportProfileId::FastV1);

    let rotation_id = RotationId::from_provider_bytes([0x41; 16]).expect("rotation ID");
    let request = RotationRequestV1::new(
        rotation_id,
        predecessor,
        RotationModeV1::Routine {
            drain_predecessor_until_unix_seconds: NOW + 120,
        },
        NOW + 1_200,
        budget,
    )
    .expect("routine rotation");
    let rotated =
        ready(provider.rotate(contract, &rotation, request, &control)).expect("rotate generation");
    let successor = *rotated.authorities().binding();

    assert_eq!(successor.generation().get(), 2);
    assert!(successor.continuity_id() == predecessor.continuity_id());
    assert!(successor.receive_scope() != predecessor.receive_scope());

    let retry = RotationRequestV1::new(
        rotation_id,
        predecessor,
        RotationModeV1::Routine {
            drain_predecessor_until_unix_seconds: NOW + 120,
        },
        NOW + 1_200,
        budget,
    )
    .expect("exact retry");
    let retried =
        ready(provider.rotate(contract, &rotation, retry, &control)).expect("exact rotation retry");
    assert!(retried.authorities().binding() == &successor);
}

#[test]
fn deterministic_provider_rejects_foreign_stale_and_mismatched_lifecycle_inputs() {
    let mut provider = DeterministicLifecycleProviderV1::new();
    let contract = provider.lifecycle_contract();
    let (control, budget) = operation();
    let first = ready(provider.issue(contract, issue_request(0x21, budget), &control))
        .expect("first mailbox");
    let second = ready(provider.issue(contract, issue_request(0x22, budget), &control))
        .expect("second mailbox");
    let (first_binding, _, _, _, first_rotation) = first.into_authorities().into_parts();
    let (_, _, _, _, second_rotation) = second.into_authorities().into_parts();

    let request = RotationRequestV1::new(
        RotationId::from_provider_bytes([0x51; 16]).expect("rotation ID"),
        first_binding,
        RotationModeV1::Compromise,
        NOW + 1_200,
        budget,
    )
    .expect("rotation request");
    let Err(foreign) = ready(provider.rotate(contract, &second_rotation, request, &control)) else {
        panic!("another mailbox rotation right must fail");
    };
    assert_eq!(foreign.code(), TransportFailureCode::InvalidAuthority);

    let wrong_contract = LifecycleProviderContractV1::new(
        TransportProfileId::PrivateInteractiveV1,
        CursorSchemaVersion::new(1).expect("cursor schema"),
        300,
    )
    .expect("mismatched contract");
    let Err(mismatched) =
        ready(provider.issue(wrong_contract, issue_request(0x23, budget), &control))
    else {
        panic!("provider contract substitution must fail");
    };
    assert_eq!(mismatched.code(), TransportFailureCode::PolicyViolation);

    let first_rotation_request = RotationRequestV1::new(
        RotationId::from_provider_bytes([0x52; 16]).expect("rotation ID"),
        first_binding,
        RotationModeV1::Compromise,
        NOW + 1_200,
        budget,
    )
    .expect("first rotation request");
    ready(provider.rotate(contract, &first_rotation, first_rotation_request, &control))
        .expect("first rotation");

    let competing = RotationRequestV1::new(
        RotationId::from_provider_bytes([0x53; 16]).expect("rotation ID"),
        first_binding,
        RotationModeV1::Compromise,
        NOW + 1_300,
        budget,
    )
    .expect("competing rotation request");
    let Err(stale) = ready(provider.rotate(contract, &first_rotation, competing, &control)) else {
        panic!("a competing stale predecessor must fail");
    };
    assert_eq!(stale.code(), TransportFailureCode::AuthorityScopeMismatch);

    let conflicting_retry = RotationRequestV1::new(
        RotationId::from_provider_bytes([0x52; 16]).expect("rotation ID"),
        first_binding,
        RotationModeV1::Compromise,
        NOW + 1_400,
        budget,
    )
    .expect("conflicting retry shape");
    let Err(conflict) =
        ready(provider.rotate(contract, &first_rotation, conflicting_retry, &control))
    else {
        panic!("changed request under one rotation ID must fail");
    };
    assert_eq!(conflict.code(), TransportFailureCode::IdempotencyConflict);

    let expired_request = MailboxIssueRequestV1::new(
        TransportProfileId::FastV1,
        BindingFingerprint::from_bytes([0x24; 32]).expect("binding fingerprint"),
        NOW,
        budget,
    )
    .expect("expired request shape");
    let Err(expired) = ready(provider.issue(contract, expired_request, &control)) else {
        panic!("expired issuance must fail");
    };
    assert_eq!(expired.code(), TransportFailureCode::PolicyViolation);
}
