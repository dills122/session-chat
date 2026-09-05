use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use session_transport::{DispatchControl, OperationBudget};
use transport_conformance::run_connected_delivery_conformance_v1;
use transport_memory::{DeterministicMemoryTransport, MemoryMailboxPolicy};

const NOW: u64 = 1_700_000_000;

struct FixedControl;

impl DispatchControl for FixedControl {
    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        Some(NOW)
    }

    fn is_cancelled(&self) -> bool {
        false
    }
}

fn budget() -> OperationBudget {
    OperationBudget::new(Instant::now() + Duration::from_secs(5), 512 * 1024, 1)
        .expect("valid operation budget")
}

fn ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("memory delivery unexpectedly remained pending"),
    }
}

#[test]
fn memory_adapter_passes_the_shared_connected_delivery_case() {
    let mut transport = DeterministicMemoryTransport::new(
        MemoryMailboxPolicy::new(300, 2, 8, 8).expect("bounded memory policy"),
    )
    .expect("memory transport");
    let (deposit, receive, acknowledgement) = transport
        .create_mailbox(NOW + 300, NOW)
        .expect("create mailbox")
        .into_dispatch_parts();

    ready(run_connected_delivery_conformance_v1(
        &mut transport,
        &deposit,
        &receive,
        &acknowledgement,
        NOW,
        &FixedControl,
        budget,
    ))
    .expect("memory adapter passes shared delivery case");
}
