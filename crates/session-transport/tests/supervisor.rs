use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    thread,
    time::{Duration, Instant},
};

use session_transport::{
    BlockingFutureSupervisor, DispatchControl, SupervisionError, ThreadDispatchControl,
};

struct DelayedWake {
    ready: Arc<AtomicBool>,
    armed: bool,
}

impl Future for DelayedWake {
    type Output = u8;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.ready.load(Ordering::Acquire) {
            return Poll::Ready(7);
        }
        if !self.armed {
            self.armed = true;
            let ready = Arc::clone(&self.ready);
            let waker = context.waker().clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(10));
                ready.store(true, Ordering::Release);
                waker.wake();
            });
        }
        Poll::Pending
    }
}

struct NeverReady {
    dropped: Arc<AtomicBool>,
}

impl Future for NeverReady {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for NeverReady {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

#[test]
fn delayed_wake_completes_before_the_deadline() {
    let (control, _cancellation) = ThreadDispatchControl::new();
    let future = DelayedWake {
        ready: Arc::new(AtomicBool::new(false)),
        armed: false,
    };
    assert_eq!(
        BlockingFutureSupervisor::run(future, &control, Instant::now() + Duration::from_secs(1),),
        Ok(7)
    );
}

#[test]
fn deadline_drops_pending_work() {
    let (control, _cancellation) = ThreadDispatchControl::new();
    let dropped = Arc::new(AtomicBool::new(false));
    assert_eq!(
        BlockingFutureSupervisor::run(
            NeverReady {
                dropped: Arc::clone(&dropped),
            },
            &control,
            Instant::now() + Duration::from_millis(20),
        ),
        Err(SupervisionError::DeadlineElapsed)
    );
    assert!(dropped.load(Ordering::Acquire));
}

#[test]
fn external_cancellation_wakes_and_drops_pending_work() {
    let (control, cancellation) = ThreadDispatchControl::new();
    let dropped = Arc::new(AtomicBool::new(false));
    let canceller = thread::spawn(move || {
        thread::sleep(Duration::from_millis(10));
        cancellation.cancel();
    });
    assert_eq!(
        BlockingFutureSupervisor::run(
            NeverReady {
                dropped: Arc::clone(&dropped),
            },
            &control,
            Instant::now() + Duration::from_secs(1),
        ),
        Err(SupervisionError::Cancelled)
    );
    canceller.join().expect("cancellation thread");
    assert!(control.is_cancelled());
    assert!(dropped.load(Ordering::Acquire));
}
