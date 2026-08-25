use std::{
    future::Future,
    pin::pin,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    task::{Context, Poll, Wake, Waker},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use thiserror::Error;

use crate::DispatchControl;

struct WaitState {
    inner: Mutex<WaitInner>,
    changed: Condvar,
}

struct WaitInner {
    generation: u64,
    cancelled: bool,
}

impl WaitState {
    fn notify(&self) {
        let mut inner = lock(&self.inner);
        inner.generation = inner.generation.wrapping_add(1);
        self.changed.notify_all();
    }
}

impl Wake for WaitState {
    fn wake(self: Arc<Self>) {
        self.notify();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.notify();
    }
}

/// Cross-thread cancellation authority for one local composition control.
#[derive(Clone)]
pub struct CancellationHandle {
    state: Arc<WaitState>,
}

impl CancellationHandle {
    /// Signals cancellation and wakes a blocking supervisor immediately.
    pub fn cancel(&self) {
        let mut inner = lock(&self.state.inner);
        if !inner.cancelled {
            inner.cancelled = true;
            inner.generation = inner.generation.wrapping_add(1);
            self.state.changed.notify_all();
        }
    }
}

/// Standard-library clock/cancellation control for the cross-platform baseline.
pub struct ThreadDispatchControl {
    state: Arc<WaitState>,
}

impl ThreadDispatchControl {
    /// Creates one control plus the only handle needed to cancel it externally.
    #[must_use]
    pub fn new() -> (Self, CancellationHandle) {
        let state = Arc::new(WaitState {
            inner: Mutex::new(WaitInner {
                generation: 0,
                cancelled: false,
            }),
            changed: Condvar::new(),
        });
        (
            Self {
                state: Arc::clone(&state),
            },
            CancellationHandle { state },
        )
    }
}

impl DispatchControl for ThreadDispatchControl {
    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }

    fn wall_now_unix_seconds(&self) -> Option<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs())
    }

    fn is_cancelled(&self) -> bool {
        lock(&self.state.inner).cancelled
    }
}

/// Bounded reasons that a supervised future was dropped before completion.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SupervisionError {
    #[error("supervised future deadline elapsed")]
    DeadlineElapsed,
    #[error("supervised future cancelled")]
    Cancelled,
}

/// Optional blocking standard-library driver for headless and worker-thread use.
///
/// UI runtimes may provide an equivalent non-blocking composition implementation
/// without changing coordinator or adapter contracts. This baseline never busy
/// loops: it waits on the future's waker, external cancellation, or the exact
/// monotonic deadline, then drops unfinished work.
pub struct BlockingFutureSupervisor;

impl BlockingFutureSupervisor {
    pub fn run<F: Future>(
        future: F,
        control: &ThreadDispatchControl,
        deadline: Instant,
    ) -> Result<F::Output, SupervisionError> {
        let mut future = pin!(future);
        let waker = Waker::from(Arc::clone(&control.state));
        let mut context = Context::from_waker(&waker);

        loop {
            let observed_generation = {
                let inner = lock(&control.state.inner);
                if inner.cancelled {
                    return Err(SupervisionError::Cancelled);
                }
                inner.generation
            };
            if Instant::now() >= deadline {
                return Err(SupervisionError::DeadlineElapsed);
            }
            if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
                return Ok(output);
            }

            let mut inner = lock(&control.state.inner);
            if inner.cancelled {
                return Err(SupervisionError::Cancelled);
            }
            if inner.generation != observed_generation {
                continue;
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(SupervisionError::DeadlineElapsed);
            }
            let wait = deadline.saturating_duration_since(now);
            inner = match control.state.changed.wait_timeout(inner, wait) {
                Ok((inner, _)) => inner,
                Err(poisoned) => poisoned.into_inner().0,
            };
            if inner.cancelled {
                return Err(SupervisionError::Cancelled);
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
