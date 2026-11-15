// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_futex_runtime::{InterruptError, InterruptWaitOutcome, SerializedFutexTable};
use kernal_scheduler_smp::GlobalThreadId;

// Keep the Pipe wait owner beside the already-independent futex blocking owner. The tiny runtime
// alias lets the child module size its bounded table from the canonical Step-15 thread capacity
// without introducing a second capacity constant or moving Process/FD ownership into this module.
mod runtime {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub const STEP15_RUNTIME_THREADS: usize = super::super::runtime::STEP15_RUNTIME_THREADS;
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    pub const STEP15_RUNTIME_THREADS: usize = super::STEP15_FUTEX_WAITERS;
}
#[cfg(feature = "step29-qemu-proof")]
#[path = "step30_pipe_blocking.rs"]
pub(super) mod pipe_blocking;
#[path = "step30_pipe_wait.rs"]
pub(super) mod pipe_wait;

pub const STEP15_FUTEX_BUCKETS: usize = 16;
pub const STEP15_FUTEX_WAITERS: usize = 16;

static STEP15_FUTEXES: SerializedFutexTable<STEP15_FUTEX_BUCKETS, STEP15_FUTEX_WAITERS> =
    SerializedFutexTable::new();

/// Fatal bridge error while selecting one of the disjoint blocking owners.
///
/// Signal delivery deliberately treats every variant as a privileged invariant. `AmbiguousOwner`
/// means one exact scheduler generation appeared interrupted in both Futex and Pipe state, which is
/// forbidden rather than resolved by arbitrary priority. PipeWait's private error details remain
/// encapsulated by that owner because no caller may branch on them after signal ownership commits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BlockingInterruptError {
    Futex(InterruptError),
    Pipe,
    AmbiguousOwner,
}

/// Post-signal routing decision from the blocking-owner cascade after WaitTable.
///
/// Only `Wake` grants scheduler-wake authority. `Retained` means the signal won while the selected
/// owner was still in its pre-block publication window, `AlreadyInterrupted` preserves the first
/// signal owner's claim, and `NotWaiting` means neither private-futex nor Pipe wait state owns this
/// generation. None of these values decide Linux EINTR/SA_RESTART/fatal policy; that remains the
/// canonical SignalTable/Core owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SignalInterruptRoute {
    NotWaiting,
    Retained,
    AlreadyInterrupted,
    Wake(GlobalThreadId),
}

fn signal_interrupt_route(
    target: GlobalThreadId,
    outcome: InterruptWaitOutcome,
) -> SignalInterruptRoute {
    match outcome {
        InterruptWaitOutcome::NotWaiting => SignalInterruptRoute::NotWaiting,
        InterruptWaitOutcome::Retained => SignalInterruptRoute::Retained,
        InterruptWaitOutcome::AlreadyInterrupted => SignalInterruptRoute::AlreadyInterrupted,
        InterruptWaitOutcome::WakeRequired => SignalInterruptRoute::Wake(target),
    }
}

fn pipe_signal_interrupt_route(
    target: GlobalThreadId,
    outcome: pipe_wait::InterruptOutcome,
) -> SignalInterruptRoute {
    match outcome {
        pipe_wait::InterruptOutcome::NotWaiting => SignalInterruptRoute::NotWaiting,
        pipe_wait::InterruptOutcome::Retained => SignalInterruptRoute::Retained,
        pipe_wait::InterruptOutcome::AlreadyInterrupted => SignalInterruptRoute::AlreadyInterrupted,
        pipe_wait::InterruptOutcome::WakeRequired => SignalInterruptRoute::Wake(target),
    }
}

/// Claims/observes one exact blocking generation after canonical signal policy has already
/// established that this target's next delivery interrupts its syscall.
///
/// WaitTable remains authoritative before this bridge. Inside the bridge, the accepted private futex
/// owner is queried first. Only an exact `NotWaiting` observation falls through to the Pipe read-wait
/// owner. This preserves one blocking owner and one scheduler-wake obligation per generation.
///
/// # Safety
/// The caller must own the signal-send/scheduler quiescence window for the current PE with local IRQ
/// delivery unable to re-enter either serialized owner. `target` must be the exact generation selected
/// by canonical LinuxIdentity/SignalTable policy; scalar PID/TID values are not sufficient authority.
pub(super) unsafe fn interrupt_wait_after_signal(
    target: GlobalThreadId,
) -> Result<SignalInterruptRoute, BlockingInterruptError> {
    // SAFETY: delegated caller contract is exactly SerializedFutexTable::interrupt_wait's additional
    // non-reentrant owner requirement. The table itself revalidates the exact GlobalThreadId encoding.
    let futex =
        unsafe { futexes().interrupt_wait(target) }.map_err(BlockingInterruptError::Futex)?;
    let route = signal_interrupt_route(target, futex);
    if route != SignalInterruptRoute::NotWaiting {
        return Ok(route);
    }

    // SAFETY: the same quiescence window applies to the standalone Pipe waiter serializers. Futex
    // has already proved absence for this exact generation before Pipe may claim interruption authority.
    let pipe = unsafe { pipe_wait::interrupt(target) }.map_err(|_| BlockingInterruptError::Pipe)?;
    let route = pipe_signal_interrupt_route(target, pipe);
    if route != SignalInterruptRoute::NotWaiting {
        return Ok(route);
    }

    // SAFETY: same quiescence window for blocking pipe write waiters.
    let pipe_write =
        unsafe { pipe_wait::interrupt_write(target) }.map_err(|_| BlockingInterruptError::Pipe)?;
    Ok(pipe_signal_interrupt_route(target, pipe_write))
}

/// Observes whether one exact scheduler generation still retains a signal-owned blocking marker.
///
/// Exactly one of the Futex/Pipe owners may retain the marker. A simultaneous marker is corruption
/// evidence and fails closed instead of choosing an arbitrary owner.
///
/// # Safety
/// The caller must prevent same-CPU blocking-owner reentrancy while the serialized tables are
/// observed and must own or be resuming the exact `target` generation.
pub(super) unsafe fn interruption_pending_after_resume(
    target: GlobalThreadId,
) -> Result<bool, BlockingInterruptError> {
    // SAFETY: delegated caller contract matches all serialized owner observation requirements.
    let futex_pending =
        unsafe { futexes().interruption_pending(target) }.map_err(BlockingInterruptError::Futex)?;
    // SAFETY: same exact-generation, non-reentrant owner window.
    let pipe_read_pending = unsafe { pipe_wait::interruption_pending(target) }
        .map_err(|_| BlockingInterruptError::Pipe)?;
    // SAFETY: same exact-generation, non-reentrant owner window.
    let pipe_write_pending = unsafe { pipe_wait::interruption_pending_write(target) }
        .map_err(|_| BlockingInterruptError::Pipe)?;
    let count = usize::from(futex_pending)
        + usize::from(pipe_read_pending)
        + usize::from(pipe_write_pending);
    if count > 1 {
        return Err(BlockingInterruptError::AmbiguousOwner);
    }
    Ok(count == 1)
}

/// Consumes one exact retained blocking interruption after canonical signal policy has committed.
///
/// A false result means neither owner retains the exact marker and must never be converted into
/// fabricated EINTR/restart behavior. If multiple owners claim the generation, fail closed.
///
/// # Safety
/// The caller must prevent same-CPU owner reentrancy and must own the exact `target` generation whose
/// retained signal-interruption marker is being retired.
pub(super) unsafe fn consume_interrupted_after_signal(
    target: GlobalThreadId,
) -> Result<bool, BlockingInterruptError> {
    // First identify the unique owner without consuming any marker.
    // SAFETY: delegated exact-generation/non-reentrant owner contract.
    let futex_pending =
        unsafe { futexes().interruption_pending(target) }.map_err(BlockingInterruptError::Futex)?;
    // SAFETY: same owner window.
    let pipe_read_pending = unsafe { pipe_wait::interruption_pending(target) }
        .map_err(|_| BlockingInterruptError::Pipe)?;
    // SAFETY: same owner window.
    let pipe_write_pending = unsafe { pipe_wait::interruption_pending_write(target) }
        .map_err(|_| BlockingInterruptError::Pipe)?;
    match (futex_pending, pipe_read_pending, pipe_write_pending) {
        (true, false, false) => {
            // SAFETY: the observation above selected the sole retained owner for this exact target.
            unsafe { futexes().consume_interrupted(target) }.map_err(BlockingInterruptError::Futex)
        }
        (false, true, false) => {
            // SAFETY: the observation above selected the sole retained owner for this exact target.
            unsafe { pipe_wait::consume_interrupted(target) }
                .map_err(|_| BlockingInterruptError::Pipe)
        }
        (false, false, true) => {
            // SAFETY: the observation above selected the sole retained owner for this exact target.
            unsafe { pipe_wait::consume_interrupted_write(target) }
                .map_err(|_| BlockingInterruptError::Pipe)
        }
        (false, false, false) => Ok(false),
        _ => Err(BlockingInterruptError::AmbiguousOwner),
    }
}

/// Returns the single process-shared Step-15 futex owner.
///
/// The table is deliberately independent from the mutable Process/VM runtime cell: FUTEX_WAIT may
/// suspend one minimum-runtime invocation while another CPU enters FUTEX_WAKE, and the serialized
/// table already owns the required internal cross-CPU synchronization. Keeping it in a standalone
/// static also means no long-lived raw futex handle can overlap a later `&mut Step15LinuxRuntime`
/// borrow of unrelated Process/VM state.
pub fn futexes() -> &'static SerializedFutexTable<STEP15_FUTEX_BUCKETS, STEP15_FUTEX_WAITERS> {
    &STEP15_FUTEXES
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_percpu::CpuIndex;
    use kernal_scheduler::ThreadId;

    fn thread() -> GlobalThreadId {
        GlobalThreadId::new(
            CpuIndex(2),
            ThreadId {
                slot: 7,
                generation: 9,
            },
        )
    }

    #[test]
    fn futex_owner_is_one_stable_static_instance() {
        assert!(core::ptr::eq(futexes(), futexes()));
        assert_eq!(STEP15_FUTEX_WAITERS, 16);
        assert_eq!(STEP15_FUTEX_BUCKETS, STEP15_FUTEX_WAITERS);
    }

    #[test]
    fn signal_route_grants_scheduler_authority_only_for_wake_required() {
        let target = thread();
        assert_eq!(
            signal_interrupt_route(target, InterruptWaitOutcome::NotWaiting),
            SignalInterruptRoute::NotWaiting
        );
        assert_eq!(
            signal_interrupt_route(target, InterruptWaitOutcome::Retained),
            SignalInterruptRoute::Retained
        );
        assert_eq!(
            signal_interrupt_route(target, InterruptWaitOutcome::AlreadyInterrupted),
            SignalInterruptRoute::AlreadyInterrupted
        );
        assert_eq!(
            signal_interrupt_route(target, InterruptWaitOutcome::WakeRequired),
            SignalInterruptRoute::Wake(target)
        );
    }

    #[test]
    fn pipe_signal_route_matches_futex_race_contract() {
        let target = thread();
        assert_eq!(
            pipe_signal_interrupt_route(target, pipe_wait::InterruptOutcome::NotWaiting),
            SignalInterruptRoute::NotWaiting
        );
        assert_eq!(
            pipe_signal_interrupt_route(target, pipe_wait::InterruptOutcome::Retained),
            SignalInterruptRoute::Retained
        );
        assert_eq!(
            pipe_signal_interrupt_route(target, pipe_wait::InterruptOutcome::AlreadyInterrupted),
            SignalInterruptRoute::AlreadyInterrupted
        );
        assert_eq!(
            pipe_signal_interrupt_route(target, pipe_wait::InterruptOutcome::WakeRequired),
            SignalInterruptRoute::Wake(target)
        );
    }

    #[test]
    fn pipe_write_wait_signal_interruption_and_ambiguity_cleanup() {
        let mut pipes = kernal_linux_pipe::PipeTable::<1, 4>::new();
        let pipe_id = pipes.create().unwrap().reader.pipe();

        let target_pre = GlobalThreadId::new(
            CpuIndex(3),
            ThreadId {
                slot: 11,
                generation: 5,
            },
        );
        let target_sleeping = GlobalThreadId::new(
            CpuIndex(3),
            ThreadId {
                slot: 12,
                generation: 6,
            },
        );
        let target_ambiguous = GlobalThreadId::new(
            CpuIndex(3),
            ThreadId {
                slot: 13,
                generation: 7,
            },
        );

        unsafe {
            pipe_wait::prepare_write(pipe_id, target_pre).unwrap();
            assert_eq!(
                interrupt_wait_after_signal(target_pre),
                Ok(SignalInterruptRoute::Retained)
            );
            assert_eq!(
                pipe_wait::commit_write(target_pre),
                Ok(pipe_wait::WaitCommit::AlreadyWoken)
            );
            assert_eq!(interruption_pending_after_resume(target_pre), Ok(true));
            assert_eq!(consume_interrupted_after_signal(target_pre), Ok(true));
            assert_eq!(interruption_pending_after_resume(target_pre), Ok(false));
            assert_eq!(consume_interrupted_after_signal(target_pre), Ok(false));

            pipe_wait::prepare_write(pipe_id, target_sleeping).unwrap();
            assert_eq!(
                pipe_wait::commit_write(target_sleeping),
                Ok(pipe_wait::WaitCommit::Sleep)
            );
            assert_eq!(
                interrupt_wait_after_signal(target_sleeping),
                Ok(SignalInterruptRoute::Wake(target_sleeping))
            );
            assert_eq!(
                interrupt_wait_after_signal(target_sleeping),
                Ok(SignalInterruptRoute::AlreadyInterrupted)
            );
            assert_eq!(interruption_pending_after_resume(target_sleeping), Ok(true));
            assert_eq!(consume_interrupted_after_signal(target_sleeping), Ok(true));
            assert_eq!(consume_interrupted_after_signal(target_sleeping), Ok(false));

            pipe_wait::prepare(pipe_id, target_ambiguous).unwrap();
            assert_eq!(
                pipe_wait::commit(target_ambiguous),
                Ok(pipe_wait::WaitCommit::Sleep)
            );
            pipe_wait::prepare_write(pipe_id, target_ambiguous).unwrap();
            assert_eq!(
                pipe_wait::commit_write(target_ambiguous),
                Ok(pipe_wait::WaitCommit::Sleep)
            );
            assert_eq!(
                pipe_wait::interrupt(target_ambiguous),
                Ok(pipe_wait::InterruptOutcome::WakeRequired)
            );
            assert_eq!(
                pipe_wait::interrupt_write(target_ambiguous),
                Ok(pipe_wait::InterruptOutcome::WakeRequired)
            );
            assert_eq!(
                interruption_pending_after_resume(target_ambiguous),
                Err(BlockingInterruptError::AmbiguousOwner)
            );
            assert_eq!(
                consume_interrupted_after_signal(target_ambiguous),
                Err(BlockingInterruptError::AmbiguousOwner)
            );
            assert_eq!(pipe_wait::consume_interrupted(target_ambiguous), Ok(true));
            assert_eq!(
                pipe_wait::consume_interrupted_write(target_ambiguous),
                Ok(true)
            );
            assert_eq!(
                interruption_pending_after_resume(target_ambiguous),
                Ok(false)
            );
        }
    }
}
