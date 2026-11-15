// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_capability::ObjectId;
use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_linux_abi::linux_signed_int;
use kernal_linux_fd::OpenObjectKind;
use kernal_linux_pipe::{End as PipeEnd, Error as PipeError, PIPE_BUF, PipeId, ReadState};
use kernal_scheduler_cpu::Error as SchedulerError;
use kernal_scheduler_smp::GlobalThreadId;

use super::pipe_wait::{self, WaitCommit};

const O_ACCMODE: u64 = 0x3;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_NONBLOCK: u64 = 0x800;
const LARGE_WRITE_PROBE: usize = PIPE_BUF + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PipeWaitKind {
    Read,
    Write,
}

impl PipeWaitKind {
    fn expected_access_mode(self) -> u64 {
        match self {
            Self::Read => O_RDONLY,
            Self::Write => O_WRONLY,
        }
    }

    unsafe fn prepare(self, pipe: PipeId, thread: GlobalThreadId) -> Result<(), pipe_wait::Error> {
        match self {
            Self::Read => unsafe { pipe_wait::prepare(pipe, thread) },
            Self::Write => unsafe { pipe_wait::prepare_write(pipe, thread) },
        }
    }

    unsafe fn commit(self, thread: GlobalThreadId) -> Result<WaitCommit, pipe_wait::Error> {
        match self {
            Self::Read => unsafe { pipe_wait::commit(thread) },
            Self::Write => unsafe { pipe_wait::commit_write(thread) },
        }
    }

    unsafe fn cancel(self, thread: GlobalThreadId) -> Result<bool, pipe_wait::Error> {
        match self {
            Self::Read => unsafe { pipe_wait::cancel(thread) },
            Self::Write => unsafe { pipe_wait::cancel_write(thread) },
        }
    }
}

enum ObserveMode {
    Prepare(GlobalThreadId),
    Revalidate(PipeId),
}

/// Resume-side result for a pipe read that previously proved it had to block.
///
/// `Retry` means normal pipe readiness won and the caller must rerun the canonical FD/pipe read
/// transaction. The other variants mean Core already resolved a signal-owned interruption. In both
/// cases the caller must return from the current syscall dispatcher without fabricating a read result;
/// either the trapped PC was rewound or a handler frame now owns the return path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlockingReadOutcome {
    Retry,
    Restarted,
    SignalFrameCommitted,
}

/// Resume-side result for a blocking pipe write; shares the exact read outcome semantics.
pub(crate) type BlockingWriteOutcome = BlockingReadOutcome;

fn requested_write_len(count: u64) -> Result<usize, ()> {
    let limit = if count <= PIPE_BUF as u64 {
        count
    } else {
        core::cmp::min(count, LARGE_WRITE_PROBE as u64)
    };
    usize::try_from(limit).map_err(|_| ())
}

/// Observes a canonical FD/OFD/Pipe endpoint for blocking readiness, optionally publishing one
/// Prepared waiter during the initial pass or verifying the same PipeId generation on revalidation.
fn observe_pipe_wait(
    kind: PipeWaitKind,
    process: ObjectId,
    raw_fd: u64,
    count: u64,
    mode: ObserveMode,
) -> Result<Option<PipeId>, ()> {
    if count == 0 {
        return Ok(None);
    }
    let fd = linux_signed_int(raw_fd);
    let requested = match kind {
        PipeWaitKind::Read => {
            usize::try_from(core::cmp::min(count, PIPE_BUF as u64)).map_err(|_| ())?
        }
        PipeWaitKind::Write => requested_write_len(count)?,
    };

    super::super::step29_runtime::with_process(process, |runtime| {
        let (fds, pipes) = runtime.fd_pipe_parts();
        if fds.object_kind(fd).map_err(|_| ())? != OpenObjectKind::Pipe {
            return Ok(None);
        }
        let status = fds.status_flags(fd).map_err(|_| ())?;
        if status & O_ACCMODE != kind.expected_access_mode() || status & O_NONBLOCK != 0 {
            return Ok(None);
        }
        let endpoint = fds.pipe_endpoint(fd).map_err(|_| ())?;
        if let ObserveMode::Revalidate(expected_pipe) = mode {
            if endpoint.pipe() != expected_pipe {
                return Ok(None);
            }
        }
        let would_block = match kind {
            PipeWaitKind::Read => match pipes.prepare_read(endpoint, requested) {
                Ok(ReadState::Ready(_) | ReadState::Eof) => false,
                Err(PipeError::WouldBlock) => true,
                Err(_) => return Err(()),
            },
            PipeWaitKind::Write => match pipes.prepare_write(endpoint, requested) {
                Ok(_) | Err(PipeError::BrokenPipe) => false,
                Err(PipeError::WouldBlock) => true,
                Err(_) => return Err(()),
            },
        };
        if !would_block {
            return Ok(None);
        }
        if let ObserveMode::Prepare(current) = mode {
            // SAFETY: the synchronous SVC owns this PE with local IRQ re-entry excluded. The
            // Pipe waiter serializer is independent of the mutable FD/Pipe runtime borrow. Only
            // Prepared state is published here; commit happens after canonical revalidation.
            unsafe { kind.prepare(endpoint.pipe(), current) }.map_err(|_| ())?;
        }
        Ok(Some(endpoint.pipe()))
    })
    .map_err(|_| ())?
}

fn resolve_prepared_without_sleep(
    kind: PipeWaitKind,
    frame: &mut ExceptionFrame,
    current: GlobalThreadId,
) -> Result<BlockingReadOutcome, ()> {
    // A signal may have won while the Prepared waiter was published. Interrupted state is retained
    // and cancellation must not erase it; resolve that owner before allowing ordinary readiness to
    // win. Otherwise exact cancellation contains Prepared/Notified state and the syscall re-observes.
    // SAFETY: this exact generation owns the IRQ-masked SVC and no Runtime/FD/Pipe borrow is live.
    if unsafe { super::interruption_pending_after_resume(current) }.map_err(|_| ())? {
        return resolve_after_resume(frame, current);
    }
    match unsafe { kind.cancel(current) } {
        Ok(true) | Ok(false) => Ok(BlockingReadOutcome::Retry),
        Err(pipe_wait::Error::InvalidWaiterState) => {
            if unsafe { super::interruption_pending_after_resume(current) }.map_err(|_| ())? {
                resolve_after_resume(frame, current)
            } else {
                Err(())
            }
        }
        Err(_) => Err(()),
    }
}

/// Blocks the exact current scheduler generation for one canonical pipe read or write.
///
/// Publication and commit intentionally straddle a second canonical FD/OFD/Pipe observation:
/// `prepare -> drop waiter serializer/runtime borrow -> revalidate -> commit`. This closes both sides
/// of the lost-wake window without moving descriptor or PipeTable authority into Core.
fn block_wait(
    kind: PipeWaitKind,
    process: ObjectId,
    raw_fd: u64,
    count: u64,
    frame: &mut ExceptionFrame,
) -> Result<BlockingReadOutcome, ()> {
    let current_cpu = super::super::super::current_cpu_index();
    let scheduler = super::super::super::CPU_SCHEDULERS
        .get(current_cpu)
        .ok_or(())?;
    // SAFETY: lower-EL synchronous SVC owns the IRQ-masked scheduler window for this PE.
    let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
    if usize::from(current.cpu.0) != current_cpu {
        return Err(());
    }

    super::super::drain_step30_pending_exits_before_wait(current_cpu)?;

    let Some(pipe) =
        observe_pipe_wait(kind, process, raw_fd, count, ObserveMode::Prepare(current))?
    else {
        return Ok(BlockingReadOutcome::Retry);
    };

    if observe_pipe_wait(kind, process, raw_fd, count, ObserveMode::Revalidate(pipe))?.is_none() {
        return resolve_prepared_without_sleep(kind, frame, current);
    }

    // No Runtime/FD/Pipe borrow survives this commit. A readiness/signal race between revalidation
    // and commit is retained by the waiter owner and returned as AlreadyWoken instead of sleeping.
    // SAFETY: exact current generation owns the local IRQ-masked scheduler window.
    match unsafe { kind.commit(current) }.map_err(|_| ())? {
        WaitCommit::AlreadyWoken => {
            if unsafe { super::interruption_pending_after_resume(current) }.map_err(|_| ())? {
                return resolve_after_resume(frame, current);
            }
            return Ok(BlockingReadOutcome::Retry);
        }
        WaitCommit::Sleep => {}
    }

    // All canonical Runtime/FD/Pipe borrows ended above. Only exact scheduler identity plus the live
    // exception frame owned by this suspended SVC remains across the context switch.
    // SAFETY: waiter commit and local owner quiescence are retained continuously into the block.
    let switched = unsafe {
        scheduler.bootstrap_block_current_and_switch_with_destination_address_space(
            current,
            super::super::activate_step30_scheduler_destination,
        )
    };

    match switched {
        Ok(resumed) if resumed == current => {
            let generation = kernal_process_aarch64::current_user_switch_generation()
                .and_then(core::num::NonZeroU64::new)
                .ok_or(())?;
            // SAFETY: `resumed == current` proves the same exact scheduler generation is current
            // again, and this synchronous SVC still owns the retained exception frame exclusively.
            unsafe { frame.rebind_entry_switch_generation(generation) };
            super::super::drain_step30_pending_exits_before_wait(current_cpu)?;
            resolve_after_resume(frame, current)
        }
        Ok(_) => Err(()),
        Err(SchedulerError::NoRunnableThread) => {
            super::super::drain_step30_pending_exits_before_wait(current_cpu)?;
            // A signal owner may have claimed the committed waiter during the failed block attempt.
            // SAFETY: current remains the exact running generation on this documented pre-switch path.
            if unsafe { super::interruption_pending_after_resume(current) }.map_err(|_| ())? {
                return resolve_after_resume(frame, current);
            }
            // A normal readiness publication may instead have consumed the waiter before the
            // scheduler reported no peer. False therefore means retry, not corruption.
            // SAFETY: exact current generation still owns this failed block path.
            match unsafe { kind.cancel(current) }.map_err(|_| ())? {
                false => Ok(BlockingReadOutcome::Retry),
                true => Err(()),
            }
        }
        Err(_) => {
            // Containment only. If signal ownership already linearized, cancellation correctly fails
            // and the original privileged scheduler error still propagates fail-closed.
            // SAFETY: the resumed/current owner window still excludes local re-entry.
            let _ = unsafe { kind.cancel(current) };
            Err(())
        }
    }
}

/// Blocks the exact current scheduler generation for one canonical pipe read.
pub(crate) fn block_read(
    process: ObjectId,
    raw_fd: u64,
    count: u64,
    frame: &mut ExceptionFrame,
) -> Result<BlockingReadOutcome, ()> {
    block_wait(PipeWaitKind::Read, process, raw_fd, count, frame)
}

/// Blocks the exact current scheduler generation for one canonical pipe write.
pub(crate) fn block_write(
    process: ObjectId,
    raw_fd: u64,
    count: u64,
    frame: &mut ExceptionFrame,
) -> Result<BlockingWriteOutcome, ()> {
    block_wait(PipeWaitKind::Write, process, raw_fd, count, frame)
}

fn resolve_after_resume(
    frame: &mut ExceptionFrame,
    current: GlobalThreadId,
) -> Result<BlockingReadOutcome, ()> {
    // SAFETY: the exact generation is current again in the same IRQ-masked SVC owner window.
    if !unsafe { super::interruption_pending_after_resume(current) }.map_err(|_| ())? {
        return Ok(BlockingReadOutcome::Retry);
    }

    // The pipe path never staged provisional x0 success, so x0..x5 still contain the original syscall
    // arguments. Reuse the already-audited interrupted-wait signal transaction directly: it either
    // rewinds the trapped SVC or installs one handler frame containing EINTR/SA_RESTART state.
    match super::super::signal_delivery::deliver_interrupted_futex(frame, current)? {
        super::super::signal_delivery::InterruptedFutexDelivery::Restarted => {
            Ok(BlockingReadOutcome::Restarted)
        }
        super::super::signal_delivery::InterruptedFutexDelivery::SignalFrameCommitted => {
            Ok(BlockingReadOutcome::SignalFrameCommitted)
        }
    }
}

fn wake_exact(target: GlobalThreadId) -> Result<(), ()> {
    let target_index = usize::from(target.cpu.0);
    let target_scheduler = super::super::super::CPU_SCHEDULERS
        .get(target_index)
        .ok_or(())?;
    let current_cpu = super::super::super::current_cpu_index();
    if target_index == current_cpu {
        // SAFETY: exact target came from the generation-safe Pipe waiter owner while this PE retains
        // the scheduler quiescence window. This only transitions the matching blocked generation.
        unsafe { target_scheduler.bootstrap_wake_local_exact(target) }.map_err(|_| ())
    } else {
        super::super::remote_wake_with_reschedule(target_scheduler, target).map_err(|_| ())
    }
}

fn wake_targets<const N: usize>(targets: [Option<GlobalThreadId>; N]) -> Result<(), ()> {
    for target in targets.into_iter().flatten() {
        wake_exact(target)?;
    }
    Ok(())
}

/// Publishes one normal pipe-read readiness transition after bytes have committed and after the
/// caller has released every Runtime/FD/Pipe borrow.
pub(crate) fn notify_after_write(pipe: PipeId) -> Result<(), ()> {
    // SAFETY: caller is the synchronous post-commit owner with local IRQ re-entry excluded and no
    // canonical Runtime/FD/Pipe borrow live.
    let (_report, target) = unsafe { pipe_wait::notify_one(pipe) }.map_err(|_| ())?;
    if let Some(target) = target {
        wake_exact(target)?;
    }
    Ok(())
}

/// Publishes EOF readiness after the final writer endpoint lease is released. Every matching reader
/// is notified because no future writer can make progress for this Pipe generation.
pub(crate) fn notify_after_writer_close(pipe: PipeId) -> Result<(), ()> {
    // SAFETY: caller has completed the canonical FD/OFD release and PipeTable close transaction and
    // dropped those borrows before entering this wake phase.
    let (targets, _report) = unsafe { pipe_wait::notify_all(pipe) }.map_err(|_| ())?;
    wake_targets(targets)
}

/// Publishes pipe-write readiness after buffered bytes are consumed and all Runtime/FD/Pipe borrows
/// are released. Wakes all write waiters on this pipe generation so differing atomic write sizes
/// cannot starve one another.
pub(crate) fn notify_after_read(pipe: PipeId) -> Result<(), ()> {
    // SAFETY: caller is the synchronous post-commit owner with local IRQ re-entry excluded and no
    // canonical Runtime/FD/Pipe borrow live.
    let (targets, _report) = unsafe { pipe_wait::notify_all_write(pipe) }.map_err(|_| ())?;
    wake_targets(targets)
}

/// Publishes broken-pipe readiness after a reader endpoint lease is released.
pub(crate) fn notify_after_reader_close(pipe: PipeId) -> Result<(), ()> {
    notify_after_read(pipe)
}

/// Dispatches endpoint-close readiness notifications for either pipe end after borrows drop.
pub(crate) fn notify_after_endpoint_close(pipe: PipeId, end: PipeEnd) -> Result<(), ()> {
    match end {
        PipeEnd::Read => notify_after_reader_close(pipe),
        PipeEnd::Write => notify_after_writer_close(pipe),
    }
}
