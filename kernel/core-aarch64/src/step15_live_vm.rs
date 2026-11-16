// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::{kmap, memory, runtime};
use kernal_linux_abi::MinimumRuntimeCall;
use kernal_linux_vm::Error as VmError;
use kernal_memory::PhysFrame;
use kernal_object::ObjectTable;
use kernal_page_table_aarch64::Backend;
use kernal_process::Process;
use kernal_process_aarch64::{BoundProcessAddressSpace, Error as ProcessAddressSpaceError};
use kernal_protected_boot_aarch64::RuntimeTablePool;
use kernal_scheduler_smp::GlobalThreadId;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_exceptions_aarch64::ExceptionFrame;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_linux_abi::Errno;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_linux_clone::ProcessClonePlan;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_scheduler_cpu::CpuSchedulerCell;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_user_entry_aarch64::El0ReturnState;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn current_scheduler_thread() -> Result<GlobalThreadId, ()> {
    let current_cpu = super::super::current_cpu_index();
    let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
    // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
    let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
    if usize::from(current.cpu.0) != current_cpu {
        return Err(());
    }
    Ok(current)
}

#[allow(clippy::type_complexity)]
unsafe fn with_current_vm_tx<T>(
    operation: impl FnOnce(
        &mut kernal_linux_vm::LinuxVmRuntime<
            { runtime::STEP15_RUNTIME_VM_BREAKS },
            { runtime::STEP15_RUNTIME_VM_TX_PAGES },
        >,
        &Process<{ runtime::STEP15_RUNTIME_CAPS }>,
        &ObjectTable<{ runtime::STEP15_RUNTIME_OBJECTS }>,
        &mut BoundProcessAddressSpace<{ runtime::STEP15_RUNTIME_VMAS }>,
        &mut RuntimeTablePool,
        &kernal_memory::ReservationSet<{ memory::STEP15_RESERVED_RANGES }>,
        &mut kernal_frame_allocator::ExtentAllocator<{ memory::STEP15_FRAME_EXTENTS }>,
        &mut kernal_kmap_aarch64::KmapController,
    ) -> T,
) -> Result<T, ()> {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    let current = current_scheduler_thread()?;

    // SAFETY: caller upholds the synchronous lower-EL trap owner window with quiesced IRQs.
    let memory_result = unsafe {
        RuntimeTablePool::with_live(|page_tables| {
            memory::with_live_frame_pool(|frame_pool| {
                runtime::with_linux_runtime(|linux| {
                    // SAFETY: outer live-table borrow is the canonical hierarchy-mutation owner.
                    kmap::with_kmap(|zeroer| {
                        let (frames, reserved) = frame_pool.split();
                        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
                        let Ok((vm, process, objects, space)) =
                            linux.vm_parts_for_scheduler_thread(current)
                        else {
                            return Err(());
                        };
                        #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
                        let (vm, process, objects, space) = linux.minimum_vm_parts();
                        Ok(operation(
                            vm,
                            process,
                            objects,
                            space,
                            page_tables,
                            reserved,
                            frames,
                            zeroer,
                        ))
                    })
                })
            })
        })
    }
    .map_err(|_| ())?;

    let runtime_result = memory_result.map_err(|_| ())?;
    let kmap_result = runtime_result.map_err(|_| ())?;
    kmap_result.map_err(|_| ())?
}

/// Executes one non-blocking live Step-15 VM transaction through the exact persistent owners.
///
/// The return shape deliberately preserves the architecture-neutral Linux VM error so the trap
/// boundary can return ordinary Linux errno while keeping ownership/backend invariant failures
/// fail-closed. Errors from any owner cell are collapsed to `()` because those are kernel invariant
/// failures rather than Linux-visible request errors.
pub(super) fn handle(call: MinimumRuntimeCall) -> Result<Result<u64, VmError>, ()> {
    // SAFETY: lower-EL synchronous trap owns CPU0 with exception delivery quiesced and no switch.
    let vm_result = unsafe {
        with_current_vm_tx(
            |vm, process, objects, space, page_tables, reserved, frames, zeroer| {
                // SAFETY: nested owner scopes provide exact Process/CSpace, address space, tables,
                // reservation set, frame allocator and persistent KMap zeroer.
                kernal_linux_vm_aarch64::handle_current(
                    vm,
                    process,
                    objects,
                    space,
                    page_tables,
                    reserved,
                    frames,
                    zeroer,
                    call,
                )
            },
        )
    }?;
    Ok(vm_result)
}

/// Executes one Step-31 dynamic linker `mmap(2)` transaction (`MAP_PRIVATE`, `MAP_FIXED`,
/// `MAP_DENYWRITE`, `PROT_NONE`, `PROT_EXEC`, and file-backed segment population) through the
/// exact persistent owners.
#[allow(clippy::too_many_arguments)]
pub(super) fn handle_step31_dynamic_mmap(
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    fd: u64,
    offset: u64,
    backing: kernal_linux_vm::MmapFileBacking<'_>,
) -> Result<Result<u64, VmError>, ()> {
    // SAFETY: same synchronous lower-EL trap owner window as `handle`.
    let vm_result = unsafe {
        with_current_vm_tx(
            |_vm, process, objects, space, page_tables, reserved, frames, zeroer| {
                // SAFETY: exact Process/CSpace, bound address space, live table cursor,
                // reservation set, frame allocator and persistent KMap zeroer are held.
                kernal_linux_vm_aarch64::handle_step31_dynamic_mmap::<
                    { runtime::STEP31_DYNAMIC_MMAP_TX_PAGES },
                    _,
                    _,
                    _,
                    _,
                    _,
                    _,
                    _,
                >(
                    process,
                    objects,
                    space,
                    page_tables,
                    reserved,
                    frames,
                    zeroer,
                    address,
                    length,
                    protection,
                    flags,
                    fd,
                    offset,
                    backing,
                )
            },
        )
    }?;
    Ok(vm_result)
}

/// Executes one Step-31 `mprotect(2)` transaction (`PROT_NONE`, `PROT_READ`, `PROT_READ |
/// PROT_WRITE`, `PROT_READ | PROT_EXEC`, `PROT_EXEC`) for the active process while rejecting W+X.
pub(super) fn handle_step31_mprotect(
    address: u64,
    length: u64,
    protection: u64,
) -> Result<Result<(), VmError>, ()> {
    // SAFETY: same synchronous lower-EL trap owner window as `handle`.
    let vm_result = unsafe {
        with_current_vm_tx(
            |_vm, process, objects, space, page_tables, reserved, frames, zeroer| {
                // SAFETY: exact Process/CSpace, bound address space, live table cursor,
                // reservation set, frame allocator and persistent KMap zeroer are held.
                kernal_linux_vm_aarch64::handle_step31_mprotect::<
                    { runtime::STEP31_DYNAMIC_MMAP_TX_PAGES },
                    _,
                    _,
                    _,
                    _,
                    _,
                    _,
                    _,
                >(
                    process,
                    objects,
                    space,
                    page_tables,
                    reserved,
                    frames,
                    zeroer,
                    address,
                    length,
                    protection,
                )
            },
        )
    }?;
    Ok(vm_result)
}

/// Runs the canonical private-fork transaction for one legacy AArch64 `clone(SIGCHLD, 0, 0, 0, 0)`.
///
/// This is orchestration only. Process/AddressSpace snapshot ownership remains in `step30_fork`,
/// physical/page-table mutation remains in the existing live owner cells, scheduler publication stays
/// in `CpuSchedulerCell`, and Linux identity/wait/signal ownership stays in `Step15LinuxRuntime`.
/// KMap is held only for the synchronous anonymous snapshot and is released before scheduler staging.
///
/// The returned receipt is the sole authority for the parent-visible child PID. A caller must not
/// write parent x0 before this function returns `Ok`.
///
/// # Safety
/// Caller must be the current scheduler owner with IRQs masked, irq_depth/preempt_count zero and the
/// exact lower-EL `frame` belonging to `current`. No context switch, nested runtime borrow or competing
/// page-table/KMap operation may occur until this synchronous transaction returns.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) unsafe fn fork_process<const THREADS: usize, const WAKES: usize>(
    frame: &ExceptionFrame,
    current: GlobalThreadId,
    plan: ProcessClonePlan,
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    priority: u8,
) -> Result<super::step30_fork::PublishedForkLeaderReceipt, ()> {
    // SAFETY: delegated caller contract matches `fork_process_inner`.
    unsafe { fork_process_inner(frame, current, plan, scheduler, priority, None, None, None) }
}

/// Variant of [`fork_process`] that applies optional `CLONE_CHILD_SETTID` / `CLONE_CHILD_CLEARTID`
/// metadata and optional explicit child user stack (`posix_spawn`) for unmodified dynamic Debian
/// userspace.
///
/// # Safety
/// Identical to [`fork_process`].
#[cfg(all(
    target_arch = "aarch64",
    target_os = "none",
    feature = "step31-debian-qemu"
))]
pub(super) unsafe fn fork_process_with_tid_options<const THREADS: usize, const WAKES: usize>(
    frame: &ExceptionFrame,
    current: GlobalThreadId,
    plan: ProcessClonePlan,
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    priority: u8,
    child_tid_set: Option<u64>,
    child_tid_clear: Option<u64>,
    child_stack_override: Option<u64>,
) -> Result<super::step30_fork::PublishedForkLeaderReceipt, ()> {
    // SAFETY: delegated caller contract matches `fork_process_inner`.
    unsafe {
        fork_process_inner(
            frame,
            current,
            plan,
            scheduler,
            priority,
            child_tid_set,
            child_tid_clear,
            child_stack_override,
        )
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe fn fork_process_inner<const THREADS: usize, const WAKES: usize>(
    frame: &ExceptionFrame,
    current: GlobalThreadId,
    plan: ProcessClonePlan,
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    priority: u8,
    child_tid_set: Option<u64>,
    child_tid_clear: Option<u64>,
    child_stack_override: Option<u64>,
) -> Result<super::step30_fork::PublishedForkLeaderReceipt, ()> {
    let target_sp = child_stack_override.unwrap_or(frame.sp_el0);
    let parent_return =
        El0ReturnState::new(frame.elr_el1, frame.spsr_el1, target_sp).map_err(|_| ())?;
    let parent_registers = frame.x;
    // SAFETY: delegated caller contract proves this is the exact current EL0 scheduler generation.
    let parent_tls = unsafe { kernal_context_aarch64::read_el0_thread_pointer() };

    // SAFETY: the delegated function contract supplies the same non-switching owner window required
    // by all four nested persistent owner cells.
    let table_result = unsafe {
        RuntimeTablePool::with_live(|page_tables| {
            memory::with_live_frame_pool(|frame_pool| {
                runtime::with_linux_runtime(|linux| -> Result<_, ()> {
                    // KMap is needed only while copying the parent's anonymous snapshot. Its borrow
                    // ends before scheduler staging so the later transaction does not retain TTBR1
                    // temporary-alias authority across scheduler mutation.
                    let staged_snapshot = unsafe {
                        kmap::with_kmap(|zeroer| {
                            // SAFETY: exact parent frame, runtime, page-table, frame and KMap owners
                            // are all held for this never-published staging operation.
                            unsafe {
                                super::step30_fork::stage_unpublished_fork_transaction_with_child_tid(
                                    linux,
                                    current,
                                    plan,
                                    &parent_registers,
                                    parent_return,
                                    parent_tls,
                                    page_tables,
                                    frame_pool,
                                    zeroer,
                                    child_tid_set,
                                )
                            }
                        })
                    };
                    let staged_snapshot = match staged_snapshot {
                        Ok(Ok(receipt)) => receipt,
                        Ok(Err(error)) => {
                            #[cfg(feature = "step31-debian-qemu")]
                            if let Some(serial) = super::step15_svc_serial() {
                                serial.write_str("KERNAL/D13: fork stage_unpublished failed: ");
                                match &error {
                                    super::step30_fork::Error::UnsupportedBacking => {
                                        serial.write_str("UnsupportedBacking")
                                    }
                                    super::step30_fork::Error::ChildNotEmpty => {
                                        serial.write_str("ChildNotEmpty")
                                    }
                                    super::step30_fork::Error::AddressSpace => {
                                        serial.write_str("AddressSpace")
                                    }
                                    super::step30_fork::Error::Frame(_) => {
                                        serial.write_str("Frame")
                                    }
                                    super::step30_fork::Error::InvalidAllocatedFrame => {
                                        serial.write_str("InvalidAllocatedFrame")
                                    }
                                    super::step30_fork::Error::Invariant => {
                                        serial.write_str("Invariant")
                                    }
                                    super::step30_fork::Error::UnsupportedProcessClonePlan => {
                                        serial.write_str("UnsupportedProcessClonePlan")
                                    }
                                    super::step30_fork::Error::RollbackFailed => {
                                        serial.write_str("RollbackFailed")
                                    }
                                    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
                                    super::step30_fork::Error::ChildTidFault => {
                                        serial.write_str("ChildTidFault")
                                    }
                                    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
                                    super::step30_fork::Error::Kmap(_) => {
                                        serial.write_str("Kmap")
                                    }
                                    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
                                    super::step30_fork::Error::Runtime(r) => {
                                        serial.write_str("Runtime(");
                                        match r {
                                            super::runtime::Error::Process(_) => {
                                                serial.write_str("Process")
                                            }
                                            super::runtime::Error::AddressSpace(_) => {
                                                serial.write_str("AddressSpace")
                                            }
                                            super::runtime::Error::Credentials(_) => {
                                                serial.write_str("Credentials")
                                            }
                                            super::runtime::Error::Signal(_) => {
                                                serial.write_str("Signal")
                                            }
                                            super::runtime::Error::Wait(_) => {
                                                serial.write_str("Wait")
                                            }
                                            super::runtime::Error::Exit(_) => {
                                                serial.write_str("Exit")
                                            }
                                            super::runtime::Error::AlreadyInitialized => {
                                                serial.write_str("AlreadyInitialized")
                                            }
                                            super::runtime::Error::Unavailable => {
                                                serial.write_str("Unavailable")
                                            }
                                            super::runtime::Error::Busy => serial.write_str("Busy"),
                                            super::runtime::Error::Poisoned => {
                                                serial.write_str("Poisoned")
                                            }
                                            super::runtime::Error::InvalidState => {
                                                serial.write_str("InvalidState")
                                            }
                                            super::runtime::Error::ProcessSlotsFull => {
                                                serial.write_str("ProcessSlotsFull")
                                            }
                                        }
                                        serial.write_str(")");
                                    }
                                    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
                                    super::step30_fork::Error::ReturnState(_) => {
                                        serial.write_str("ReturnState")
                                    }
                                    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
                                    super::step30_fork::Error::Stack(_) => {
                                        serial.write_str("Stack")
                                    }
                                    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
                                    super::step30_fork::Error::Scheduler(_) => {
                                        serial.write_str("Scheduler")
                                    }
                                    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
                                    super::step30_fork::Error::Lifecycle(_) => {
                                        serial.write_str("Lifecycle")
                                    }
                                    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
                                    super::step30_fork::Error::Identity(_) => {
                                        serial.write_str("Identity")
                                    }
                                    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
                                    super::step30_fork::Error::Process(_) => {
                                        serial.write_str("Process")
                                    }
                                    #[cfg(test)]
                                    super::step30_fork::Error::InjectedCopyFailure => {
                                        serial.write_str("InjectedCopyFailure")
                                    }
                                }
                                serial.write_str("\n");
                            }
                            let _ = error;
                            return Err(());
                        }
                        Err(_) => {
                            #[cfg(feature = "step31-debian-qemu")]
                            if let Some(serial) = super::step15_svc_serial() {
                                serial.write_str("KERNAL/D13: fork kmap borrow failed\n");
                            }
                            return Err(());
                        }
                    };

                    // SAFETY: caller still owns the scheduler/quiescent window and the exact receipt
                    // has not escaped or been published.
                    let staged_scheduler = match unsafe {
                        super::step30_fork::stage_fork_scheduler_generation_with_clear_child_tid(
                            scheduler,
                            staged_snapshot,
                            priority,
                            child_tid_clear,
                        )
                    } {
                        Ok(receipt) => receipt,
                        Err(error) => {
                            if let Some((_scheduler_error, receipt)) = error.into_recoverable() {
                                // SAFETY: the scheduler contract proved no generation was published;
                                // rollback consumes the exact still-reversible snapshot receipt.
                                unsafe {
                                    super::step30_fork::rollback_unpublished_fork_transaction(
                                        linux,
                                        current,
                                        receipt,
                                        page_tables,
                                        frame_pool,
                                    )
                                }
                                .map_err(|_| ())?;
                            }
                            return Err(());
                        }
                    };

                    // SAFETY: the exact scheduler generation remains Blocked+Staged and owner-held.
                    let staged_leader = match unsafe {
                        super::step30_fork::stage_fork_leader_authority(
                            scheduler,
                            linux,
                            staged_scheduler,
                        )
                    } {
                        Ok(receipt) => receipt,
                        Err(_) => return Err(()),
                    };

                    // SAFETY: final publication consumes the exact leader receipt and performs no
                    // fallible userspace access. Any recoverable error proves Blocked+Staged state.
                    match unsafe {
                        super::step30_fork::publish_staged_fork_leader(
                            scheduler,
                            linux,
                            staged_leader,
                        )
                    } {
                        Ok(published) => Ok(published),
                        Err(error) => {
                            if let Some((_publish_error, receipt)) = error.into_recoverable() {
                                // SAFETY: recoverable publish failure restored the complete staged
                                // leader receipt; owner/page-table/frame state remains unchanged.
                                unsafe {
                                    super::step30_fork::rollback_staged_fork_leader_authority(
                                        scheduler,
                                        linux,
                                        current,
                                        receipt,
                                        page_tables,
                                        frame_pool,
                                    )
                                }
                                .map_err(|_| ())?;
                            }
                            Err(())
                        }
                    }
                })
            })
        })
    }
    .map_err(|_| ())?;

    let frame_result = table_result.map_err(|_| ())?;
    let runtime_result = frame_result.map_err(|_| ())?;
    runtime_result
}

/// Proves the bounded Step-30 exec precondition that the exact current Process has one and only one
/// bound scheduler generation, and that generation is `current`.
///
/// This is observation only. The canonical LinuxIdentity table remains the sole Process -> scheduler
/// binding owner; no scheduler scan, raw TID lookup or Core sidecar is introduced. A second bound
/// generation returns `Ok(false)` so the caller can leave exec unsupported/fail-closed before any
/// replacement-image commit.
#[allow(dead_code)]
pub(super) fn exact_current_is_only_bound_process_thread(
    current: GlobalThreadId,
) -> Result<bool, ()> {
    runtime::with_linux_runtime(|state| {
        state.with_current_process_identity(
            current,
            |process, identities| -> Result<bool, kernal_linux_identity::Error> {
                let Some(first) = identities.bound_scheduler_thread_at(process, 0)? else {
                    return Ok(false);
                };
                if first != current {
                    return Ok(false);
                }
                Ok(identities.bound_scheduler_thread_at(process, 1)?.is_none())
            },
        )
    })
    .map_err(|_| ())?
    .map_err(|_| ())?
    .map_err(|_| ())
}

/// Fixed bounded loader ceilings for Step-30 exec image staging.
///
/// Bounded Step-30 live-exec frame capacity (16 MiB) and ELF segment table size.
/// Heap-backed `LiveExecFrameBatch` keeps kernel stack usage constant while accommodating large
/// Debian binaries such as `dpkg`. ELF segment and Linux-stack validity still come exclusively
/// from the canonical loader/parser owners.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const STEP30_EXEC_FRAME_CAPACITY: usize = 4096;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const STEP30_EXEC_SEGMENTS: usize = 16;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ExecStageError {
    Linux(Errno),
    Invariant,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn map_exec_preflight_error(error: super::loader_frames::Error) -> ExecStageError {
    use super::loader_frames::Error as LoaderFrameError;
    use kernal_frame_allocator::Error as FrameError;
    use kernal_user_elf_aarch64::Error as MappingError;
    use kernal_user_elf_runtime_aarch64::Error as RuntimeError;

    match error {
        LoaderFrameError::Loader(
            RuntimeError::Elf(_)
            | RuntimeError::UserPolicy(_)
            | RuntimeError::LinuxStack(_)
            | RuntimeError::InterpreterRequired,
        )
        | LoaderFrameError::Mapping(MappingError::PageCountOverflow)
        | LoaderFrameError::InitialBreak => ExecStageError::Linux(Errno::ENOEXEC),
        LoaderFrameError::FrameCapacity { .. }
        | LoaderFrameError::FrameRollbackFailed
        | LoaderFrameError::InvalidAllocatedFrame
        | LoaderFrameError::LoaderFramesQuarantined(_) => ExecStageError::Invariant,
        LoaderFrameError::Frame(frame_error) => match frame_error {
            FrameError::InvalidRange
            | FrameError::Overflow
            | FrameError::Capacity
            | FrameError::NoMemory
            | FrameError::DoubleFreeOrOverlap
            | FrameError::ReservedRange
            | FrameError::InvalidAlignment
            | FrameError::InvalidBootMap => ExecStageError::Invariant,
        },
        LoaderFrameError::Mapping(mapping_error) => match mapping_error {
            MappingError::PageCountOverflow => ExecStageError::Linux(Errno::ENOEXEC),
            MappingError::AddressOverflow
            | MappingError::FrameCountMismatch { .. }
            | MappingError::DuplicateFrame
            | MappingError::ReservedFrame
            | MappingError::UserPolicy(_)
            | MappingError::Vm(_)
            | MappingError::AddressSpace(_)
            | MappingError::RollbackFailed => ExecStageError::Invariant,
        },
        LoaderFrameError::Loader(runtime_error) => match runtime_error {
            RuntimeError::Elf(_)
            | RuntimeError::UserPolicy(_)
            | RuntimeError::LinuxStack(_)
            | RuntimeError::InterpreterRequired => ExecStageError::Linux(Errno::ENOEXEC),
            RuntimeError::Initialization(_)
            | RuntimeError::LinuxStackInvariant
            | RuntimeError::Mapping(_)
            | RuntimeError::FrameCountMismatch { .. }
            | RuntimeError::DuplicateFrame
            | RuntimeError::ReservedFrame
            | RuntimeError::AddressOverflow
            | RuntimeError::Vm
            | RuntimeError::AddressSpace
            | RuntimeError::Usercopy
            | RuntimeError::CacheMaintenance
            | RuntimeError::StagingRollbackFailed => ExecStageError::Invariant,
        },
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn map_exec_recovered_load_error(error: super::loader_frames::Error) -> ExecStageError {
    use super::loader_frames::Error as LoaderFrameError;
    use kernal_frame_allocator::Error as FrameError;
    use kernal_user_elf_aarch64::Error as MappingError;
    use kernal_user_elf_runtime_aarch64::Error as RuntimeError;

    match error {
        LoaderFrameError::FrameCapacity { .. } => ExecStageError::Linux(Errno::ENOMEM),
        LoaderFrameError::Frame(frame_error) => match frame_error {
            FrameError::NoMemory => ExecStageError::Linux(Errno::ENOMEM),
            FrameError::InvalidRange
            | FrameError::Overflow
            | FrameError::Capacity
            | FrameError::DoubleFreeOrOverlap
            | FrameError::ReservedRange
            | FrameError::InvalidAlignment
            | FrameError::InvalidBootMap => ExecStageError::Invariant,
        },
        LoaderFrameError::FrameRollbackFailed | LoaderFrameError::InvalidAllocatedFrame => {
            ExecStageError::Invariant
        }
        LoaderFrameError::Mapping(mapping_error) => match mapping_error {
            MappingError::PageCountOverflow
            | MappingError::AddressOverflow
            | MappingError::FrameCountMismatch { .. }
            | MappingError::DuplicateFrame
            | MappingError::ReservedFrame
            | MappingError::UserPolicy(_)
            | MappingError::Vm(_)
            | MappingError::AddressSpace(_)
            | MappingError::RollbackFailed => ExecStageError::Invariant,
        },
        LoaderFrameError::InitialBreak => ExecStageError::Invariant,
        LoaderFrameError::Loader(runtime_error)
        | LoaderFrameError::LoaderFramesQuarantined(runtime_error) => match runtime_error {
            RuntimeError::Elf(_)
            | RuntimeError::UserPolicy(_)
            | RuntimeError::Initialization(_)
            | RuntimeError::LinuxStack(_)
            | RuntimeError::LinuxStackInvariant
            | RuntimeError::InterpreterRequired
            | RuntimeError::Mapping(_)
            | RuntimeError::FrameCountMismatch { .. }
            | RuntimeError::DuplicateFrame
            | RuntimeError::ReservedFrame
            | RuntimeError::AddressOverflow
            | RuntimeError::Vm
            | RuntimeError::AddressSpace
            | RuntimeError::Usercopy
            | RuntimeError::CacheMaintenance
            | RuntimeError::StagingRollbackFailed => ExecStageError::Invariant,
        },
    }
}

/// Fully staged replacement image that is still invisible to the running Process.
///
/// The replacement carries the exact same Process and AddressSpace ObjectIds as the current retained
/// binding, but a distinct logical binding/root. `loaded` is the canonical ELF/Linux-stack result and
/// includes the exact unrounded initial brk value. Neither field is publication authority by itself;
/// the later exec commit must re-enter the canonical runtime owner before activation/swap.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) struct StagedExecImage {
    replacement: BoundProcessAddressSpace<{ runtime::STEP15_RUNTIME_VMAS }>,
    loaded: super::loader_frames::LoadedInitialLinuxImage,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl StagedExecImage {
    pub(super) fn into_parts(
        self,
    ) -> (
        BoundProcessAddressSpace<{ runtime::STEP15_RUNTIME_VMAS }>,
        super::loader_frames::LoadedInitialLinuxImage,
    ) {
        (self.replacement, self.loaded)
    }
}

/// Stages one complete exec ELF/Linux-stack image in a fresh same-Process AArch64 binding.
///
/// The exact Process is selected only through the current generation's canonical LinuxIdentity
/// relation using `with_fork_snapshot_parent`; despite the historical helper name, that bridge is a
/// read-only exact-current Process/AddressSpace/ObjectTable selector and works for both bootstrap and
/// retained fork-child Processes.
///
/// RuntimeTablePool and the sole Core frame pool are held in their existing global order. The fresh
/// binding is created from the selected Process's mandatory AddressSpace capability, then the live-exec
/// loader returns a linear frame journal on failure. The lower loader may temporarily select/deactivate
/// that fresh root while populating userspace, so this owner explicitly restores the original retained
/// binding before either a staged replacement escapes or a failed staging binding is discarded. Every
/// mapped or never-mapped failed-staging frame is then returned to the sole Core frame pool.
///
/// # Safety
/// Caller must own the exact current PE lower-EL synchronous no-switch window with local IRQs masked,
/// preemption/migration suppressed and `current` equal to the trapping scheduler generation. `image`
/// and all LinuxProcessStart borrows must remain valid for this synchronous call. Nothing may return to
/// EL0 or context-switch while the sole live table/frame/runtime borrows are held.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) unsafe fn stage_exec_image(
    current: GlobalThreadId,
    image: &[u8],
    interpreter: Option<&[u8]>,
    start: kernal_user_elf_runtime_aarch64::LinuxProcessStart<'_>,
) -> Result<StagedExecImage, ExecStageError> {
    // SAFETY: delegated caller contract owns the exact same synchronous live-table mutation window.
    let table_result = unsafe {
        RuntimeTablePool::with_live(|page_tables| {
            memory::with_live_frame_pool(|frame_pool| {
                runtime::with_linux_runtime(|linux| {
                    linux.with_fork_snapshot_parent(current, |process, active_space, objects| {
                        super::loader_frames::preflight_exec_linux_load::<STEP30_EXEC_SEGMENTS>(
                            image,
                            interpreter,
                            start,
                        )
                        .map_err(map_exec_preflight_error)?;

                        let mut replacement = BoundProcessAddressSpace::<
                            { runtime::STEP15_RUNTIME_VMAS },
                        >::create(
                            process, objects, page_tables
                        )
                        .map_err(|_| ExecStageError::Invariant)?;

                        // This receipt-preserving live wrapper reuses canonical
                        // `load_aarch64_linux_elf` while retaining all removed frames on failure.
                        // SAFETY: the fresh binding is not active or retained anywhere else;
                        // page-table/frame owners and the exact Process/ObjectTable remain borrowed
                        // for this complete canonical loader transaction.
                        let loaded = unsafe {
                            super::loader_frames::load_exec_linux_elf_with_core_frames::<
                                STEP30_EXEC_FRAME_CAPACITY,
                                STEP30_EXEC_SEGMENTS,
                                { runtime::STEP15_RUNTIME_CAPS },
                                { runtime::STEP15_RUNTIME_OBJECTS },
                                { runtime::STEP15_RUNTIME_VMAS },
                                RuntimeTablePool,
                            >(
                                image,
                                interpreter,
                                start,
                                frame_pool,
                                process,
                                objects,
                                &mut replacement,
                                page_tables,
                            )
                        };

                        // Loader staging may leave the PE on the fresh root or in the kernel-only
                        // TTBR1 regime. Re-establish the exact original logical binding before any
                        // recoverable result leaves this transaction. Failure here cannot safely
                        // return to the old EL0 image, so contain it non-returningly.
                        // SAFETY: the same no-switch owner window still serializes TTBR0 and the
                        // per-PE activation registry for this exact Process.
                        if unsafe { active_space.activate_owner(process, objects) }.is_err() {
                            loop {
                                core::hint::spin_loop();
                            }
                        }

                        let loaded = match loaded {
                            Ok(loaded) => loaded,
                            Err(mut failure) => {
                                // SAFETY: the original binding was restored immediately above;
                                // staging has never been published and may already be poisoned.
                                // The discard owner removes only its anonymous leaves and hands
                                // each exact mapped frame back through the linear failure receipt.
                                unsafe {
                                    replacement.discard_exec_staging_anonymous_user_frames(
                                        process,
                                        objects,
                                        active_space,
                                        page_tables,
                                        |frame| failure.release_discarded_frame(frame_pool, frame),
                                    )
                                }
                                .map_err(|_| ExecStageError::Invariant)?;

                                // Return frames allocated but never mapped (or already rolled back
                                // by the lower loader) before exposing a recoverable staging error.
                                let semantic_error = failure
                                    .reclaim_remaining(frame_pool)
                                    .map_err(|_| ExecStageError::Invariant)?;
                                return Err(map_exec_recovered_load_error(semantic_error));
                            }
                        };

                        Ok(StagedExecImage {
                            replacement,
                            loaded,
                        })
                    })
                })
            })
        })
    }
    .map_err(|_| ExecStageError::Invariant)?;

    let frame_result = table_result.map_err(|_| ExecStageError::Invariant)?;
    let runtime_result = frame_result.map_err(|_| ExecStageError::Invariant)?;
    let selection_result = runtime_result.map_err(|_| ExecStageError::Invariant)?;
    selection_result
}

/// Core-side exec orchestration for the canonical process-aarch64 superseded-binding owner edge.
///
/// No cleanup policy lives here. The process owner validates exact Process/AddressSpace identity,
/// proves the replacement binding current and the old binding inactive, drains only anonymous leaves
/// and poisons partial failures. Core supplies only the already-owned page-table/frame transaction.
///
/// # Safety
/// Caller must satisfy `BoundProcessAddressSpace::reclaim_superseded_anonymous_user_frames`: own the
/// local non-switching page-table window, pass the committed replacement plus exact prior binding,
/// and ensure no scheduler generation can reach the prior image while the drain is in progress.
#[allow(clippy::too_many_arguments, dead_code)]
pub(super) unsafe fn reclaim_superseded_anonymous_user_frames<
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    B: Backend,
    F: FnMut(PhysFrame) -> bool,
>(
    process: &Process<CAPS>,
    objects: &ObjectTable<OBJECTS>,
    superseded: &mut BoundProcessAddressSpace<VMAS>,
    active_space: &BoundProcessAddressSpace<VMAS>,
    backend: &mut B,
    release: F,
) -> Result<usize, ProcessAddressSpaceError> {
    // SAFETY: delegated function contract is intentionally identical to the canonical owner edge.
    unsafe {
        superseded.reclaim_superseded_anonymous_user_frames(
            process,
            objects,
            active_space,
            backend,
            release,
        )
    }
}
