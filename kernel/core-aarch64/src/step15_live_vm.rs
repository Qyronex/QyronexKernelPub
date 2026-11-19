// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::{kmap, memory, runtime};
use alloc::vec::Vec;
use kernal_capability::ObjectId;
use kernal_linux_abi::{Errno, MinimumRuntimeCall};
use kernal_linux_vm::{
    DEFAULT_MMAP_CEILING, Error as VmError, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, MmapFileBacking,
    STEP15_ANON_FLAGS, parse_step31_perms, validate_step31_mmap_spec,
};
use kernal_memory::PhysFrame;
use kernal_object::ObjectTable;
use kernal_page_table_aarch64::Backend;
use kernal_process::Process;
use kernal_process_aarch64::{BoundProcessAddressSpace, Error as ProcessAddressSpaceError};
use kernal_protected_boot_aarch64::RuntimeTablePool;
use kernal_scheduler_smp::GlobalThreadId;
use kernal_vm::{Backing, PAGE_SIZE, VmPerms, Vma};

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_exceptions_aarch64::ExceptionFrame;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_linux_clone::ProcessClonePlan;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_scheduler_cpu::CpuSchedulerCell;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_user_entry_aarch64::El0ReturnState;

/// Upper bound (`512 MiB`) for virtual unbacked `PROT_NONE` reservations (`glibc` arenas, guard spans).
const PROT_NONE_RES_MAX_LEN: u64 = 512 * 1024 * 1024;

struct ProtNoneResCell {
    state: core::sync::atomic::AtomicU8,
    entries: core::cell::UnsafeCell<Vec<(ObjectId, u64, u64)>>,
}

// SAFETY: synchronous kernel trap/lifecycle paths serialize all accesses via `state` CAS.
unsafe impl Sync for ProtNoneResCell {}

static PROT_NONE_RES: ProtNoneResCell = ProtNoneResCell {
    state: core::sync::atomic::AtomicU8::new(0),
    entries: core::cell::UnsafeCell::new(Vec::new()),
};

fn with_prot_none_res<R>(f: impl FnOnce(&mut Vec<(ObjectId, u64, u64)>) -> R) -> R {
    use core::sync::atomic::Ordering;
    while PROT_NONE_RES
        .state
        .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: `state == 1` grants exclusive access; closures never re-enter `with_prot_none_res`.
    let res = f(unsafe { &mut *PROT_NONE_RES.entries.get() });
    PROT_NONE_RES.state.store(0, Ordering::Release);
    res
}

fn res_earliest_overlap(
    entries: &[(ObjectId, u64, u64)],
    process: ObjectId,
    start: u64,
    end: u64,
) -> Option<u64> {
    let mut best: Option<u64> = None;
    for &(p, rs, re) in entries {
        if p == process && rs < end && start < re {
            best = Some(match best {
                Some(prev) if prev < rs => prev,
                _ => rs,
            });
        }
    }
    best
}

fn res_punch_range(
    entries: &mut Vec<(ObjectId, u64, u64)>,
    process: ObjectId,
    start: u64,
    end: u64,
) {
    if start >= end {
        return;
    }
    let mut add = Vec::new();
    let mut i = 0;
    while i < entries.len() {
        let (p, rs, re) = entries[i];
        if p == process && rs < end && start < re {
            entries.swap_remove(i);
            if rs < start {
                add.push((p, rs, start));
            }
            if re > end {
                add.push((p, end, re));
            }
        } else {
            i += 1;
        }
    }
    entries.extend(add);
}

fn res_insert_merged(
    entries: &mut Vec<(ObjectId, u64, u64)>,
    process: ObjectId,
    mut start: u64,
    mut end: u64,
) {
    if start >= end {
        return;
    }
    res_punch_range(entries, process, start, end);
    let mut i = 0;
    while i < entries.len() {
        let (p, rs, re) = entries[i];
        if p == process && (re == start || end == rs) {
            entries.swap_remove(i);
            start = start.min(rs);
            end = end.max(re);
        } else {
            i += 1;
        }
    }
    entries.push((process, start, end));
}

fn split_against_res(
    entries: &[(ObjectId, u64, u64)],
    process: ObjectId,
    start: u64,
    end: u64,
) -> Vec<(bool, u64, u64)> {
    let mut overlaps: Vec<(u64, u64)> = Vec::new();
    for &(p, rs, re) in entries {
        if p == process && rs < end && start < re {
            overlaps.push((rs.max(start), re.min(end)));
        }
    }
    overlaps.sort_unstable_by_key(|r| r.0);
    let mut out = Vec::new();
    let mut cursor = start;
    for (rs, re) in overlaps {
        if rs > cursor {
            out.push((false, cursor, rs));
        }
        if re > cursor {
            let s = rs.max(cursor);
            if re > s {
                out.push((true, s, re));
                cursor = re;
            }
        }
    }
    if cursor < end {
        out.push((false, cursor, end));
    }
    out
}

fn align_len(length: u64) -> Result<u64, VmError> {
    if length == 0 {
        return Err(VmError::Linux(Errno::EINVAL));
    }
    length
        .checked_add(PAGE_SIZE - 1)
        .map(|v| v & !(PAGE_SIZE - 1))
        .ok_or_else(enomem_err)
}

fn validate_range(start: u64, len: u64) -> Result<(), VmError> {
    Vma::new(start, len, VmPerms::NONE, Backing::Anonymous)
        .map(|_| ())
        .map_err(|_| VmError::Linux(Errno::EINVAL))
}

fn enomem_err() -> VmError {
    Errno::new(12).map_or(VmError::BackendInvariant, VmError::Linux)
}

fn find_gap_avoiding_res(
    process_id: ObjectId,
    process: &Process<{ runtime::STEP15_RUNTIME_CAPS }>,
    objects: &ObjectTable<{ runtime::STEP15_RUNTIME_OBJECTS }>,
    space: &BoundProcessAddressSpace<{ runtime::STEP15_RUNTIME_VMAS }>,
    len: u64,
    hint: u64,
) -> Result<u64, VmError> {
    if hint != 0
        && validate_range(hint, len).is_ok()
        && let Some(end) = hint.checked_add(len)
        && space
            .user_range_is_free(process, objects, process.address_space_handle(), hint, len)
            .unwrap_or(false)
        && with_prot_none_res(|e| res_earliest_overlap(e, process_id, hint, end).is_none())
    {
        return Ok(hint);
    }

    let mut ceiling = DEFAULT_MMAP_CEILING;
    for _ in 0..1024 {
        if ceiling < len {
            return Err(enomem_err());
        }
        let cand = space
            .find_user_gap_top_down(
                process,
                objects,
                process.address_space_handle(),
                len,
                ceiling,
            )
            .map_err(|_| enomem_err())?;
        let end = cand.checked_add(len).ok_or_else(enomem_err)?;
        let overlap = with_prot_none_res(|e| res_earliest_overlap(e, process_id, cand, end));
        match overlap {
            None => return Ok(cand),
            Some(r_start) => {
                if r_start >= ceiling || r_start <= PAGE_SIZE {
                    return Err(enomem_err());
                }
                ceiling = r_start;
            }
        }
    }
    Err(enomem_err())
}

pub(super) fn on_process_fork(parent: ObjectId, child: ObjectId) {
    with_prot_none_res(|entries| {
        let mut cloned = Vec::new();
        for &(p, s, e) in entries.iter() {
            if p == parent {
                cloned.push((child, s, e));
            }
        }
        entries.extend(cloned);
    });
}

pub(super) fn on_process_exec(process: ObjectId) {
    with_prot_none_res(|entries| entries.retain(|&(p, _, _)| p != process));
}

pub(super) fn on_process_exit(process: ObjectId) {
    with_prot_none_res(|entries| entries.retain(|&(p, _, _)| p != process));
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) fn has_prot_none_overlap(address: u64, length: u64) -> bool {
    let Some(process) = super::step_fd_util::current_process_object() else {
        return false;
    };
    let len = if length == 0 {
        PAGE_SIZE
    } else {
        match length.checked_add(PAGE_SIZE - 1) {
            Some(v) => v & !(PAGE_SIZE - 1),
            None => return true,
        }
    };
    let start = address & !(PAGE_SIZE - 1);
    let end = start.saturating_add(len);
    with_prot_none_res(|e| res_earliest_overlap(e, process, start, end).is_some())
}

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
                if let MinimumRuntimeCall::Munmap { address, length } = call {
                    let len = match align_len(length) {
                        Ok(l) => l,
                        Err(e) => return Err(e),
                    };
                    validate_range(address, len)?;
                    let end = address.checked_add(len).ok_or_else(enomem_err)?;
                    let segs =
                        with_prot_none_res(|e| split_against_res(e, process.id(), address, end));
                    if segs.iter().any(|(in_res, ..)| *in_res) {
                        for &(in_res, s, e) in &segs {
                            if !in_res {
                                kernal_linux_vm_aarch64::handle_current(
                                    vm,
                                    process,
                                    objects,
                                    space,
                                    page_tables,
                                    reserved,
                                    frames,
                                    zeroer,
                                    MinimumRuntimeCall::Munmap {
                                        address: s,
                                        length: e - s,
                                    },
                                )?;
                            }
                        }
                        with_prot_none_res(|el| res_punch_range(el, process.id(), address, end));
                        return Ok(0);
                    }
                }

                let mut adjusted_call = call;
                if let MinimumRuntimeCall::Mmap {
                    address,
                    length,
                    protection,
                    flags,
                    fd,
                    offset,
                } = call
                    && flags == STEP15_ANON_FLAGS
                    && fd == u64::MAX
                    && offset == 0
                    && let Ok(len) = align_len(length)
                    && (len / PAGE_SIZE) <= runtime::STEP15_RUNTIME_VM_TX_PAGES as u64
                {
                    let chosen =
                        find_gap_avoiding_res(process.id(), process, objects, space, len, address)?;
                    adjusted_call = MinimumRuntimeCall::Mmap {
                        address: chosen,
                        length,
                        protection,
                        flags,
                        fd,
                        offset,
                    };
                }

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
                    adjusted_call,
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
    if let Ok(spec) = validate_step31_mmap_spec(protection, flags, fd, offset)
        && spec.anonymous
        && !spec.shared
        && spec.perms == VmPerms::NONE
        && matches!(backing, MmapFileBacking::Anonymous)
    {
        let vm_result = unsafe {
            with_current_vm_tx(
                |vm, process, objects, space, page_tables, reserved, frames, zeroer| {
                    let len = align_len(length)?;
                    if len > PROT_NONE_RES_MAX_LEN {
                        return Err(enomem_err());
                    }
                    let start = if spec.fixed {
                        validate_range(address, len)?;
                        let end = address.checked_add(len).ok_or_else(enomem_err)?;
                        let segs = with_prot_none_res(|e| {
                            split_against_res(e, process.id(), address, end)
                        });
                        for &(in_res, s, e) in &segs {
                            if !in_res {
                                kernal_linux_vm_aarch64::handle_current(
                                    vm,
                                    process,
                                    objects,
                                    space,
                                    page_tables,
                                    reserved,
                                    frames,
                                    zeroer,
                                    MinimumRuntimeCall::Munmap {
                                        address: s,
                                        length: e - s,
                                    },
                                )?;
                            }
                        }
                        address
                    } else {
                        find_gap_avoiding_res(process.id(), process, objects, space, len, address)?
                    };
                    let end = start.checked_add(len).ok_or_else(enomem_err)?;
                    with_prot_none_res(|e| res_insert_merged(e, process.id(), start, end));
                    Ok(start)
                },
            )
        }?;
        return Ok(vm_result);
    }

    // SAFETY: same synchronous lower-EL trap owner window as `handle`.
    let vm_result = unsafe {
        with_current_vm_tx(
            |_vm, process, objects, space, page_tables, reserved, frames, zeroer| {
                let mut target_address = address;
                let mut mapped_len: Option<(bool, u64)> = None;
                if let Ok(spec) = validate_step31_mmap_spec(protection, flags, fd, offset)
                    && let Ok(len) = align_len(length)
                {
                    if !spec.fixed {
                        if (len / PAGE_SIZE) > runtime::STEP31_DYNAMIC_MMAP_TX_PAGES as u64 {
                            return Err(enomem_err());
                        }
                        target_address = find_gap_avoiding_res(
                            process.id(),
                            process,
                            objects,
                            space,
                            len,
                            address,
                        )?;
                    }
                    mapped_len = Some((spec.fixed, len));
                }
                // SAFETY: exact Process/CSpace, bound address space, live table cursor,
                // reservation set, frame allocator and persistent KMap zeroer are held.
                let res = kernal_linux_vm_aarch64::handle_step31_dynamic_mmap::<
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
                    target_address,
                    length,
                    protection,
                    flags,
                    fd,
                    offset,
                    backing,
                );
                if let Ok(va) = res
                    && let Some((true, len)) = mapped_len
                    && let Some(end) = va.checked_add(len)
                {
                    with_prot_none_res(|e| res_punch_range(e, process.id(), va, end));
                }
                res
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
    let perms = match parse_step31_perms(protection) {
        Ok(p) => p,
        Err(e) => return Ok(Err(e)),
    };
    if length == 0 {
        return Ok(validate_range(address, PAGE_SIZE));
    }
    let len = match align_len(length) {
        Ok(l) => l,
        Err(e) => return Ok(Err(e)),
    };
    if let Err(e) = validate_range(address, len) {
        return Ok(Err(e));
    }

    // SAFETY: same synchronous lower-EL trap owner window as `handle`.
    let vm_result = unsafe {
        with_current_vm_tx(
            |_vm, process, objects, space, page_tables, reserved, frames, zeroer| {
                let end = address.checked_add(len).ok_or_else(enomem_err)?;
                let segs = with_prot_none_res(|e| split_against_res(e, process.id(), address, end));
                if !segs.iter().any(|(in_res, ..)| *in_res) {
                    // SAFETY: exact Process/CSpace, bound address space, live table cursor,
                    // reservation set, frame allocator and persistent KMap zeroer are held.
                    return kernal_linux_vm_aarch64::handle_step31_mprotect::<
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
                    );
                }

                for &(in_res, s, e) in &segs {
                    if !in_res {
                        let mut va = s;
                        while va < e {
                            if space
                                .translate_user(
                                    process,
                                    objects,
                                    process.address_space_handle(),
                                    page_tables,
                                    va,
                                )
                                .is_err()
                            {
                                return Err(enomem_err());
                            }
                            va += PAGE_SIZE;
                        }
                    }
                }

                let max_chunk = (runtime::STEP31_DYNAMIC_MMAP_TX_PAGES as u64) * PAGE_SIZE;
                for &(in_res, s, e) in &segs {
                    let mut cur = s;
                    while cur < e {
                        let chunk = (e - cur).min(max_chunk);
                        if !in_res {
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
                                cur,
                                chunk,
                                protection,
                            )?;
                        } else if perms != VmPerms::NONE {
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
                                cur,
                                chunk,
                                protection,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                u64::MAX,
                                0,
                                MmapFileBacking::Anonymous,
                            )?;
                            with_prot_none_res(|el| {
                                res_punch_range(el, process.id(), cur, cur + chunk)
                            });
                        }
                        cur += chunk;
                    }
                }
                Ok(())
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
                    let staged_snapshot = kmap::with_kmap(|zeroer| {
                        // SAFETY: exact parent frame, runtime, page-table, frame and KMap owners
                        // are all held for this never-published staging operation.
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
                    });
                    let staged_snapshot = match staged_snapshot {
                        Ok(Ok(receipt)) => receipt,
                        Ok(Err(_)) | Err(_) => return Err(()),
                    };

                    // SAFETY: caller still owns the scheduler/quiescent window and the exact receipt
                    // has not escaped or been published.
                    let staged_scheduler = match super::step30_fork::stage_fork_scheduler_generation_with_clear_child_tid(
                        scheduler,
                        staged_snapshot,
                        priority,
                        child_tid_clear,
                    ) {
                        Ok(receipt) => receipt,
                        Err(error) => {
                            if let Some((_scheduler_error, receipt)) = error.into_recoverable() {
                                // SAFETY: the scheduler contract proved no generation was published;
                                // rollback consumes the exact still-reversible snapshot receipt.
                                super::step30_fork::rollback_unpublished_fork_transaction(
                                    linux,
                                    current,
                                    receipt,
                                    page_tables,
                                    frame_pool,
                                )
                                .map_err(|_| ())?;
                            }
                            return Err(());
                        }
                    };

                    // SAFETY: the exact scheduler generation remains Blocked+Staged and owner-held.
                    let staged_leader = match super::step30_fork::stage_fork_leader_authority(
                        scheduler,
                        linux,
                        staged_scheduler,
                    ) {
                        Ok(receipt) => receipt,
                        Err(_) => return Err(()),
                    };

                    // SAFETY: final publication consumes the exact leader receipt and performs no
                    // fallible userspace access. Any recoverable error proves Blocked+Staged state.
                    match super::step30_fork::publish_staged_fork_leader(
                        scheduler,
                        linux,
                        staged_leader,
                    ) {
                        Ok(published) => Ok(published),
                        Err(error) => {
                            if let Some((_publish_error, receipt)) = error.into_recoverable() {
                                // SAFETY: recoverable publish failure restored the complete staged
                                // leader receipt; owner/page-table/frame state remains unchanged.
                                super::step30_fork::rollback_staged_fork_leader_authority(
                                    scheduler,
                                    linux,
                                    current,
                                    receipt,
                                    page_tables,
                                    frame_pool,
                                )
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
) -> Result<alloc::boxed::Box<StagedExecImage>, ExecStageError> {
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

                        Ok(alloc::boxed::Box::new(StagedExecImage {
                            replacement,
                            loaded,
                        }))
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

/// Allocates `pages` contiguous physical 4 KiB frames and zeroes each frame before returning the
/// physical base address.
#[allow(dead_code)]
pub(super) fn alloc_zeroed_contiguous_frames(pages: u64) -> Result<u64, ()> {
    if pages == 0 {
        return Err(());
    }
    // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked window.
    let res = unsafe {
        RuntimeTablePool::with_live(|page_tables| {
            memory::with_live_frame_pool(|frame_pool| {
                kmap::with_kmap(|zeroer| {
                    let (frames, _reserved) = frame_pool.split();
                    let range = frames.allocate(pages, 1).map_err(|_| ())?;
                    for page_idx in 0..pages {
                        let phys = range.start.saturating_add(page_idx.saturating_mul(4096));
                        if zeroer.zero_frame(page_tables, phys).is_err() {
                            let _ = frames.free(range);
                            return Err(());
                        }
                    }
                    Ok(range.start)
                })
            })
        })
    };
    res.map_err(|_| ())?.map_err(|_| ())?.map_err(|_| ())?
}

/// Returns `pages` contiguous physical frames back to the live frame allocator.
#[allow(dead_code)]
pub(super) fn free_contiguous_frames(phys_base: u64, pages: u64) -> Result<(), ()> {
    let range = kernal_frame_allocator::FrameRange::new(phys_base, pages).map_err(|_| ())?;
    let res = memory::with_live_frame_pool(|frame_pool| {
        let (frames, _reserved) = frame_pool.split();
        frames.free(range).map_err(|_| ())
    });
    res.map_err(|_| ())?
}

/// Writes up to one 4 KiB page into a caller-owned physical frame through KMap.
#[allow(dead_code)]
pub(super) fn write_phys_page_bytes(phys_page: u64, offset: usize, bytes: &[u8]) -> Result<(), ()> {
    // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked window and caller owns `phys_page`.
    let res = unsafe {
        RuntimeTablePool::with_live(|page_tables| {
            kmap::with_kmap(|zeroer| {
                zeroer
                    .write_frame_bytes(page_tables, phys_page, offset, bytes)
                    .map_err(|_| ())
            })
        })
    };
    res.map_err(|_| ())?.map_err(|_| ())?
}
