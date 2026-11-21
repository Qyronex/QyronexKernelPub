// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Step 45: Native Android 15 / GrapheneOS / Google Pixel kernel runtime subsystem.
//!
//! Exposes live 64-bit Binder IPC (`/dev/binder`, `/dev/hwbinder`, `/dev/vndbinder`),
//! Android Shared Memory (`/dev/ashmem`, `/dev/dma_heap/system`), SELinuxFS (`/sys/fs/selinux/*`),
//! Android Power Wakelocks (`/sys/power/wake_lock`), PSI (`/proc/pressure/*`), Android Log
//! (`/dev/log/main`, `/dev/pmsg0`), immutable `ro.*` System Properties, GrapheneOS hardening
//! status, and Google Pixel Tensor/Titan M2 hardware telemetry.

use super::step_fd_util::{
    DirectProcessRefs, S_IFCHR_MODE, S_IFREG_MODE, SUBSYS_ANDROID, StatMeta, copy_from_user,
    copy_to_user, current_process_object, current_uid_gid, encode_result, fd_in_close_range,
    lookup_aliased_subsystem, lookup_aliased_subsystem_current, read_user_cstr, read_user_iovec,
    seek_bounded, write_aarch64_stat_meta, write_aarch64_statx_meta,
};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_capability::{CapRights, Capability, ObjectId};
use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_google_pixel::{GooglePixelBoard, PixelSocGeneration};
use kernal_linux_abi::{Errno, POLLIN, POLLOUT, SyscallRequest, SyscallReturn, linux_signed_int};
use kernal_linux_android::{
    ASHMEM_GET_NAME, ASHMEM_GET_PIN_STATUS, ASHMEM_GET_PROT_MASK, ASHMEM_GET_SIZE,
    ASHMEM_IS_PINNED, ASHMEM_IS_UNPINNED, ASHMEM_PIN, ASHMEM_PURGE_ALL_CACHES, ASHMEM_SET_NAME,
    ASHMEM_SET_PROT_MASK, ASHMEM_SET_SIZE, ASHMEM_UNPIN, AndroidKernelState, BC_ACQUIRE,
    BC_DEAD_BINDER_DONE, BC_DECREFS, BC_ENTER_LOOPER, BC_EXIT_LOOPER, BC_FREE_BUFFER, BC_INCREFS,
    BC_REGISTER_LOOPER, BC_RELEASE, BC_REPLY, BC_REQUEST_DEATH_NOTIFICATION, BC_TRANSACTION,
    BINDER_CURRENT_PROTOCOL_VERSION, BINDER_SET_CONTEXT_MGR, BINDER_SET_CONTEXT_MGR_EXT,
    BINDER_SET_IDLE_PRIORITY, BINDER_SET_IDLE_TIMEOUT, BINDER_SET_MAX_THREADS, BINDER_THREAD_EXIT,
    BINDER_TRANSACTION_DATA_BYTES, BINDER_VERSION, BINDER_WRITE_READ, BINDER_WRITE_READ_BYTES,
    BR_NOOP, BR_REPLY, BR_TRANSACTION, BR_TRANSACTION_COMPLETE, BinderDomain,
    BinderTransactionData, BinderWriteRead, DMA_HEAP_IOCTL_ALLOC, MAX_BINDER_PAYLOAD_BYTES,
};
use kernal_linux_fd::SubsystemHandle;

/// Dedicated file-descriptor base for Step-45 Android/Pixel/GrapheneOS descriptors (`1024..1056`),
/// cleanly partitioned above `DEV_FD_BASE` (`992..1024`).
pub(super) const ANDROID_FD_BASE: i32 = 1024;
const MAX_ANDROID_FDS: usize = 32;
const O_CLOEXEC_U64: u64 = 0x0008_0000;
const O_NONBLOCK_U64: u64 = 0x0800;
const O_DIRECTORY_U64: u64 = 0x0000_4000;
const AT_EMPTY_PATH: u64 = 0x1000;
const MAX_LOG_RING_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
enum AndroidNodeKind {
    None,
    Binder(BinderDomain),
    Ashmem,
    DmaHeapSystem,
    AndroidLogMain,
    SelinuxEnforce,
    SelinuxMls,
    SelinuxPolicyvers,
    SelinuxStatus,
    PowerWakeLock,
    PowerWakeUnlock,
    PowerState,
    PsiMemory,
    PsiCpu,
    PsiIo,
    QyronexProperties,
    QyronexBinderStats,
    GrapheneOsStatus,
    GooglePixelStatus,
}

impl AndroidNodeKind {
    const fn stat_mode(self) -> u32 {
        match self {
            Self::Binder(_) | Self::Ashmem | Self::DmaHeapSystem | Self::AndroidLogMain => {
                S_IFCHR_MODE
            }
            _ => S_IFREG_MODE,
        }
    }

    const fn rdev_and_ino(self) -> (u64, u64) {
        match self {
            Self::None => (0, 0),
            Self::Binder(BinderDomain::Framework) => ((10u64 << 8) | 60, 45_001),
            Self::Binder(BinderDomain::HardwareHal) => ((10u64 << 8) | 61, 45_002),
            Self::Binder(BinderDomain::Vendor) => ((10u64 << 8) | 62, 45_003),
            Self::Ashmem => ((10u64 << 8) | 63, 45_004),
            Self::DmaHeapSystem => ((252u64 << 8), 45_005),
            Self::AndroidLogMain => ((10u64 << 8) | 64, 45_006),
            Self::SelinuxEnforce => (0, 45_010),
            Self::SelinuxMls => (0, 45_011),
            Self::SelinuxPolicyvers => (0, 45_012),
            Self::SelinuxStatus => (0, 45_013),
            Self::PowerWakeLock => (0, 45_020),
            Self::PowerWakeUnlock => (0, 45_021),
            Self::PowerState => (0, 45_022),
            Self::PsiMemory => (0, 45_030),
            Self::PsiCpu => (0, 45_031),
            Self::PsiIo => (0, 45_032),
            Self::QyronexProperties => (0, 45_040),
            Self::QyronexBinderStats => (0, 45_041),
            Self::GrapheneOsStatus => (0, 45_042),
            Self::GooglePixelStatus => (0, 45_043),
        }
    }

    const fn path_bytes(self) -> &'static [u8] {
        match self {
            Self::None => b"",
            Self::Binder(BinderDomain::Framework) => b"/dev/binder",
            Self::Binder(BinderDomain::HardwareHal) => b"/dev/hwbinder",
            Self::Binder(BinderDomain::Vendor) => b"/dev/vndbinder",
            Self::Ashmem => b"/dev/ashmem",
            Self::DmaHeapSystem => b"/dev/dma_heap/system",
            Self::AndroidLogMain => b"/dev/log/main",
            Self::SelinuxEnforce => b"/sys/fs/selinux/enforce",
            Self::SelinuxMls => b"/sys/fs/selinux/mls",
            Self::SelinuxPolicyvers => b"/sys/fs/selinux/policyvers",
            Self::SelinuxStatus => b"/sys/fs/selinux/status",
            Self::PowerWakeLock => b"/sys/power/wake_lock",
            Self::PowerWakeUnlock => b"/sys/power/wake_unlock",
            Self::PowerState => b"/sys/power/state",
            Self::PsiMemory => b"/proc/pressure/memory",
            Self::PsiCpu => b"/proc/pressure/cpu",
            Self::PsiIo => b"/proc/pressure/io",
            Self::QyronexProperties => b"/sys/kernel/qyronex/android/properties",
            Self::QyronexBinderStats => b"/sys/kernel/qyronex/android/binder_stats",
            Self::GrapheneOsStatus => b"/sys/kernel/qyronex/grapheneos/status",
            Self::GooglePixelStatus => b"/sys/bus/platform/drivers/google_pixel/status",
        }
    }
}

#[derive(Clone, Copy)]
struct AndroidFdSlot {
    live: bool,
    kind: AndroidNodeKind,
    generation: u64,
    owners: DirectProcessRefs<16>,
    alias_refs: u32,
    offset: usize,
    status_flags: u64,
    binder_endpoint_id: u32,
    ashmem_region_id: u32,
}

impl AndroidFdSlot {
    const EMPTY: Self = Self {
        live: false,
        kind: AndroidNodeKind::None,
        generation: 0,
        owners: DirectProcessRefs::empty(),
        alias_refs: 0,
        offset: 0,
        status_flags: 0,
        binder_endpoint_id: 0,
        ashmem_region_id: 0,
    };
}

struct Step45State {
    initialized: bool,
    android: Option<AndroidKernelState>,
    pixel: GooglePixelBoard<4>,
    log_ring: Vec<u8>,
    next_fd_generation: u64,
    fds: [AndroidFdSlot; MAX_ANDROID_FDS],
}

impl Step45State {
    const fn new() -> Self {
        Self {
            initialized: false,
            android: None,
            pixel: GooglePixelBoard::new(PixelSocGeneration::EmulatorVirtGki),
            log_ring: Vec::new(),
            next_fd_generation: 1,
            fds: [AndroidFdSlot::EMPTY; MAX_ANDROID_FDS],
        }
    }

    fn ensure_initialized(&mut self) {
        if !self.initialized {
            let mut state = AndroidKernelState::new();
            state.hardening.hw_pan_active = kernal_usercopy_aarch64::pan_supported();
            let admin_cap = Capability {
                object: ObjectId(45),
                rights: CapRights::READ
                    .union(CapRights::WRITE)
                    .union(CapRights::CONTROL),
            };
            let _ = self.pixel.initialize_board(admin_cap);
            state.hardening.hw_mte_supported = self.pixel.hw_mte_enabled;
            self.android = Some(state);
            self.append_log(
                b"I/QyronexAndroid: Hybrid Rust Android 15 / GrapheneOS kernel subsystem online\n",
            );
            self.append_log(
                b"I/TitanM2: StrongBox KeyMint 3.0 ready | Verified Boot=green | Modem IOMMU=sandboxed\n",
            );
            self.initialized = true;
        }
    }

    fn android(&self) -> &AndroidKernelState {
        self.android
            .as_ref()
            .expect("Step45State::ensure_initialized called before access")
    }

    fn android_mut(&mut self) -> &mut AndroidKernelState {
        self.android
            .as_mut()
            .expect("Step45State::ensure_initialized called before access")
    }

    fn append_log(&mut self, bytes: &[u8]) {
        if self.log_ring.len().saturating_add(bytes.len()) > MAX_LOG_RING_BYTES {
            let drop_len = self
                .log_ring
                .len()
                .saturating_add(bytes.len())
                .saturating_sub(MAX_LOG_RING_BYTES)
                .min(self.log_ring.len());
            self.log_ring.drain(..drop_len);
        }
        self.log_ring.extend_from_slice(bytes);
    }
}

struct Step45Cell {
    state: AtomicU8,
    value: UnsafeCell<Step45State>,
}

// SAFETY: atomic `0 -> 1 -> 0` lock serializes all synchronous EL0 trap accesses.
unsafe impl Sync for Step45Cell {}

static STEP45_STATE: Step45Cell = Step45Cell {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(Step45State::new()),
};

fn with_step45_state<R>(f: impl FnOnce(&mut Step45State) -> R) -> Result<R, ()> {
    if STEP45_STATE
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(());
    }
    // SAFETY: state `1` provides exclusive mutable ownership for this synchronous scope.
    let state = unsafe { &mut *STEP45_STATE.value.get() };
    state.ensure_initialized();
    let res = f(state);
    STEP45_STATE.state.store(0, Ordering::Release);
    Ok(res)
}

/// Configures the Google Pixel Tensor SoC generation detected from FDT or bootargs.
#[allow(dead_code)]
pub(super) fn configure_pixel_soc(soc: PixelSocGeneration) {
    let _ = with_step45_state(|state| {
        let admin_cap = Capability {
            object: ObjectId(45),
            rights: CapRights::READ
                .union(CapRights::WRITE)
                .union(CapRights::CONTROL),
        };
        let mut board = GooglePixelBoard::new(soc);
        let _ = board.initialize_board(admin_cap);
        state.pixel = board;
        state.android_mut().hardening.hw_mte_supported = soc.supports_hw_mte();
        let _ = state
            .android_mut()
            .set_property("ro.product.model", soc.model_name(), true);
    });
}

pub(super) const fn is_android_fd(raw_fd: u64) -> bool {
    let fd = linux_signed_int(raw_fd);
    fd >= ANDROID_FD_BASE && fd < ANDROID_FD_BASE + (MAX_ANDROID_FDS as i32)
}

pub(super) fn is_open_android_fd(process: ObjectId, raw_fd: u64) -> bool {
    if !is_android_fd(raw_fd) {
        return false;
    }
    let idx = (linux_signed_int(raw_fd) - ANDROID_FD_BASE) as usize;
    with_step45_state(|state| resolve_slot(state, process, idx, None).is_some()).unwrap_or(false)
}

fn is_android_fd_or_alias(raw_fd: u64) -> bool {
    is_android_fd(raw_fd)
        || lookup_aliased_subsystem_current(raw_fd).is_some_and(|h| h.kind == SUBSYS_ANDROID)
}

fn resolve_slot_idx(process: ObjectId, raw_fd: u64) -> Result<(usize, Option<u64>), Errno> {
    if is_android_fd(raw_fd) {
        return Ok(((linux_signed_int(raw_fd) - ANDROID_FD_BASE) as usize, None));
    }
    if let Some(handle) = lookup_aliased_subsystem(process, raw_fd)
        && handle.kind == SUBSYS_ANDROID
    {
        return Ok((handle.slot as usize, Some(handle.generation)));
    }
    Err(Errno::EBADF)
}

fn resolve_slot<'a>(
    state: &'a Step45State,
    process: ObjectId,
    slot_idx: usize,
    alias_gen: Option<u64>,
) -> Option<&'a AndroidFdSlot> {
    let entry = state.fds.get(slot_idx)?;
    if !entry.live {
        return None;
    }
    match alias_gen {
        Some(expected_gen) if entry.generation == expected_gen && entry.alias_refs > 0 => {
            Some(entry)
        }
        Some(_) => None,
        None if entry.owners.has_owner(process) => Some(entry),
        None => None,
    }
}

fn resolve_slot_mut<'a>(
    state: &'a mut Step45State,
    process: ObjectId,
    slot_idx: usize,
    alias_gen: Option<u64>,
) -> Option<&'a mut AndroidFdSlot> {
    let entry = state.fds.get_mut(slot_idx)?;
    if !entry.live {
        return None;
    }
    match alias_gen {
        Some(expected_gen) if entry.generation == expected_gen && entry.alias_refs > 0 => {
            Some(entry)
        }
        Some(_) => None,
        None if entry.owners.has_owner(process) => Some(entry),
        None => None,
    }
}

fn retire_slot_if_unused(state: &mut Step45State, slot_idx: usize) {
    let Some(entry) = state.fds.get(slot_idx).copied() else {
        return;
    };
    if !entry.live || !entry.owners.is_empty() || entry.alias_refs > 0 {
        return;
    }
    match entry.kind {
        AndroidNodeKind::Binder(domain) if entry.binder_endpoint_id != 0 => {
            state
                .android_mut()
                .broker_mut(domain)
                .close_endpoint(entry.binder_endpoint_id);
        }
        AndroidNodeKind::Ashmem | AndroidNodeKind::DmaHeapSystem if entry.ashmem_region_id != 0 => {
            state.android_mut().destroy_ashmem(entry.ashmem_region_id);
        }
        _ => {}
    }
    state.fds[slot_idx] = AndroidFdSlot::EMPTY;
}

pub(super) fn retain_alias_handle(
    process: ObjectId,
    raw_fd: u64,
) -> Result<(SubsystemHandle, u64), Errno> {
    if !is_android_fd(raw_fd) {
        return Err(Errno::EBADF);
    }
    let idx = (linux_signed_int(raw_fd) - ANDROID_FD_BASE) as usize;
    retain_slot(idx, Some(process), None)
}

pub(super) fn retain_existing_handle(
    handle: SubsystemHandle,
) -> Result<(SubsystemHandle, u64), Errno> {
    if handle.kind != SUBSYS_ANDROID {
        return Err(Errno::EBADF);
    }
    retain_slot(handle.slot as usize, None, Some(handle.generation))
}

fn retain_slot(
    slot_idx: usize,
    owner: Option<ObjectId>,
    expected_gen: Option<u64>,
) -> Result<(SubsystemHandle, u64), Errno> {
    with_step45_state(|state| {
        let Some(entry) = state.fds.get_mut(slot_idx) else {
            return Err(Errno::EBADF);
        };
        let valid = entry.live
            && owner.map_or(true, |p| entry.owners.has_owner(p))
            && expected_gen.map_or(true, |g| entry.generation == g);
        if !valid {
            return Err(Errno::EBADF);
        }
        entry.alias_refs += 1;
        Ok((
            SubsystemHandle {
                kind: SUBSYS_ANDROID,
                slot: slot_idx as u16,
                generation: entry.generation,
            },
            entry.status_flags,
        ))
    })
    .map_err(|()| Errno::EIO)?
}

pub(super) fn release_alias_handle(handle: SubsystemHandle) {
    if handle.kind != SUBSYS_ANDROID {
        return;
    }
    let idx = handle.slot as usize;
    let _ = with_step45_state(|state| {
        if let Some(entry) = state.fds.get_mut(idx)
            && entry.live
            && entry.generation == handle.generation
            && entry.alias_refs > 0
        {
            entry.alias_refs -= 1;
            retire_slot_if_unused(state, idx);
        }
    });
}

pub(super) fn handle_native_fcntl(
    process: ObjectId,
    raw_fd: u64,
    cmd: u32,
    argi: i32,
) -> Option<Result<i64, Errno>> {
    let Ok((idx, alias_gen)) = resolve_slot_idx(process, raw_fd) else {
        return None;
    };
    if alias_gen.is_some() && !matches!(cmd, 3 | 4) {
        return None;
    }
    let res = with_step45_state(|state| {
        let Some(entry) = resolve_slot_mut(state, process, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        match cmd {
            1 => Ok(i64::from(i32::from(
                entry.owners.get_cloexec(process).unwrap_or(false),
            ))),
            2 => {
                let _ = entry.owners.set_cloexec(process, (argi & 1) != 0);
                Ok(0)
            }
            3 => Ok(entry.status_flags as i64),
            4 => {
                let acc = entry.status_flags & 0o3;
                entry.status_flags = acc | ((argi as u64) & O_NONBLOCK_U64);
                Ok(0)
            }
            _ => Err(Errno::EINVAL),
        }
    });
    Some(res.unwrap_or(Err(Errno::EIO)))
}

pub(super) fn append_open_android_fds(process: ObjectId, out: &mut Vec<i32>) {
    let _ = with_step45_state(|state| {
        for (idx, entry) in state.fds.iter().enumerate() {
            if entry.live && entry.owners.has_owner(process) {
                out.push(ANDROID_FD_BASE + (idx as i32));
            }
        }
    });
}

pub(super) fn describe_android_slot(
    slot: u16,
    generation: Option<u64>,
    process: Option<ObjectId>,
    out: &mut [u8],
) -> Option<usize> {
    let mut written = None;
    let _ = with_step45_state(|state| {
        let Some(entry) = state.fds.get(usize::from(slot)) else {
            return;
        };
        if !entry.live {
            return;
        }
        if let Some(expected_gen) = generation {
            if entry.generation != expected_gen || entry.alias_refs == 0 {
                return;
            }
        } else if let Some(owner) = process
            && !entry.owners.has_owner(owner)
        {
            return;
        }
        let path = entry.kind.path_bytes();
        let take = path.len().min(out.len());
        out[..take].copy_from_slice(&path[..take]);
        written = Some(take);
    });
    written
}

pub(super) fn on_process_fork(parent: ObjectId, child: ObjectId) {
    let _ = with_step45_state(|state| {
        for entry in &mut state.fds {
            if entry.live {
                entry.owners.on_fork(parent, child);
            }
        }
    });
}

pub(super) fn on_process_exec(process: ObjectId) {
    let _ = with_step45_state(|state| {
        for idx in 0..MAX_ANDROID_FDS {
            if state.fds[idx].live {
                state.fds[idx].owners.close_cloexec_for(process);
                retire_slot_if_unused(state, idx);
            }
        }
    });
}

pub(super) fn on_process_exit(process: ObjectId) {
    let _ = with_step45_state(|state| {
        for idx in 0..MAX_ANDROID_FDS {
            if state.fds[idx].live {
                let _ = state.fds[idx].owners.close_owner(process);
                retire_slot_if_unused(state, idx);
            }
        }
    });
}

pub(super) fn close_range_for_process(
    process: ObjectId,
    first: u32,
    last: u32,
    cloexec_only: bool,
) {
    let _ = with_step45_state(|state| {
        for idx in 0..MAX_ANDROID_FDS {
            let fd = ANDROID_FD_BASE + (idx as i32);
            if fd_in_close_range(fd, first, last)
                && state.fds[idx].live
                && state.fds[idx]
                    .owners
                    .apply_close_range(process, cloexec_only)
            {
                retire_slot_if_unused(state, idx);
            }
        }
    });
}

/// Polls readiness for `/dev/binder` (`POLLIN` when work queued) and other Android FDs.
pub(super) fn probe_android_fd_readiness(
    process: ObjectId,
    raw_fd: u64,
) -> Option<Result<u32, Errno>> {
    let Ok((idx, alias_gen)) = resolve_slot_idx(process, raw_fd) else {
        return None;
    };
    let res = with_step45_state(|state| {
        let Some(entry) = resolve_slot(state, process, idx, alias_gen).copied() else {
            return Err(Errno::EBADF);
        };
        match entry.kind {
            AndroidNodeKind::Binder(domain) => {
                let mut mask = u32::from(POLLOUT);
                if state
                    .android()
                    .broker(domain)
                    .has_pending_work(entry.binder_endpoint_id)
                {
                    mask |= u32::from(POLLIN);
                }
                Ok(mask)
            }
            _ => Ok(u32::from(POLLIN | POLLOUT)),
        }
    })
    .unwrap_or(Err(Errno::EIO));
    Some(res)
}

/// Descriptor returned by [`try_prepare_android_mmap`] for `/dev/binder` or `/dev/ashmem`.
#[derive(Clone, Copy, Debug)]
pub(super) enum AndroidMmapKind {
    Binder {
        domain: BinderDomain,
        endpoint_id: u32,
    },
    Ashmem {
        region_id: u32,
    },
}

pub(super) fn try_prepare_android_mmap(
    raw_fd: u64,
    length: usize,
) -> Result<Option<AndroidMmapKind>, Errno> {
    let process = current_process_object().ok_or(Errno::EIO)?;
    let Ok((idx, alias_gen)) = resolve_slot_idx(process, raw_fd) else {
        return Ok(None);
    };
    with_step45_state(|state| {
        let Some(entry) = resolve_slot(state, process, idx, alias_gen).copied() else {
            return Err(Errno::EBADF);
        };
        match entry.kind {
            AndroidNodeKind::Binder(domain) => Ok(Some(AndroidMmapKind::Binder {
                domain,
                endpoint_id: entry.binder_endpoint_id,
            })),
            AndroidNodeKind::Ashmem | AndroidNodeKind::DmaHeapSystem => {
                let reg = state
                    .android_mut()
                    .ashmem_mut(entry.ashmem_region_id)
                    .ok_or(Errno::EBADF)?;
                if reg.size == 0 && length > 0 {
                    reg.set_size(length)?;
                }
                reg.ensure_allocated()?;
                Ok(Some(AndroidMmapKind::Ashmem {
                    region_id: entry.ashmem_region_id,
                }))
            }
            _ => Err(Errno::ENODEV),
        }
    })
    .map_err(|()| Errno::EIO)?
}

pub(super) fn register_binder_mmap(
    domain: BinderDomain,
    endpoint_id: u32,
    mapped_va: u64,
    length: usize,
) {
    let _ = with_step45_state(|state| {
        let _ =
            state
                .android_mut()
                .broker_mut(domain)
                .register_mmap(endpoint_id, mapped_va, length);
    });
}

pub(super) fn read_ashmem_snapshot(region_id: u32, offset: usize, max_len: usize) -> Vec<u8> {
    with_step45_state(|state| {
        let Some(reg) = state.android().ashmem(region_id) else {
            return Vec::new();
        };
        if offset >= reg.data.len() {
            return Vec::new();
        }
        let end = offset.saturating_add(max_len).min(reg.data.len());
        reg.data[offset..end].to_vec()
    })
    .unwrap_or_default()
}

pub(super) fn write_back_ashmem_mmap(region_id: u32, offset: u64, data: &[u8]) {
    let off = offset as usize;
    let _ = with_step45_state(|state| {
        if let Some(reg) = state.android_mut().ashmem_mut(region_id) {
            let _ = reg.ensure_allocated();
            if off < reg.data.len() {
                let take = data.len().min(reg.data.len() - off);
                reg.data[off..off + take].copy_from_slice(&data[..take]);
            }
        }
    });
}

fn match_android_path(path: &[u8]) -> Option<AndroidNodeKind> {
    match path {
        b"/dev/binder" | b"/dev/binderfs/binder" => {
            Some(AndroidNodeKind::Binder(BinderDomain::Framework))
        }
        b"/dev/hwbinder" | b"/dev/binderfs/hwbinder" => {
            Some(AndroidNodeKind::Binder(BinderDomain::HardwareHal))
        }
        b"/dev/vndbinder" | b"/dev/binderfs/vndbinder" => {
            Some(AndroidNodeKind::Binder(BinderDomain::Vendor))
        }
        b"/dev/ashmem" => Some(AndroidNodeKind::Ashmem),
        b"/dev/dma_heap/system" => Some(AndroidNodeKind::DmaHeapSystem),
        b"/dev/pmsg0" | b"/dev/log/main" | b"/dev/log/system" => {
            Some(AndroidNodeKind::AndroidLogMain)
        }
        b"/sys/fs/selinux/enforce" => Some(AndroidNodeKind::SelinuxEnforce),
        b"/sys/fs/selinux/mls" => Some(AndroidNodeKind::SelinuxMls),
        b"/sys/fs/selinux/policyvers" => Some(AndroidNodeKind::SelinuxPolicyvers),
        b"/sys/fs/selinux/status" => Some(AndroidNodeKind::SelinuxStatus),
        b"/sys/power/wake_lock" => Some(AndroidNodeKind::PowerWakeLock),
        b"/sys/power/wake_unlock" => Some(AndroidNodeKind::PowerWakeUnlock),
        b"/sys/power/state" => Some(AndroidNodeKind::PowerState),
        b"/proc/pressure/memory" => Some(AndroidNodeKind::PsiMemory),
        b"/proc/pressure/cpu" => Some(AndroidNodeKind::PsiCpu),
        b"/proc/pressure/io" => Some(AndroidNodeKind::PsiIo),
        b"/sys/kernel/qyronex/android/properties" => Some(AndroidNodeKind::QyronexProperties),
        b"/sys/kernel/qyronex/android/binder_stats" => Some(AndroidNodeKind::QyronexBinderStats),
        b"/sys/kernel/qyronex/grapheneos/status" => Some(AndroidNodeKind::GrapheneOsStatus),
        b"/sys/bus/platform/drivers/google_pixel/status" => {
            Some(AndroidNodeKind::GooglePixelStatus)
        }
        _ => None,
    }
}

fn current_linux_pid() -> i32 {
    let cpu = super::super::current_cpu_index();
    let Some(sched) = super::super::CPU_SCHEDULERS.get(cpu) else {
        return 1;
    };
    // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
    let Ok(cur) = (unsafe { sched.bootstrap_current_global_thread() }) else {
        return 1;
    };
    super::runtime::with_linux_runtime(|rt| {
        rt.with_current_process_identity(cur, |process, ids| ids.bound_pid(process))
    })
    .ok()
    .and_then(|r| r.ok())
    .and_then(|r| r.ok())
    .map_or(1, |pid| pid.get() as i32)
}

fn render_node_bytes(state: &Step45State, kind: AndroidNodeKind) -> Vec<u8> {
    let a = state.android();
    match kind {
        AndroidNodeKind::SelinuxEnforce => {
            if a.hardening.selinux_enforcing {
                b"1".to_vec()
            } else {
                b"0".to_vec()
            }
        }
        AndroidNodeKind::SelinuxMls => b"1".to_vec(),
        AndroidNodeKind::SelinuxPolicyvers => {
            format!("{}", a.hardening.selinux_policy_version).into_bytes()
        }
        AndroidNodeKind::SelinuxStatus => {
            // Linux `struct selinux_status_t`: version=1, sequence=0, enforcing=1, policyload=1
            let mut buf = [0u8; 16];
            buf[0..4].copy_from_slice(&1u32.to_le_bytes());
            buf[4..8].copy_from_slice(&0u32.to_le_bytes());
            buf[8..12]
                .copy_from_slice(&(u32::from(a.hardening.selinux_enforcing)).to_le_bytes());
            buf[12..16].copy_from_slice(&1u32.to_le_bytes());
            buf.to_vec()
        }
        AndroidNodeKind::PowerWakeLock => {
            let mut s = String::new();
            for (i, w) in a.wakelocks.iter().enumerate() {
                if i > 0 {
                    s.push(' ');
                }
                s.push_str(w);
            }
            s.push('\n');
            s.into_bytes()
        }
        AndroidNodeKind::PowerWakeUnlock => b"\n".to_vec(),
        AndroidNodeKind::PowerState => b"freeze mem\n".to_vec(),
        AndroidNodeKind::PsiMemory => {
            b"some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n".to_vec()
        }
        AndroidNodeKind::PsiCpu => b"some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n".to_vec(),
        AndroidNodeKind::PsiIo => {
            b"some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n".to_vec()
        }
        AndroidNodeKind::AndroidLogMain => state.log_ring.clone(),
        AndroidNodeKind::QyronexProperties => {
            let mut s = String::new();
            for p in &a.properties {
                s.push_str(&p.key);
                s.push('=');
                s.push_str(&p.value);
                s.push('\n');
            }
            s.into_bytes()
        }
        AndroidNodeKind::QyronexBinderStats => {
            let st = a.binder_audit_stats();
            format!(
                "protocol_version={}\ncontext_managers={}\nactive_endpoints={}\ntotal_transactions={}\ntotal_replies={}\ncapability_denials={}\n",
                BINDER_CURRENT_PROTOCOL_VERSION,
                st.context_managers_bound,
                st.active_endpoints,
                st.total_transactions,
                st.total_replies,
                st.capability_denials
            )
            .into_bytes()
        }
        AndroidNodeKind::GrapheneOsStatus => {
            let h = a.hardening;
            format!(
                "profile=GrapheneOS-Qyronex-Hardened\nselinux={}\nwx_ttbr1_isolated={}\ncapability_binder={}\nzero_on_free={}\nexec_spawning={}\nptrace_scope={}\nunprivileged_userns={}\nkptr_restrict={}\ndmesg_restrict={}\nhw_pan={}\nhw_mte={}\navb_verified_boot={}\n",
                if h.selinux_enforcing { "enforcing" } else { "permissive" },
                if h.wx_ttbr1_isolated { "active" } else { "off" },
                if h.capability_binder_enforced { "enforced" } else { "off" },
                u8::from(h.zero_on_free_allocator),
                u8::from(h.exec_spawning_enabled),
                h.ptrace_scope,
                u8::from(h.unprivileged_userns_clone),
                h.kptr_restrict,
                u8::from(h.dmesg_restrict),
                if h.hw_pan_active { "active" } else { "armv8.0-ttbr0" },
                if h.hw_mte_supported { "enabled" } else { "emulated" },
                if h.avb_verified_boot_green { "green" } else { "orange" }
            )
            .into_bytes()
        }
        AndroidNodeKind::GooglePixelStatus => {
            let p = &state.pixel;
            format!(
                "model={}\ncores={}\ntitan_m2={}\nkeymint_version={}\nweaver_slots={}\nufs_slot=_{}\ndisplay={}x{}@{}Hz\nmodem_iommu_sandbox={}\nhw_mte={}\n",
                p.soc.model_name(),
                p.soc.cpu_cores(),
                if p.titan_m2.online { "online-strongbox" } else { "offline" },
                p.titan_m2.strongbox_keymint_version,
                p.titan_m2.weaver_slots,
                p.ufs.active_slot as char,
                p.display.width,
                p.display.height,
                p.display.refresh_hz,
                if p.modem_ipc.iommu_sandboxed { "enforced" } else { "off" },
                u8::from(p.hw_mte_enabled)
            )
            .into_bytes()
        }
        _ => Vec::new(),
    }
}

pub(super) fn try_handle_syscall(
    request: SyscallRequest,
    frame: &mut ExceptionFrame,
) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        29 if is_android_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_ioctl(
            request.args[0],
            request.args[1],
            request.args[2],
            frame,
        )?))),
        48 => handle_faccessat_if_android(request.args[1]),
        56 => handle_openat_if_android(request.args[1], request.args[2]),
        57 if is_android_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_close(request.args[0])?)))
        }
        62 if is_android_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_lseek(
            request.args[0],
            request.args[1] as i64,
            request.args[2] as i32,
        )?))),
        63 if is_android_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_read(
            request.args[0],
            request.args[1],
            request.args[2] as usize,
            None,
        )?))),
        64 if is_android_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_write(
            request.args[0],
            request.args[1],
            request.args[2] as usize,
            None,
        )?))),
        65 if is_android_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_readv(
            request.args[0],
            request.args[1],
            request.args[2] as usize,
        )?))),
        66 if is_android_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_writev(
            request.args[0],
            request.args[1],
            request.args[2] as usize,
        )?))),
        67 if is_android_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_read(
            request.args[0],
            request.args[1],
            request.args[2] as usize,
            Some(request.args[3] as usize),
        )?))),
        68 if is_android_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_write(
            request.args[0],
            request.args[1],
            request.args[2] as usize,
            Some(request.args[3] as usize),
        )?))),
        79 => handle_newfstatat_if_android(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        80 if is_android_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_fstat(
            request.args[0],
            request.args[1],
        )?))),
        291 => handle_statx_if_android(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[4],
        ),
        _ => Ok(None),
    }
}

fn handle_faccessat_if_android(path_ptr: u64) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; 256];
    let Ok(path_len) = read_user_cstr(path_ptr, &mut path_buf) else {
        return Ok(None);
    };
    if match_android_path(&path_buf[..path_len]).is_some() {
        return Ok(Some(encode_result(Ok(0))));
    }
    Ok(None)
}

fn handle_openat_if_android(path_ptr: u64, flags: u64) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; 256];
    let Ok(path_len) = read_user_cstr(path_ptr, &mut path_buf) else {
        return Ok(None);
    };
    let Some(kind) = match_android_path(&path_buf[..path_len]) else {
        return Ok(None);
    };
    if (flags & O_DIRECTORY_U64) != 0 {
        return Ok(Some(encode_result(Err(Errno::ENOTDIR))));
    }
    let Some(process) = current_process_object() else {
        return Err(());
    };
    let pid = current_linux_pid();
    let (uid, _) = current_uid_gid();
    let cloexec = (flags & O_CLOEXEC_U64) != 0;
    let res = with_step45_state(|state| {
        let Some(idx) = state.fds.iter().position(|slot| !slot.live) else {
            return Err(Errno::EMFILE);
        };
        let mut binder_endpoint_id = 0u32;
        let mut ashmem_region_id = 0u32;
        match kind {
            AndroidNodeKind::Binder(domain) => {
                // Qyronex Capability binding: root/system gets CONTROL+READ+WRITE; apps get READ+WRITE.
                let rights = if uid == 0 || uid == 1000 {
                    CapRights::READ
                        .union(CapRights::WRITE)
                        .union(CapRights::CONTROL)
                } else {
                    CapRights::READ.union(CapRights::WRITE)
                };
                let cap = Capability {
                    object: process,
                    rights,
                };
                binder_endpoint_id = state
                    .android_mut()
                    .broker_mut(domain)
                    .open_endpoint(process, pid, uid, cap)?;
            }
            AndroidNodeKind::Ashmem | AndroidNodeKind::DmaHeapSystem => {
                ashmem_region_id = state.android_mut().create_ashmem()?;
            }
            _ => {}
        }
        let fd_gen = state.next_fd_generation;
        state.next_fd_generation = state.next_fd_generation.wrapping_add(1).max(1);
        let mut owners = DirectProcessRefs::empty();
        owners.init(process, cloexec);
        state.fds[idx] = AndroidFdSlot {
            live: true,
            kind,
            generation: fd_gen,
            owners,
            alias_refs: 0,
            offset: 0,
            status_flags: flags & (0o3 | O_NONBLOCK_U64),
            binder_endpoint_id,
            ashmem_region_id,
        };
        Ok(i64::from(ANDROID_FD_BASE + (idx as i32)))
    })?;
    Ok(Some(encode_result(res)))
}

fn handle_close(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    let Some(process) = current_process_object() else {
        return Err(());
    };
    let idx = (linux_signed_int(raw_fd) - ANDROID_FD_BASE) as usize;
    with_step45_state(|state| {
        let Some(entry) = state.fds.get_mut(idx) else {
            return Err(Errno::EBADF);
        };
        if !entry.live || !entry.owners.close_owner(process) {
            return Err(Errno::EBADF);
        }
        retire_slot_if_unused(state, idx);
        Ok(0)
    })
}

fn handle_lseek(raw_fd: u64, offset: i64, whence: i32) -> Result<Result<i64, Errno>, ()> {
    let Some(process) = current_process_object() else {
        return Err(());
    };
    let Ok((idx, alias_gen)) = resolve_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    with_step45_state(|state| {
        let Some(entry) = resolve_slot(state, process, idx, alias_gen).copied() else {
            return Err(Errno::EBADF);
        };
        let total = match entry.kind {
            AndroidNodeKind::Ashmem | AndroidNodeKind::DmaHeapSystem => state
                .android()
                .ashmem(entry.ashmem_region_id)
                .map_or(0, |r| r.size),
            _ => render_node_bytes(state, entry.kind).len(),
        };
        let next = seek_bounded(entry.offset, total, offset, whence)?;
        if let Some(slot) = resolve_slot_mut(state, process, idx, alias_gen) {
            slot.offset = next;
        }
        Ok(next as i64)
    })
}

fn handle_read(
    raw_fd: u64,
    user_buf: u64,
    count: usize,
    explicit_offset: Option<usize>,
) -> Result<Result<i64, Errno>, ()> {
    let Some(process) = current_process_object() else {
        return Err(());
    };
    let Ok((idx, alias_gen)) = resolve_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let slice_result: Result<Vec<u8>, Errno> = with_step45_state(|state| {
        let Some(entry) = resolve_slot(state, process, idx, alias_gen).copied() else {
            return Err(Errno::EBADF);
        };
        let pos = explicit_offset.unwrap_or(entry.offset);
        let data = match entry.kind {
            AndroidNodeKind::Ashmem | AndroidNodeKind::DmaHeapSystem => {
                let reg = state
                    .android_mut()
                    .ashmem_mut(entry.ashmem_region_id)
                    .ok_or(Errno::EBADF)?;
                reg.ensure_allocated()?;
                reg.data.clone()
            }
            AndroidNodeKind::Binder(_) => return Err(Errno::EINVAL),
            other => render_node_bytes(state, other),
        };
        if pos >= data.len() || count == 0 {
            return Ok(Vec::new());
        }
        let take = count.min(data.len() - pos);
        let out = data[pos..pos + take].to_vec();
        if explicit_offset.is_none()
            && let Some(slot) = resolve_slot_mut(state, process, idx, alias_gen)
        {
            slot.offset = pos + take;
        }
        Ok(out)
    })?;
    let bytes = match slice_result {
        Ok(b) => b,
        Err(e) => return Ok(Err(e)),
    };
    if !bytes.is_empty()
        && let Err(e) = copy_to_user(user_buf, &bytes)
    {
        return Ok(Err(e));
    }
    Ok(Ok(bytes.len() as i64))
}

fn handle_write(
    raw_fd: u64,
    user_buf: u64,
    count: usize,
    explicit_offset: Option<usize>,
) -> Result<Result<i64, Errno>, ()> {
    let Some(process) = current_process_object() else {
        return Err(());
    };
    let Ok((idx, alias_gen)) = resolve_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let take = count.min(4096);
    let mut kbuf = vec![0u8; take];
    if take > 0
        && let Err(e) = copy_from_user(&mut kbuf, user_buf)
    {
        return Ok(Err(e));
    }
    with_step45_state(|state| {
        let Some(entry) = resolve_slot(state, process, idx, alias_gen).copied() else {
            return Err(Errno::EBADF);
        };
        match entry.kind {
            AndroidNodeKind::SelinuxEnforce => {
                // GrapheneOS kernel lockdown: enforcing mode cannot be downgraded to permissive.
                let text = core::str::from_utf8(&kbuf).unwrap_or("").trim();
                if text == "1" {
                    Ok(take as i64)
                } else {
                    Err(Errno::EPERM)
                }
            }
            AndroidNodeKind::PowerWakeLock => {
                let name = core::str::from_utf8(&kbuf).map_err(|_| Errno::EINVAL)?;
                state.android_mut().acquire_wakelock(name)?;
                Ok(take as i64)
            }
            AndroidNodeKind::PowerWakeUnlock => {
                let name = core::str::from_utf8(&kbuf).map_err(|_| Errno::EINVAL)?;
                state.android_mut().release_wakelock(name)?;
                Ok(take as i64)
            }
            AndroidNodeKind::AndroidLogMain => {
                state.append_log(&kbuf);
                Ok(take as i64)
            }
            AndroidNodeKind::QyronexProperties => {
                let text = core::str::from_utf8(&kbuf).map_err(|_| Errno::EINVAL)?;
                for line in text.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let Some((k, v)) = trimmed.split_once('=') else {
                        return Err(Errno::EINVAL);
                    };
                    state
                        .android_mut()
                        .set_property(k.trim(), v.trim(), false)?;
                }
                Ok(take as i64)
            }
            AndroidNodeKind::Ashmem | AndroidNodeKind::DmaHeapSystem => {
                let pos = explicit_offset.unwrap_or(entry.offset);
                let reg = state
                    .android_mut()
                    .ashmem_mut(entry.ashmem_region_id)
                    .ok_or(Errno::EBADF)?;
                if reg.size == 0 && pos + take > 0 {
                    reg.set_size((pos + take).next_power_of_two().max(4096))?;
                }
                reg.ensure_allocated()?;
                if pos >= reg.data.len() {
                    return Err(Errno::ENOSPC);
                }
                let wr = take.min(reg.data.len() - pos);
                reg.data[pos..pos + wr].copy_from_slice(&kbuf[..wr]);
                if explicit_offset.is_none()
                    && let Some(slot) = resolve_slot_mut(state, process, idx, alias_gen)
                {
                    slot.offset = pos + wr;
                }
                Ok(wr as i64)
            }
            _ => Err(Errno::EACCES),
        }
    })
}

fn handle_readv(raw_fd: u64, iov_ptr: u64, iovcnt: usize) -> Result<Result<i64, Errno>, ()> {
    let mut total = 0i64;
    for i in 0..iovcnt.min(16) {
        let Ok((base, len)) = read_user_iovec(iov_ptr, i) else {
            return Ok(Err(Errno::EFAULT));
        };
        if len == 0 {
            continue;
        }
        match handle_read(raw_fd, base, len, None)? {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if (n as usize) < len {
                    break;
                }
            }
            Err(e) => return Ok(if total > 0 { Ok(total) } else { Err(e) }),
        }
    }
    Ok(Ok(total))
}

fn handle_writev(raw_fd: u64, iov_ptr: u64, iovcnt: usize) -> Result<Result<i64, Errno>, ()> {
    let mut total = 0i64;
    for i in 0..iovcnt.min(16) {
        let Ok((base, len)) = read_user_iovec(iov_ptr, i) else {
            return Ok(Err(Errno::EFAULT));
        };
        if len == 0 {
            continue;
        }
        match handle_write(raw_fd, base, len, None)? {
            Ok(n) => total += n,
            Err(e) => return Ok(if total > 0 { Ok(total) } else { Err(e) }),
        }
    }
    Ok(Ok(total))
}

fn handle_ioctl(
    raw_fd: u64,
    cmd: u64,
    arg: u64,
    frame: &mut ExceptionFrame,
) -> Result<Result<i64, Errno>, ()> {
    let Some(process) = current_process_object() else {
        return Err(());
    };
    let Ok((idx, alias_gen)) = resolve_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let entry = match with_step45_state(|state| {
        resolve_slot(state, process, idx, alias_gen)
            .copied()
            .ok_or(Errno::EBADF)
    })? {
        Ok(e) => e,
        Err(e) => return Ok(Err(e)),
    };

    match entry.kind {
        AndroidNodeKind::Binder(domain) => handle_binder_ioctl(domain, entry, cmd, arg, frame),
        AndroidNodeKind::Ashmem | AndroidNodeKind::DmaHeapSystem => {
            handle_ashmem_ioctl(entry.ashmem_region_id, cmd, arg)
        }
        _ => Ok(Err(Errno::ENOTTY)),
    }
}

fn handle_binder_ioctl(
    domain: BinderDomain,
    entry: AndroidFdSlot,
    cmd: u64,
    arg: u64,
    frame: &mut ExceptionFrame,
) -> Result<Result<i64, Errno>, ()> {
    let ep_id = entry.binder_endpoint_id;
    let nonblocking = (entry.status_flags & O_NONBLOCK_U64) != 0;
    let cmd32 = cmd & 0xFFFF_FFFF;

    match cmd32 {
        BINDER_VERSION => {
            let ver = BINDER_CURRENT_PROTOCOL_VERSION.to_le_bytes();
            if let Err(e) = copy_to_user(arg, &ver) {
                return Ok(Err(e));
            }
            Ok(Ok(0))
        }
        BINDER_SET_MAX_THREADS => {
            let mut raw = [0u8; 4];
            if let Err(e) = copy_from_user(&mut raw, arg) {
                return Ok(Err(e));
            }
            let max_threads = u32::from_le_bytes(raw);
            with_step45_state(|state| {
                state
                    .android_mut()
                    .broker_mut(domain)
                    .set_max_threads(ep_id, max_threads)?;
                Ok(0)
            })
        }
        BINDER_SET_CONTEXT_MGR | BINDER_SET_CONTEXT_MGR_EXT => with_step45_state(|state| {
            state
                .android_mut()
                .broker_mut(domain)
                .set_context_manager(ep_id)?;
            Ok(0)
        }),
        BINDER_SET_IDLE_TIMEOUT | BINDER_SET_IDLE_PRIORITY | BINDER_THREAD_EXIT => Ok(Ok(0)),
        BINDER_WRITE_READ => handle_binder_write_read(domain, ep_id, nonblocking, arg, frame),
        _ => Ok(Err(Errno::ENOTTY)),
    }
}

fn handle_binder_write_read(
    domain: BinderDomain,
    ep_id: u32,
    nonblocking: bool,
    bwr_user_ptr: u64,
    frame: &mut ExceptionFrame,
) -> Result<Result<i64, Errno>, ()> {
    let mut bwr_raw = [0u8; BINDER_WRITE_READ_BYTES];
    if let Err(e) = copy_from_user(&mut bwr_raw, bwr_user_ptr) {
        return Ok(Err(e));
    }
    let mut bwr = BinderWriteRead::from_le_bytes(&bwr_raw);

    // Phase 1: Process Binder write buffer commands (`BC_*`).
    if bwr.write_size > bwr.write_consumed {
        let wlen = (bwr.write_size - bwr.write_consumed).min(4096) as usize;
        let mut wbuf = vec![0u8; wlen];
        if let Err(e) = copy_from_user(&mut wbuf, bwr.write_buffer.wrapping_add(bwr.write_consumed))
        {
            return Ok(Err(e));
        }
        let mut off = 0usize;
        while off + 4 <= wbuf.len() {
            let bc = u32::from_le_bytes([wbuf[off], wbuf[off + 1], wbuf[off + 2], wbuf[off + 3]]);
            off += 4;
            match bc {
                BC_ENTER_LOOPER | BC_REGISTER_LOOPER => {
                    let _ = with_step45_state(|s| {
                        s.android_mut().broker_mut(domain).enter_looper(ep_id)
                    });
                }
                BC_EXIT_LOOPER => {}
                BC_INCREFS | BC_ACQUIRE | BC_RELEASE | BC_DECREFS => {
                    if off + 4 > wbuf.len() {
                        break;
                    }
                    off += 4;
                }
                BC_FREE_BUFFER | BC_DEAD_BINDER_DONE => {
                    if off + 8 > wbuf.len() {
                        break;
                    }
                    off += 8;
                }
                BC_REQUEST_DEATH_NOTIFICATION => {
                    if off + 12 > wbuf.len() {
                        break;
                    }
                    off += 12;
                }
                BC_TRANSACTION | BC_REPLY => {
                    if off + BINDER_TRANSACTION_DATA_BYTES > wbuf.len() {
                        return Ok(Err(Errno::EINVAL));
                    }
                    let mut tx_raw = [0u8; BINDER_TRANSACTION_DATA_BYTES];
                    tx_raw.copy_from_slice(&wbuf[off..off + BINDER_TRANSACTION_DATA_BYTES]);
                    off += BINDER_TRANSACTION_DATA_BYTES;
                    let tx = BinderTransactionData::from_le_bytes(&tx_raw);
                    let data_len = (tx.data_size as usize).min(MAX_BINDER_PAYLOAD_BYTES);
                    let mut payload = vec![0u8; data_len];
                    if data_len > 0
                        && let Err(e) = copy_from_user(&mut payload, tx.data_ptr)
                    {
                        return Ok(Err(e));
                    }
                    let dispatch_res = with_step45_state(|state| {
                        let broker = state.android_mut().broker_mut(domain);
                        if bc == BC_TRANSACTION {
                            broker.dispatch_transaction(ep_id, tx, payload)
                        } else {
                            broker.dispatch_reply(ep_id, tx, payload)
                        }
                    })?;
                    if let Err(e) = dispatch_res {
                        return Ok(Err(e));
                    }
                }
                _ => return Ok(Err(Errno::EINVAL)),
            }
        }
        bwr.write_consumed = bwr.write_consumed.saturating_add(off as u64);
    }

    // Phase 2: Deliver pending `BR_*` return commands into read buffer (with cooperative yield).
    if bwr.read_size > bwr.read_consumed {
        // If nothing is queued yet, wait cooperatively for another process (e.g. servicemanager or
        // client) to deliver work into our queue.
        for _ in 0..400u32 {
            let has_work =
                with_step45_state(|state| state.android().broker(domain).has_pending_work(ep_id))
                    .unwrap_or(false);
            if has_work || nonblocking {
                break;
            }
            let _ = super::step30_runtime::yield_and_rebind_frame(Some(frame));
        }

        let mut rbuf = Vec::<u8>::new();
        let max_read = (bwr.read_size - bwr.read_consumed) as usize;
        // Always prefix with BR_NOOP if space allows (standard Linux Binder convention).
        if rbuf.len() + 4 <= max_read {
            rbuf.extend_from_slice(&BR_NOOP.to_le_bytes());
        }

        loop {
            let next_work =
                with_step45_state(|state| state.android_mut().broker_mut(domain).pop_work(ep_id))
                    .ok()
                    .flatten();
            let Some(work) = next_work else {
                break;
            };
            match work.return_cmd {
                BR_TRANSACTION_COMPLETE => {
                    if rbuf.len() + 4 <= max_read {
                        rbuf.extend_from_slice(&BR_TRANSACTION_COMPLETE.to_le_bytes());
                    }
                }
                BR_TRANSACTION | BR_REPLY => {
                    if rbuf.len() + 4 + BINDER_TRANSACTION_DATA_BYTES > max_read {
                        break;
                    }
                    let mut user_payload_ptr = 0u64;
                    if !work.payload.is_empty() {
                        if let Some(dst_va) = with_step45_state(|state| {
                            state
                                .android_mut()
                                .broker_mut(domain)
                                .alloc_mmap_slice(ep_id, work.payload.len())
                        })
                        .ok()
                        .flatten()
                        {
                            let _ = copy_to_user(dst_va, &work.payload);
                            user_payload_ptr = dst_va;
                        }
                    }
                    let tx_out = BinderTransactionData {
                        target_handle_or_ptr: work.target_ptr,
                        cookie: work.cookie,
                        code: work.code,
                        flags: work.flags,
                        sender_pid: work.sender_pid,
                        sender_euid: work.sender_euid,
                        data_size: work.payload.len() as u64,
                        offsets_size: 0,
                        data_ptr: user_payload_ptr,
                        offsets_ptr: 0,
                    };
                    rbuf.extend_from_slice(&work.return_cmd.to_le_bytes());
                    rbuf.extend_from_slice(&tx_out.to_le_bytes());
                    // Deliver one transaction/reply per BINDER_WRITE_READ return so userspace
                    // processes it promptly.
                    break;
                }
                other => {
                    if rbuf.len() + 4 <= max_read {
                        rbuf.extend_from_slice(&other.to_le_bytes());
                    }
                }
            }
        }

        if !rbuf.is_empty() {
            if let Err(e) = copy_to_user(bwr.read_buffer.wrapping_add(bwr.read_consumed), &rbuf) {
                return Ok(Err(e));
            }
            bwr.read_consumed = bwr.read_consumed.saturating_add(rbuf.len() as u64);
        }
    }

    if let Err(e) = copy_to_user(bwr_user_ptr, &bwr.to_le_bytes()) {
        return Ok(Err(e));
    }
    Ok(Ok(0))
}

fn handle_ashmem_ioctl(region_id: u32, cmd: u64, arg: u64) -> Result<Result<i64, Errno>, ()> {
    let cmd32 = cmd & 0xFFFF_FFFF;
    match cmd32 {
        ASHMEM_SET_NAME => {
            let mut raw = [0u8; 256];
            let _ = read_user_cstr(arg, &mut raw);
            with_step45_state(|state| {
                let reg = state
                    .android_mut()
                    .ashmem_mut(region_id)
                    .ok_or(Errno::EBADF)?;
                reg.set_name(&raw)?;
                Ok(0)
            })
        }
        ASHMEM_GET_NAME => {
            let name = with_step45_state(|state| {
                state
                    .android()
                    .ashmem(region_id)
                    .map(|r| r.name.as_bytes().to_vec())
                    .ok_or(Errno::EBADF)
            })?;
            let bytes = match name {
                Ok(b) => b,
                Err(e) => return Ok(Err(e)),
            };
            let mut out = [0u8; 256];
            let take = bytes.len().min(255);
            out[..take].copy_from_slice(&bytes[..take]);
            if let Err(e) = copy_to_user(arg, &out) {
                return Ok(Err(e));
            }
            Ok(Ok(0))
        }
        ASHMEM_SET_SIZE => with_step45_state(|state| {
            let reg = state
                .android_mut()
                .ashmem_mut(region_id)
                .ok_or(Errno::EBADF)?;
            reg.set_size(arg as usize)?;
            Ok(0)
        }),
        ASHMEM_GET_SIZE => with_step45_state(|state| {
            let reg = state.android().ashmem(region_id).ok_or(Errno::EBADF)?;
            Ok(reg.size as i64)
        }),
        ASHMEM_SET_PROT_MASK => with_step45_state(|state| {
            let reg = state
                .android_mut()
                .ashmem_mut(region_id)
                .ok_or(Errno::EBADF)?;
            reg.prot_mask = arg & 0x7;
            Ok(0)
        }),
        ASHMEM_GET_PROT_MASK => with_step45_state(|state| {
            let reg = state.android().ashmem(region_id).ok_or(Errno::EBADF)?;
            Ok(reg.prot_mask as i64)
        }),
        ASHMEM_PIN => with_step45_state(|state| {
            let reg = state
                .android_mut()
                .ashmem_mut(region_id)
                .ok_or(Errno::EBADF)?;
            Ok(reg.pin())
        }),
        ASHMEM_UNPIN => with_step45_state(|state| {
            let reg = state
                .android_mut()
                .ashmem_mut(region_id)
                .ok_or(Errno::EBADF)?;
            Ok(reg.unpin())
        }),
        ASHMEM_GET_PIN_STATUS => with_step45_state(|state| {
            let reg = state.android().ashmem(region_id).ok_or(Errno::EBADF)?;
            Ok(if reg.pinned {
                ASHMEM_IS_PINNED
            } else {
                ASHMEM_IS_UNPINNED
            })
        }),
        ASHMEM_PURGE_ALL_CACHES => Ok(Ok(0)),
        DMA_HEAP_IOCTL_ALLOC => {
            // `struct dma_heap_allocation_data`: u64 len, u32 fd, u32 fd_flags, u64 heap_flags
            let mut raw = [0u8; 24];
            if let Err(e) = copy_from_user(&mut raw, arg) {
                return Ok(Err(e));
            }
            let alloc_len = u64::from_le_bytes(raw[0..8].try_into().unwrap_or([0; 8])) as usize;
            let Some(process) = current_process_object() else {
                return Err(());
            };
            let new_fd = with_step45_state(|state| {
                let Some(idx) = state.fds.iter().position(|s| !s.live) else {
                    return Err(Errno::EMFILE);
                };
                let new_id = state.android_mut().create_ashmem()?;
                {
                    let reg = state
                        .android_mut()
                        .ashmem_mut(new_id)
                        .ok_or(Errno::ENOMEM)?;
                    reg.set_name(b"dma_heap_system\0")?;
                    reg.set_size(alloc_len.max(4096))?;
                    reg.ensure_allocated()?;
                }
                let fd_gen = state.next_fd_generation;
                state.next_fd_generation = state.next_fd_generation.wrapping_add(1).max(1);
                let mut owners = DirectProcessRefs::empty();
                owners.init(process, true);
                state.fds[idx] = AndroidFdSlot {
                    live: true,
                    kind: AndroidNodeKind::Ashmem,
                    generation: fd_gen,
                    owners,
                    alias_refs: 0,
                    offset: 0,
                    status_flags: 2,
                    binder_endpoint_id: 0,
                    ashmem_region_id: new_id,
                };
                Ok((ANDROID_FD_BASE + (idx as i32)) as u32)
            })?;
            match new_fd {
                Ok(fd_u32) => {
                    raw[8..12].copy_from_slice(&fd_u32.to_le_bytes());
                    if let Err(e) = copy_to_user(arg, &raw) {
                        return Ok(Err(e));
                    }
                    Ok(Ok(0))
                }
                Err(e) => Ok(Err(e)),
            }
        }
        _ => Ok(Err(Errno::ENOTTY)),
    }
}

fn stat_meta_for(state: &Step45State, kind: AndroidNodeKind, ashmem_id: u32) -> StatMeta {
    let (rdev, ino) = kind.rdev_and_ino();
    let size = match kind {
        AndroidNodeKind::Ashmem | AndroidNodeKind::DmaHeapSystem if ashmem_id != 0 => state
            .android()
            .ashmem(ashmem_id)
            .map_or(0, |r| r.size as u64),
        AndroidNodeKind::Binder(_) => 0,
        other => render_node_bytes(state, other).len() as u64,
    };
    let now = super::step_fd_util::current_epoch_now_secs() as i64;
    StatMeta {
        dev: 45,
        ino,
        mode: kind.stat_mode(),
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev,
        size,
        blksize: 4096,
        blocks: size.div_ceil(512),
        atime_sec: now,
        atime_nsec: 0,
        mtime_sec: now,
        mtime_nsec: 0,
        ctime_sec: now,
        ctime_nsec: 0,
        mnt_id: 45,
        is_mount_root: false,
    }
}

fn handle_fstat(raw_fd: u64, stat_ptr: u64) -> Result<Result<i64, Errno>, ()> {
    let Some(process) = current_process_object() else {
        return Err(());
    };
    let Ok((idx, alias_gen)) = resolve_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let meta = with_step45_state(|state| {
        let Some(entry) = resolve_slot(state, process, idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        Ok(stat_meta_for(state, entry.kind, entry.ashmem_region_id))
    })?;
    match meta {
        Ok(m) => Ok(write_aarch64_stat_meta(stat_ptr, &m)),
        Err(e) => Ok(Err(e)),
    }
}

fn handle_newfstatat_if_android(
    raw_dirfd: u64,
    path_ptr: u64,
    stat_ptr: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if (flags & AT_EMPTY_PATH) != 0 && is_android_fd_or_alias(raw_dirfd) {
        return Ok(Some(encode_result(handle_fstat(raw_dirfd, stat_ptr)?)));
    }
    let mut path_buf = [0u8; 256];
    let Ok(path_len) = read_user_cstr(path_ptr, &mut path_buf) else {
        return Ok(None);
    };
    let Some(kind) = match_android_path(&path_buf[..path_len]) else {
        return Ok(None);
    };
    let meta = with_step45_state(|state| stat_meta_for(state, kind, 0))?;
    Ok(Some(encode_result(write_aarch64_stat_meta(
        stat_ptr, &meta,
    ))))
}

fn handle_statx_if_android(
    raw_dirfd: u64,
    path_ptr: u64,
    flags: u64,
    statx_ptr: u64,
) -> Result<Option<SyscallReturn>, ()> {
    if (flags & AT_EMPTY_PATH) != 0 && is_android_fd_or_alias(raw_dirfd) {
        let Some(process) = current_process_object() else {
            return Err(());
        };
        let Ok((idx, alias_gen)) = resolve_slot_idx(process, raw_dirfd) else {
            return Ok(Some(encode_result(Err(Errno::EBADF))));
        };
        let meta = with_step45_state(|state| {
            let Some(entry) = resolve_slot(state, process, idx, alias_gen) else {
                return Err(Errno::EBADF);
            };
            Ok(stat_meta_for(state, entry.kind, entry.ashmem_region_id))
        })?;
        return match meta {
            Ok(m) => Ok(Some(encode_result(write_aarch64_statx_meta(statx_ptr, &m)))),
            Err(e) => Ok(Some(encode_result(Err(e)))),
        };
    }
    let mut path_buf = [0u8; 256];
    let Ok(path_len) = read_user_cstr(path_ptr, &mut path_buf) else {
        return Ok(None);
    };
    let Some(kind) = match_android_path(&path_buf[..path_len]) else {
        return Ok(None);
    };
    let meta = with_step45_state(|state| stat_meta_for(state, kind, 0))?;
    Ok(Some(encode_result(write_aarch64_statx_meta(
        statx_ptr, &meta,
    ))))
}
