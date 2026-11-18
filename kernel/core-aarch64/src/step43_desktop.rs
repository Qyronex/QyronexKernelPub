// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::step_fd_util::{
    DirectProcessRefs, S_IFCHR_MODE, S_IFREG_MODE, SUBSYS_DESKTOP, StatMeta, copy_from_user,
    copy_to_user, current_process_object, encode_result, fd_in_close_range,
    lookup_aliased_subsystem, lookup_aliased_subsystem_current, read_user_cstr, seek_bounded,
    write_aarch64_stat_meta, write_aarch64_statx_meta,
};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_capability::{CapRights, Capability, ObjectId};
use kernal_linux_abi::{Errno, SyscallRequest, SyscallReturn, linux_signed_int};
use kernal_linux_desktop::{
    AddFbRequest, DRM_CAP_ADDFB2_MODIFIERS, DRM_CAP_ASYNC_PAGE_FLIP, DRM_CAP_CRTC_IN_VBLANK_EVENT,
    DRM_CAP_CURSOR_HEIGHT, DRM_CAP_CURSOR_WIDTH, DRM_CAP_DUMB_BUFFER, DRM_CAP_DUMB_PREFER_SHADOW,
    DRM_CAP_DUMB_PREFERRED_DEPTH, DRM_CAP_PRIME, DRM_CAP_TIMESTAMP_MONOTONIC,
    DRM_CAP_VBLANK_HIGH_CRTC, DRM_CLIENT_CAP_ATOMIC, DRM_CLIENT_CAP_STEREO_3D,
    DRM_CLIENT_CAP_UNIVERSAL_PLANES, DRM_CONNECTOR_ID, DRM_CRTC_ID, DRM_ENCODER_ID,
    DRM_FORMAT_ARGB8888, DRM_FORMAT_XRGB8888, DRM_IOCTL_DROP_MASTER, DRM_IOCTL_GEM_CLOSE,
    DRM_IOCTL_GET_CAP, DRM_IOCTL_GET_MAGIC, DRM_IOCTL_GET_UNIQUE, DRM_IOCTL_MODE_ADDFB,
    DRM_IOCTL_MODE_ADDFB2, DRM_IOCTL_MODE_ATOMIC, DRM_IOCTL_MODE_CREATE_DUMB,
    DRM_IOCTL_MODE_CURSOR, DRM_IOCTL_MODE_CURSOR2, DRM_IOCTL_MODE_DESTROY_DUMB,
    DRM_IOCTL_MODE_DIRTYFB, DRM_IOCTL_MODE_GETCONNECTOR, DRM_IOCTL_MODE_GETCRTC,
    DRM_IOCTL_MODE_GETENCODER, DRM_IOCTL_MODE_GETFB, DRM_IOCTL_MODE_GETPLANE,
    DRM_IOCTL_MODE_GETPLANERESOURCES, DRM_IOCTL_MODE_GETPROPBLOB, DRM_IOCTL_MODE_GETPROPERTY,
    DRM_IOCTL_MODE_GETRESOURCES, DRM_IOCTL_MODE_MAP_DUMB, DRM_IOCTL_MODE_OBJ_GETPROPERTIES,
    DRM_IOCTL_MODE_PAGE_FLIP, DRM_IOCTL_MODE_RMFB, DRM_IOCTL_MODE_SETCRTC,
    DRM_IOCTL_MODE_SETPROPERTY, DRM_IOCTL_PRIME_HANDLE_TO_FD, DRM_IOCTL_SET_CLIENT_CAP,
    DRM_IOCTL_SET_MASTER, DRM_IOCTL_VERSION, DRM_IOCTL_WAIT_VBLANK, DRM_MODE_CONNECTED,
    DRM_MODE_CONNECTOR_VIRTUAL, DRM_MODE_ENCODER_VIRTUAL, DRM_PRIMARY_PLANE_ID, DisplayMode,
    DrmModeInfo, EvdevIoctl, FBIOGET_FSCREENINFO, FBIOGET_VSCREENINFO, FBIOPAN_DISPLAY,
    INPUT_EVENT_BYTES, InputAbsAxisInfo, InputDeviceMeta, InputDeviceProfile, InputEvent,
    MAX_INPUT_DEVICES, PageFlipRequest, PcmAudioDevice, PcmFormat, PcmParams, SNDRV_PCM_IOCTL_DROP,
    SNDRV_PCM_IOCTL_PREPARE, SNDRV_PCM_IOCTL_START, SeatManager, SetCrtcRequest,
};
use kernal_linux_fd::SubsystemHandle;
use kernal_virtio::gpu::{VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM, VirtioGpuMemEntry, VirtioGpuRect};
use kernal_virtio::{VirtioInputCaps, VirtioInputKind};

/// Dedicated file-descriptor base for Step-43 desktop DRM/evdev/audio/seat descriptors
/// (`256..272`), cleanly isolated above `HW_FD_BASE` (`240..256`).
pub(super) const DESKTOP_FD_BASE: i32 = 256;
const MAX_DESKTOP_FDS: usize = 16;
const MAX_DUMB_BACKINGS: usize = 16;
const AT_EMPTY_PATH: u64 = 0x1000;
const O_CLOEXEC_U64: u64 = 0x0008_0000;
const O_NONBLOCK_U64: u64 = 0x0800;

const DESKTOP_CTRL_CAP: Capability = Capability {
    object: ObjectId(43),
    rights: CapRights::CONTROL
        .union(CapRights::READ)
        .union(CapRights::WRITE),
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum DesktopNodeKind {
    None,
    DrmCard0,
    Fb0,
    InputEvent(u8),
    SndPcm0,
    Seat0Status,
}

impl DesktopNodeKind {
    const fn stat_mode(self) -> u32 {
        match self {
            Self::Seat0Status => S_IFREG_MODE,
            _ => S_IFCHR_MODE,
        }
    }

    const fn rdev_and_ino(self) -> (u64, u64) {
        match self {
            Self::None => (0, 0),
            Self::DrmCard0 => ((226u64 << 8), 43_000),
            Self::Fb0 => ((29u64 << 8), 43_001),
            Self::InputEvent(idx) => {
                let minor = 64 + (idx as u64);
                ((13u64 << 8) | minor, 43_010 + (idx as u64))
            }
            Self::SndPcm0 => ((116u64 << 8) | 16, 43_020),
            Self::Seat0Status => (0, 43_030),
        }
    }

    fn write_path(self, out: &mut [u8]) -> usize {
        let fixed: &[u8] = match self {
            Self::None => b"",
            Self::DrmCard0 => b"/dev/dri/card0",
            Self::Fb0 => b"/dev/fb0",
            Self::SndPcm0 => b"/dev/snd/pcmC0D0p",
            Self::Seat0Status => b"/run/systemd/seats/seat0",
            Self::InputEvent(idx) => {
                let prefix = b"/dev/input/event";
                let mut n = prefix.len().min(out.len());
                out[..n].copy_from_slice(&prefix[..n]);
                if n < out.len() {
                    out[n] = b'0' + (idx % 10);
                    n += 1;
                }
                return n;
            }
        };
        let n = fixed.len().min(out.len());
        out[..n].copy_from_slice(&fixed[..n]);
        n
    }
}

#[derive(Clone, Copy)]
struct DesktopFdSlot {
    live: bool,
    kind: DesktopNodeKind,
    generation: u64,
    owners: DirectProcessRefs<16>,
    alias_refs: usize,
    status_flags: u64,
    session_id: u32,
    session_gen: u32,
    offset: usize,
}

impl DesktopFdSlot {
    const EMPTY: Self = Self {
        live: false,
        kind: DesktopNodeKind::None,
        generation: 0,
        owners: DirectProcessRefs::empty(),
        alias_refs: 0,
        status_flags: 0,
        session_id: 0,
        session_gen: 0,
        offset: 0,
    };
}

#[derive(Clone, Copy)]
struct DumbBacking {
    active: bool,
    handle: u32,
    phys_base: u64,
    pages: u64,
    width: u32,
    height: u32,
    gpu_attached: bool,
}

impl DumbBacking {
    const EMPTY: Self = Self {
        active: false,
        handle: 0,
        phys_base: 0,
        pages: 0,
        width: 0,
        height: 0,
        gpu_attached: false,
    };
}

struct Step43State {
    initialized: bool,
    seat: SeatManager,
    audio: PcmAudioDevice,
    default_session_id: u32,
    default_session_gen: u32,
    next_generation: u64,
    fb0_dumb_handle: Option<u32>,
    input_count: usize,
    evdev_clock_ids: [i32; MAX_INPUT_DEVICES],
    dumb_backings: [DumbBacking; MAX_DUMB_BACKINGS],
    fds: [DesktopFdSlot; MAX_DESKTOP_FDS],
}

impl Step43State {
    const fn new() -> Self {
        Self {
            initialized: false,
            seat: SeatManager::new(),
            audio: PcmAudioDevice::new(),
            default_session_id: 0,
            default_session_gen: 0,
            next_generation: 1,
            fb0_dumb_handle: None,
            input_count: 1,
            evdev_clock_ids: [0; MAX_INPUT_DEVICES],
            dumb_backings: [DumbBacking::EMPTY; MAX_DUMB_BACKINGS],
            fds: [DesktopFdSlot::EMPTY; MAX_DESKTOP_FDS],
        }
    }

    fn ensure_initialized(&mut self) {
        if self.initialized {
            return;
        }
        if let Ok(opened) = self.seat.open_session(DESKTOP_CTRL_CAP, 0, 1)
            && let Ok(active) = self
                .seat
                .activate_session(DESKTOP_CTRL_CAP, opened.session_id)
        {
            self.default_session_id = active.session_id;
            self.default_session_gen = active.generation;
        }
        if let Some((w, h)) = super::step42_hardware::hardware_gpu_dimensions() {
            self.seat.drm.set_preferred_dimensions(w, h);
        }
        let hw_inputs = super::step42_hardware::hardware_input_count();
        if hw_inputs > 0 {
            let count = hw_inputs.min(MAX_INPUT_DEVICES);
            self.input_count = count;
            for idx in 0..count {
                if let Some((kind, caps)) = super::step42_hardware::hardware_input_info(idx) {
                    self.seat.evdevs[idx].meta = input_meta_from_hw(kind, &caps);
                }
            }
        } else {
            self.input_count = 1;
            self.seat.evdevs[0].meta = InputDeviceMeta::default_keyboard();
        }
        let _ = self.audio.set_hw_params(
            DESKTOP_CTRL_CAP,
            PcmParams {
                rate_hz: 48_000,
                channels: 2,
                format: PcmFormat::S16Le,
                period_frames: 256,
            },
        );
        self.initialized = true;
    }

    fn find_backing(&self, handle: u32) -> Option<DumbBacking> {
        self.dumb_backings
            .iter()
            .copied()
            .find(|b| b.active && b.handle == handle)
    }

    fn find_backing_mut(&mut self, handle: u32) -> Option<&mut DumbBacking> {
        self.dumb_backings
            .iter_mut()
            .find(|b| b.active && b.handle == handle)
    }
}

fn input_meta_from_hw(kind: VirtioInputKind, caps: &VirtioInputCaps) -> InputDeviceMeta {
    let mut meta = InputDeviceMeta::empty();
    meta.present = true;
    meta.profile = match kind {
        VirtioInputKind::Keyboard | VirtioInputKind::Generic => InputDeviceProfile::Keyboard,
        VirtioInputKind::Mouse => InputDeviceProfile::Mouse,
        VirtioInputKind::Tablet => InputDeviceProfile::Tablet,
    };
    meta.bustype = caps.devids.bustype;
    meta.vendor = caps.devids.vendor;
    meta.product = caps.devids.product;
    meta.version = caps.devids.version;
    meta.name = caps.name;
    meta.name_len = caps.name_len;
    meta.prop_bits = caps.prop_bits;
    meta.ev_bits = caps.ev_bits;
    meta.key_bits = caps.key_bits;
    meta.rel_bits = caps.rel_bits;
    meta.abs_bits = caps.abs_bits;
    meta.abs_x = InputAbsAxisInfo {
        value: 0,
        minimum: caps.abs_x.min as i32,
        maximum: caps.abs_x.max as i32,
        fuzz: caps.abs_x.fuzz as i32,
        flat: caps.abs_x.flat as i32,
        resolution: caps.abs_x.res as i32,
    };
    meta.abs_y = InputAbsAxisInfo {
        value: 0,
        minimum: caps.abs_y.min as i32,
        maximum: caps.abs_y.max as i32,
        fuzz: caps.abs_y.fuzz as i32,
        flat: caps.abs_y.flat as i32,
        resolution: caps.abs_y.res as i32,
    };
    meta
}

struct Step43Cell {
    state: AtomicU8,
    value: UnsafeCell<Step43State>,
}

// SAFETY: lower-EL trap dispatch serializes access cleanly via atomic `0 -> 1 -> 0`.
unsafe impl Sync for Step43Cell {}

static STEP43_STATE: Step43Cell = Step43Cell {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(Step43State::new()),
};

fn with_step43_state<R>(f: impl FnOnce(&mut Step43State) -> R) -> Result<R, ()> {
    if STEP43_STATE
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(());
    }
    // SAFETY: state `1` provides exclusive mutable access inside this synchronous handler scope.
    let state = unsafe { &mut *STEP43_STATE.value.get() };
    state.ensure_initialized();
    let res = f(state);
    STEP43_STATE.state.store(0, Ordering::Release);
    Ok(res)
}

pub(super) const fn is_desktop_fd(raw_fd: u64) -> bool {
    let fd = linux_signed_int(raw_fd);
    fd >= DESKTOP_FD_BASE && fd < DESKTOP_FD_BASE + (MAX_DESKTOP_FDS as i32)
}

fn is_desktop_fd_or_alias(raw_fd: u64) -> bool {
    is_desktop_fd(raw_fd)
        || lookup_aliased_subsystem_current(raw_fd).is_some_and(|h| h.kind == SUBSYS_DESKTOP)
}

pub(super) fn is_open_desktop_fd(process: ObjectId, raw_fd: u64) -> bool {
    if !is_desktop_fd(raw_fd) {
        return false;
    }
    let idx = (linux_signed_int(raw_fd) - DESKTOP_FD_BASE) as usize;
    with_step43_state(|state| resolve_slot_mut(state, process, idx, None).is_some())
        .unwrap_or(false)
}

fn resolve_slot_idx(process: ObjectId, raw_fd: u64) -> Result<(usize, Option<u64>), Errno> {
    if is_desktop_fd(raw_fd) {
        return Ok(((linux_signed_int(raw_fd) - DESKTOP_FD_BASE) as usize, None));
    }
    if let Some(handle) = lookup_aliased_subsystem(process, raw_fd)
        && handle.kind == SUBSYS_DESKTOP
    {
        return Ok((handle.slot as usize, Some(handle.generation)));
    }
    Err(Errno::EBADF)
}

fn resolve_slot_mut<'a>(
    state: &'a mut Step43State,
    process: ObjectId,
    slot_idx: usize,
    alias_gen: Option<u64>,
) -> Option<&'a mut DesktopFdSlot> {
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

fn retire_slot_if_unused(state: &mut Step43State, slot_idx: usize) {
    let Some(entry) = state.fds.get(slot_idx).copied() else {
        return;
    };
    if !entry.live || !entry.owners.is_empty() || entry.alias_refs > 0 {
        return;
    }
    state.fds[slot_idx] = DesktopFdSlot::EMPTY;
}

fn match_desktop_path(state: &Step43State, path: &[u8]) -> Option<DesktopNodeKind> {
    match path {
        b"/dev/dri/card0" => Some(DesktopNodeKind::DrmCard0),
        b"/dev/fb0" => Some(DesktopNodeKind::Fb0),
        b"/dev/snd/pcmC0D0p" => Some(DesktopNodeKind::SndPcm0),
        b"/run/systemd/seats/seat0" if !super::step33_mounts::has_live_ext4_mounts() => {
            Some(DesktopNodeKind::Seat0Status)
        }
        _ if path.starts_with(b"/dev/input/event")
            && path.len() == b"/dev/input/event".len() + 1 =>
        {
            let d = path[b"/dev/input/event".len()];
            if d.is_ascii_digit() {
                let idx = usize::from(d - b'0');
                if idx < state.input_count && idx < MAX_INPUT_DEVICES {
                    return Some(DesktopNodeKind::InputEvent(idx as u8));
                }
            }
            None
        }
        _ => None,
    }
}

fn desktop_stat_meta(state: &Step43State, kind: DesktopNodeKind) -> StatMeta {
    let (rdev, ino) = kind.rdev_and_ino();
    let size = if kind == DesktopNodeKind::Seat0Status {
        let mut data = [0u8; 128];
        state.seat.format_seat0_status(&mut data).unwrap_or(0) as u64
    } else {
        0
    };
    let ts = super::step42_hardware::rtc_epoch_base_seconds() as i64;
    StatMeta {
        dev: 5,
        ino,
        mode: kind.stat_mode(),
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev,
        size,
        blksize: 4096,
        blocks: 0,
        atime_sec: ts,
        atime_nsec: 0,
        mtime_sec: ts,
        mtime_nsec: 0,
        ctime_sec: ts,
        ctime_nsec: 0,
        mnt_id: 5,
        is_mount_root: false,
    }
}

pub(super) fn describe_desktop_slot(
    slot_idx: u16,
    expected_gen: Option<u64>,
    owner: Option<ObjectId>,
    out: &mut [u8],
) -> Option<usize> {
    with_step43_state(|state| {
        let entry = state.fds.get(slot_idx as usize)?;
        if !entry.live {
            return None;
        }
        if let Some(g) = expected_gen
            && (entry.generation != g || entry.alias_refs == 0)
        {
            return None;
        }
        if let Some(p) = owner
            && !entry.owners.has_owner(p)
        {
            return None;
        }
        Some(entry.kind.write_path(out))
    })
    .ok()
    .flatten()
}

pub(super) fn append_open_desktop_fds(process: ObjectId, out: &mut alloc::vec::Vec<i32>) {
    let _ = with_step43_state(|state| {
        for (idx, slot) in state.fds.iter().enumerate() {
            if slot.live && slot.owners.has_owner(process) {
                out.push(DESKTOP_FD_BASE + (idx as i32));
            }
        }
    });
}

fn retain_desktop_slot(
    slot_idx: usize,
    owner: Option<ObjectId>,
    expected_gen: Option<u64>,
) -> Result<(SubsystemHandle, u64), Errno> {
    with_step43_state(|state| {
        let Some(entry) = state.fds.get_mut(slot_idx) else {
            return Err(Errno::EBADF);
        };
        let valid = entry.live
            && owner.is_none_or(|p| entry.owners.has_owner(p))
            && expected_gen.is_none_or(|g| entry.generation == g);
        if !valid {
            return Err(Errno::EBADF);
        }
        entry.alias_refs += 1;
        Ok((
            SubsystemHandle {
                kind: SUBSYS_DESKTOP,
                slot: slot_idx as u16,
                generation: entry.generation,
            },
            entry.status_flags,
        ))
    })
    .map_err(|()| Errno::EIO)?
}

pub(super) fn retain_alias_handle(
    process: ObjectId,
    raw_fd: u64,
) -> Result<(SubsystemHandle, u64), Errno> {
    if !is_desktop_fd(raw_fd) {
        return Err(Errno::EBADF);
    }
    let idx = (linux_signed_int(raw_fd) - DESKTOP_FD_BASE) as usize;
    retain_desktop_slot(idx, Some(process), None)
}

pub(super) fn retain_existing_handle(
    handle: SubsystemHandle,
) -> Result<(SubsystemHandle, u64), Errno> {
    if handle.kind != SUBSYS_DESKTOP {
        return Err(Errno::EBADF);
    }
    retain_desktop_slot(handle.slot as usize, None, Some(handle.generation))
}

pub(super) fn release_alias_handle(handle: SubsystemHandle) {
    if handle.kind != SUBSYS_DESKTOP {
        return;
    }
    let idx = handle.slot as usize;
    let _ = with_step43_state(|state| {
        let Some(entry) = state.fds.get_mut(idx) else {
            return;
        };
        if entry.live && entry.generation == handle.generation && entry.alias_refs > 0 {
            entry.alias_refs -= 1;
            retire_slot_if_unused(state, idx);
        }
    });
}

pub(super) fn on_process_fork(parent: ObjectId, child: ObjectId) {
    let _ = with_step43_state(|state| {
        for slot in &mut state.fds {
            if slot.live {
                slot.owners.on_fork(parent, child);
            }
        }
    });
}

pub(super) fn on_process_exec(process: ObjectId) {
    let _ = with_step43_state(|state| {
        for idx in 0..MAX_DESKTOP_FDS {
            if state.fds[idx].live {
                state.fds[idx].owners.close_cloexec_for(process);
                retire_slot_if_unused(state, idx);
            }
        }
    });
}

pub(super) fn on_process_exit(process: ObjectId) {
    let _ = with_step43_state(|state| {
        for idx in 0..MAX_DESKTOP_FDS {
            if state.fds[idx].live {
                state.fds[idx].owners.close_owner(process);
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
    let _ = with_step43_state(|state| {
        for idx in 0..MAX_DESKTOP_FDS {
            let fd = DESKTOP_FD_BASE + (idx as i32);
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

pub(super) fn handle_native_fcntl(
    process: ObjectId,
    raw_fd: u64,
    cmd: u32,
    argi: i32,
) -> Option<Result<i64, Errno>> {
    let Ok((slot_idx, alias_gen)) = resolve_slot_idx(process, raw_fd) else {
        return None;
    };
    if alias_gen.is_some() && !matches!(cmd, 3 | 4) {
        return None;
    }
    let res = with_step43_state(|state| {
        let Some(entry) = resolve_slot_mut(state, process, slot_idx, alias_gen) else {
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
            3 => Ok((entry.status_flags & O_NONBLOCK_U64) as i64),
            4 => {
                entry.status_flags = (u64::from(argi as u32)) & O_NONBLOCK_U64;
                Ok(0)
            }
            _ => Err(Errno::EINVAL),
        }
    });
    Some(res.unwrap_or(Err(Errno::EIO)))
}

/// Polls hardware `virtio-input` queues and appends events into their respective `evdev` rings.
pub(super) fn poll_hardware_input_into_rings() {
    let count = super::step42_hardware::hardware_input_count().min(MAX_INPUT_DEVICES);
    if count == 0 {
        return;
    }
    let realtime_sec = super::step42_hardware::rtc_epoch_base_seconds() as i64;
    let mono_ns = kernal_timer_aarch64::monotonic_now_ns().unwrap_or(0);
    let mono_sec = (mono_ns / 1_000_000_000) as i64;
    let mono_usec = ((mono_ns % 1_000_000_000) / 1_000) as i64;
    for idx in 0..count {
        for _ in 0..32 {
            let Some(hw_ev) = super::step42_hardware::hardware_input_poll_event(idx) else {
                break;
            };
            let _ = with_step43_state(|state| {
                let (sec, usec) = if state.evdev_clock_ids[idx] == 1 {
                    (mono_sec, mono_usec)
                } else {
                    (realtime_sec, 0)
                };
                let _ = state.seat.evdevs[idx].push_event(InputEvent {
                    sec,
                    usec,
                    event_type: hw_ev.event_type,
                    code: hw_ev.code,
                    value: hw_ev.value as i32,
                });
            });
        }
    }
}

/// Probes `POLLIN`/`POLLOUT` readiness bits for a desktop DRM, evdev, fb0, or audio FD (or alias).
pub(super) fn probe_desktop_fd_readiness(
    process: ObjectId,
    raw_fd: u64,
) -> Option<Result<u32, Errno>> {
    const POLLIN: u32 = 0x0001;
    const POLLOUT: u32 = 0x0004;

    if !is_desktop_fd(raw_fd)
        && !lookup_aliased_subsystem(process, raw_fd).is_some_and(|h| h.kind == SUBSYS_DESKTOP)
    {
        return None;
    }
    let Ok((slot_idx, alias_gen)) = resolve_slot_idx(process, raw_fd) else {
        return Some(Err(Errno::EBADF));
    };
    poll_hardware_input_into_rings();
    let res = with_step43_state(|state| {
        let Some(entry) = resolve_slot_mut(state, process, slot_idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        let mask = match entry.kind {
            DesktopNodeKind::None => return Err(Errno::EBADF),
            DesktopNodeKind::DrmCard0 => {
                if state.seat.drm.has_pending_event() {
                    POLLIN
                } else {
                    0
                }
            }
            DesktopNodeKind::InputEvent(idx) => {
                if state.seat.evdevs[usize::from(idx)].has_pending_events() {
                    POLLIN
                } else {
                    0
                }
            }
            DesktopNodeKind::Fb0 | DesktopNodeKind::SndPcm0 => POLLOUT,
            DesktopNodeKind::Seat0Status => POLLIN,
        };
        Ok(mask)
    })
    .map_err(|()| Errno::EIO);
    Some(match res {
        Ok(inner) => inner,
        Err(e) => Err(e),
    })
}

pub(super) fn try_open_desktop_bytes(path: &[u8], flags: u64) -> Result<Option<SyscallReturn>, ()> {
    let Some(process) = current_process_object() else {
        return Err(());
    };
    let found = with_step43_state(|state| match_desktop_path(state, path))?;
    let Some(kind) = found else {
        return Ok(None);
    };
    let res = with_step43_state(|state| open_desktop_slot(state, process, kind, flags))?;
    Ok(Some(encode_result(res)))
}

pub(super) fn try_stat_desktop_bytes(
    path: &[u8],
    user_statbuf: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let meta = with_step43_state(|state| {
        match_desktop_path(state, path).map(|kind| desktop_stat_meta(state, kind))
    })?;
    let Some(meta) = meta else {
        return Ok(None);
    };
    Ok(Some(encode_result(write_aarch64_stat_meta(
        user_statbuf,
        &meta,
    ))))
}

pub(super) fn try_statx_desktop_bytes(
    path: &[u8],
    user_statx: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let meta = with_step43_state(|state| {
        match_desktop_path(state, path).map(|kind| desktop_stat_meta(state, kind))
    })?;
    let Some(meta) = meta else {
        return Ok(None);
    };
    Ok(Some(encode_result(write_aarch64_statx_meta(
        user_statx, &meta,
    ))))
}

/// Synthesizes `/sys/class/input/input{0,1}/...` attributes dynamically from the probed hardware
/// `virtio-input` device slot so `systemd-udevd` (`input_id`) tags keyboard vs. tablet/mouse
/// accurately regardless of QEMU MMIO slot ordering.
pub(super) fn read_dynamic_input_sysfs_attr(rel_path: &[u8], out: &mut [u8]) -> Option<usize> {
    let (idx, tail, is_event_node): (usize, &[u8], bool) = if let Some(t) = rel_path
        .strip_prefix(b"class/input/event0/")
        .or_else(|| rel_path.strip_prefix(b"class/input/input0/event0/"))
        .or_else(|| rel_path.strip_prefix(b"devices/virtio3/input/input0/event0/"))
        .or_else(|| rel_path.strip_prefix(b"dev/char/13:64/"))
    {
        (0, t, true)
    } else if let Some(t) = rel_path
        .strip_prefix(b"class/input/event1/")
        .or_else(|| rel_path.strip_prefix(b"class/input/input1/event1/"))
        .or_else(|| rel_path.strip_prefix(b"devices/virtio4/input/input1/event1/"))
        .or_else(|| rel_path.strip_prefix(b"dev/char/13:65/"))
    {
        (1, t, true)
    } else if let Some(t) = rel_path
        .strip_prefix(b"class/input/input0/")
        .or_else(|| rel_path.strip_prefix(b"devices/virtio3/input/input0/"))
    {
        (0, t, false)
    } else if let Some(t) = rel_path
        .strip_prefix(b"class/input/input1/")
        .or_else(|| rel_path.strip_prefix(b"devices/virtio4/input/input1/"))
    {
        (1, t, false)
    } else {
        return None;
    };

    let kind = super::step42_hardware::hardware_input_info(idx)
        .map(|(k, _)| k)
        .unwrap_or(if idx == 0 {
            VirtioInputKind::Keyboard
        } else {
            VirtioInputKind::Tablet
        });

    if is_event_node && tail == b"uevent" {
        let bytes: &[u8] = match (idx, kind) {
            (0, VirtioInputKind::Tablet | VirtioInputKind::Mouse) => {
                b"MAJOR=13\nMINOR=64\nDEVNAME=input/event0\nID_INPUT=1\nID_INPUT_MOUSE=1\nID_INPUT_TOUCHSCREEN=1\n"
            }
            (0, _) => {
                b"MAJOR=13\nMINOR=64\nDEVNAME=input/event0\nID_INPUT=1\nID_INPUT_KEY=1\nID_INPUT_KEYBOARD=1\n"
            }
            (_, VirtioInputKind::Tablet | VirtioInputKind::Mouse) => {
                b"MAJOR=13\nMINOR=65\nDEVNAME=input/event1\nID_INPUT=1\nID_INPUT_MOUSE=1\nID_INPUT_TOUCHSCREEN=1\n"
            }
            (_, _) => {
                b"MAJOR=13\nMINOR=65\nDEVNAME=input/event1\nID_INPUT=1\nID_INPUT_KEY=1\nID_INPUT_KEYBOARD=1\n"
            }
        };
        let n = bytes.len().min(out.len());
        out[..n].copy_from_slice(&bytes[..n]);
        return Some(n);
    }

    let bytes: &[u8] = match (kind, tail) {
        (VirtioInputKind::Tablet, b"name") => b"QEMU Virtio Tablet\n",
        (VirtioInputKind::Mouse, b"name") => b"QEMU Virtio Mouse\n",
        (_, b"name") => b"QEMU Virtio Keyboard\n",

        (VirtioInputKind::Tablet, b"uevent") => {
            b"PRODUCT=6/627/2/100\nNAME=\"QEMU Virtio Tablet\"\nEV=b\nKEY=70000 0 0 0 0\nABS=3\n"
        }
        (VirtioInputKind::Mouse, b"uevent") => {
            b"PRODUCT=6/627/2/100\nNAME=\"QEMU Virtio Mouse\"\nEV=7\nKEY=70000 0 0 0 0\nREL=3\n"
        }
        (_, b"uevent") => {
            b"PRODUCT=6/627/1/100\nNAME=\"QEMU Virtio Keyboard\"\nEV=100003\nKEY=ffffffffffffffff fffffffffffffffe\n"
        }

        (VirtioInputKind::Tablet, b"capabilities/ev") => b"b\n",
        (VirtioInputKind::Mouse, b"capabilities/ev") => b"7\n",
        (_, b"capabilities/ev") => b"100003\n",

        (VirtioInputKind::Tablet | VirtioInputKind::Mouse, b"capabilities/key") => {
            b"70000 0 0 0 0\n"
        }
        (_, b"capabilities/key") => b"ffffffffffffffff fffffffffffffffe\n",

        (VirtioInputKind::Tablet, b"capabilities/abs") => b"3\n",
        (_, b"capabilities/abs") => b"0\n",

        (VirtioInputKind::Mouse, b"capabilities/rel") => b"3\n",
        (_, b"capabilities/rel") => b"0\n",

        _ => return None,
    };

    let n = bytes.len().min(out.len());
    out[..n].copy_from_slice(&bytes[..n]);
    Some(n)
}

fn open_desktop_slot(
    state: &mut Step43State,
    process: ObjectId,
    kind: DesktopNodeKind,
    flags: u64,
) -> Result<i64, Errno> {
    let Some((idx, slot)) = state.fds.iter_mut().enumerate().find(|(_, s)| !s.live) else {
        return Err(Errno::EMFILE);
    };
    let generation = state.next_generation.max(1);
    state.next_generation = state.next_generation.wrapping_add(1).max(1);
    let mut owners = DirectProcessRefs::empty();
    owners.init(process, (flags & O_CLOEXEC_U64) != 0);
    *slot = DesktopFdSlot {
        live: true,
        kind,
        generation,
        owners,
        alias_refs: 0,
        status_flags: flags & O_NONBLOCK_U64,
        session_id: state.default_session_id,
        session_gen: state.default_session_gen,
        offset: 0,
    };
    Ok(i64::from(DESKTOP_FD_BASE + (idx as i32)))
}

#[cfg(feature = "step29-qemu-proof")]
pub(super) fn try_prepare_desktop_mmap(
    raw_fd: u64,
    offset: u64,
    length: u64,
) -> Result<Option<u32>, Errno> {
    let Some(process) = current_process_object() else {
        return Err(Errno::EIO);
    };
    let Ok((slot_idx, alias_gen)) = resolve_slot_idx(process, raw_fd) else {
        return Ok(None);
    };
    let kind_and_handle = with_step43_state(|state| {
        let Some(entry) = resolve_slot_mut(state, process, slot_idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        let entry_kind = entry.kind;
        let session_id = entry.session_id;
        match entry_kind {
            DesktopNodeKind::DrmCard0 => {
                let Some(dumb) = state.seat.drm.lookup_dumb_by_mmap_offset(offset) else {
                    return Err(Errno::EINVAL);
                };
                let aligned_size = (dumb.size.saturating_add(4095)) & !4095;
                if length == 0 || length > aligned_size {
                    return Err(Errno::EINVAL);
                }
                Ok(Ok(dumb.handle))
            }
            DesktopNodeKind::Fb0 => {
                if offset != 0 {
                    return Err(Errno::EINVAL);
                }
                let w = state.seat.drm.mode.width;
                let h = state.seat.drm.mode.height;
                let existing = state.fb0_dumb_handle.or(state.seat.drm.active_fb_handle);
                Ok(Err((session_id, w, h, existing)))
            }
            _ => Err(Errno::ENODEV),
        }
    })
    .map_err(|()| Errno::EIO)??;

    match kind_and_handle {
        Ok(handle) => Ok(Some(handle)),
        Err((_session_id, w, h, Some(existing_handle))) => {
            let max_bytes = u64::from(w) * u64::from(h) * 4;
            if length == 0 || length > ((max_bytes + 4095) & !4095) {
                return Err(Errno::EINVAL);
            }
            Ok(Some(existing_handle))
        }
        Err((session_id, w, h, None)) => {
            let (handle, _, _, _) = allocate_and_register_dumb(session_id, w, h, 32)?;
            let _ = with_step43_state(|state| {
                state.fb0_dumb_handle = Some(handle);
            });
            present_dumb_to_gpu(handle, w, h, 0, 0, w, h, true)?;
            let max_bytes = (u64::from(w) * u64::from(h) * 4 + 4095) & !4095;
            if length == 0 || length > max_bytes {
                return Err(Errno::EINVAL);
            }
            Ok(Some(handle))
        }
    }
}

#[cfg(feature = "step29-qemu-proof")]
pub(super) fn write_back_drm_dumb_mmap(handle: u32, buf_offset: u64, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let backing = with_step43_state(|state| state.find_backing(handle))
        .ok()
        .flatten();
    let Some(backing) = backing else {
        return;
    };
    let end = buf_offset.saturating_add(data.len() as u64);
    let max_bytes = backing.pages.saturating_mul(4096);
    if buf_offset >= max_bytes || end > max_bytes {
        return;
    }
    let mut written = 0usize;
    while written < data.len() {
        let cur_off = buf_offset.saturating_add(written as u64);
        let page_off = cur_off & 4095;
        let phys_page = backing.phys_base.saturating_add(cur_off & !4095);
        let chunk = (data.len() - written).min(4096 - (page_off as usize));
        let _ = super::live_vm::write_phys_page_bytes(
            phys_page,
            page_off as usize,
            &data[written..written + chunk],
        );
        written += chunk;
    }
}

fn allocate_and_register_dumb(
    session_id: u32,
    width: u32,
    height: u32,
    bpp: u32,
) -> Result<(u32, u32, u64, u64), Errno> {
    let created =
        with_step43_state(|state| state.seat.drm.create_dumb(session_id, width, height, bpp))
            .map_err(|()| Errno::EIO)??;
    let pages = created.size.div_ceil(4096).max(1);
    let Ok(phys_base) = super::live_vm::alloc_zeroed_contiguous_frames(pages) else {
        let _ = with_step43_state(|state| state.seat.drm.destroy_dumb(session_id, created.handle));
        return Err(Errno::ENOMEM);
    };

    let mut gpu_attached = false;
    if super::step42_hardware::has_hardware_gpu()
        && let Ok(res_bytes) = u32::try_from(pages.saturating_mul(4096))
    {
        let gpu_res = super::step42_hardware::with_hardware_gpu(|gpu| {
            gpu.create_resource_2d(
                created.handle,
                VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM,
                width,
                height,
            )?;
            gpu.attach_backing(
                created.handle,
                &[VirtioGpuMemEntry {
                    addr: phys_base,
                    length: res_bytes,
                    padding: 0,
                }],
            )
        });
        gpu_attached = matches!(gpu_res, Ok(Ok(())));
    }

    let inserted = with_step43_state(|state| {
        let Some(slot) = state.dumb_backings.iter_mut().find(|b| !b.active) else {
            return Err(Errno::ENOSPC);
        };
        *slot = DumbBacking {
            active: true,
            handle: created.handle,
            phys_base,
            pages,
            width,
            height,
            gpu_attached,
        };
        Ok(())
    })
    .map_err(|()| Errno::EIO)?;
    if let Err(err) = inserted {
        let _ = super::live_vm::free_contiguous_frames(phys_base, pages);
        let _ = with_step43_state(|state| state.seat.drm.destroy_dumb(session_id, created.handle));
        return Err(err);
    }

    Ok((
        created.handle,
        created.pitch,
        created.size,
        created.mmap_offset,
    ))
}

fn destroy_dumb_with_backing(session_id: u32, handle: u32) -> Result<(), Errno> {
    let removed = with_step43_state(|state| {
        state.seat.drm.destroy_dumb(session_id, handle)?;
        if state.fb0_dumb_handle == Some(handle) {
            state.fb0_dumb_handle = None;
        }
        let found = state.find_backing_mut(handle).map(|b| {
            let copy = *b;
            *b = DumbBacking::EMPTY;
            copy
        });
        Ok(found)
    })
    .map_err(|()| Errno::EIO)??;

    if let Some(backing) = removed {
        if backing.gpu_attached && super::step42_hardware::has_hardware_gpu() {
            let _ = super::step42_hardware::with_hardware_gpu(|gpu| {
                let _ = gpu.detach_backing(backing.handle);
                let _ = gpu.unref_resource(backing.handle);
            });
        }
        let _ = super::live_vm::free_contiguous_frames(backing.phys_base, backing.pages);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn present_dumb_to_gpu(
    handle: u32,
    fb_w: u32,
    fb_h: u32,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    set_scanout: bool,
) -> Result<(), Errno> {
    if !super::step42_hardware::has_hardware_gpu() {
        return Ok(());
    }
    let backing = with_step43_state(|state| state.find_backing(handle)).map_err(|()| Errno::EIO)?;
    let Some(backing) = backing else {
        return Ok(());
    };
    if !backing.gpu_attached {
        return Ok(());
    }
    let rw = w.min(backing.width.saturating_sub(x));
    let rh = h.min(backing.height.saturating_sub(y));
    if rw == 0 || rh == 0 {
        return Ok(());
    }
    let rect = VirtioGpuRect::new(x, y, rw, rh);
    let offset = (u64::from(y) * u64::from(backing.width) + u64::from(x)) * 4;
    let res = super::step42_hardware::with_hardware_gpu(|gpu| {
        if set_scanout {
            gpu.set_scanout(0, handle, VirtioGpuRect::new(0, 0, fb_w, fb_h))?;
        }
        gpu.transfer_to_host_2d(handle, rect, offset)?;
        gpu.resource_flush(handle, rect)
    });
    match res {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.to_errno()),
        Err(e) => Err(e),
    }
}

pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        29 if is_desktop_fd_or_alias(request.args[0]) => {
            let req = request.args[1] & 0xffff_ffff;
            if matches!(
                req,
                DRM_IOCTL_MODE_DIRTYFB
                    | DRM_IOCTL_MODE_PAGE_FLIP
                    | DRM_IOCTL_MODE_SETCRTC
                    | FBIOPAN_DISPLAY
            ) {
                super::step31_runtime::sync_shared_mmap_all_for_current(false);
            }
            Ok(Some(encode_result(handle_ioctl(
                request.args[0],
                req,
                request.args[2],
            )?)))
        }
        56 => handle_openat_if_desktop(request.args[1], request.args[2]),
        57 if is_desktop_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_close(request.args[0])?)))
        }
        62 if is_desktop_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_lseek(
            request.args[0],
            request.args[1] as i64,
            linux_signed_int(request.args[2]),
        )?))),
        63 if is_desktop_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_read(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        64 if is_desktop_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_write(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        79 => handle_newfstatat_if_desktop(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        80 if is_desktop_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_fstat(
            request.args[0],
            request.args[1],
        )?))),
        291 => handle_statx_if_desktop(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[4],
        ),
        _ => Ok(None),
    }
}

fn handle_openat_if_desktop(user_path: u64, flags: u64) -> Result<Option<SyscallReturn>, ()> {
    let Some(process) = current_process_object() else {
        return Err(());
    };
    let mut path_buf = [0u8; 64];
    let Ok(len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    let path = &path_buf[..len];
    let Some(kind) = with_step43_state(|state| match_desktop_path(state, path))? else {
        return Ok(None);
    };
    let res = with_step43_state(|state| open_desktop_slot(state, process, kind, flags))?;
    Ok(Some(encode_result(res)))
}

fn handle_read(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    let Some(process) = current_process_object() else {
        return Err(());
    };
    let Ok((slot_idx, alias_gen)) = resolve_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    poll_hardware_input_into_rings();
    with_step43_state(|state| {
        let Some(slot) = resolve_slot_mut(state, process, slot_idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        let slot_copy = *slot;
        match slot_copy.kind {
            DesktopNodeKind::None => Err(Errno::EBADF),
            DesktopNodeKind::Seat0Status => {
                let mut data = [0u8; 128];
                let total = state.seat.format_seat0_status(&mut data)?;
                let avail = &data[slot_copy.offset.min(total)..total];
                let take = avail.len().min(count as usize);
                if take > 0 {
                    copy_to_user(user_buf, &avail[..take])?;
                    if let Some(s) = resolve_slot_mut(state, process, slot_idx, alias_gen) {
                        s.offset += take;
                    }
                }
                Ok(take as i64)
            }
            DesktopNodeKind::DrmCard0 => {
                if (count as usize) < 32 {
                    return Err(Errno::EINVAL);
                }
                let Some(ev) = state.seat.drm.pop_event() else {
                    return Err(Errno::EAGAIN);
                };
                let raw = ev.encode();
                copy_to_user(user_buf, &raw)?;
                Ok(raw.len() as i64)
            }
            DesktopNodeKind::InputEvent(idx) => {
                if (count as usize) < INPUT_EVENT_BYTES {
                    return Err(Errno::EINVAL);
                }
                let active = state.seat.active_session();
                let evdev = &mut state.seat.evdevs[usize::from(idx)];
                let max_events = (count as usize) / INPUT_EVENT_BYTES;
                let mut total = 0usize;
                for _ in 0..max_events {
                    match evdev.read_event(slot_copy.session_id, slot_copy.session_gen, active) {
                        Ok(ev) => {
                            let encoded = ev.encode();
                            copy_to_user(user_buf.saturating_add(total as u64), &encoded)?;
                            total += encoded.len();
                        }
                        Err(Errno::EAGAIN) if total > 0 => break,
                        Err(e) => return Err(e),
                    }
                }
                Ok(total as i64)
            }
            _ => Err(Errno::EINVAL),
        }
    })
}

fn handle_write(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    let Some(process) = current_process_object() else {
        return Err(());
    };
    let Ok((slot_idx, alias_gen)) = resolve_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let kind_and_session = with_step43_state(|state| {
        let Some(slot) = resolve_slot_mut(state, process, slot_idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        Ok((slot.kind, slot.session_id, slot.offset))
    })?;
    let (kind, session_id, offset) = match kind_and_session {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };

    match kind {
        DesktopNodeKind::SndPcm0 => with_step43_state(|state| {
            let mut buf = [0u8; 256];
            let take = (count as usize).min(buf.len());
            copy_from_user(&mut buf[..take], user_buf)?;
            let _frames = state.audio.write_frames(DESKTOP_CTRL_CAP, &buf[..take])?;
            Ok(take as i64)
        }),
        DesktopNodeKind::Fb0 => {
            let (fb_handle, w, h) = match ensure_fb0_dumb(session_id) {
                Ok(v) => v,
                Err(e) => return Ok(Err(e)),
            };
            let take = (count as usize).min(4096);
            let mut buf = [0u8; 4096];
            if let Err(e) = copy_from_user(&mut buf[..take], user_buf) {
                return Ok(Err(e));
            }
            write_back_drm_dumb_mmap(fb_handle, offset as u64, &buf[..take]);
            let _ = present_dumb_to_gpu(fb_handle, w, h, 0, 0, w, h, true);
            let _ = with_step43_state(|state| {
                if let Some(s) = resolve_slot_mut(state, process, slot_idx, alias_gen) {
                    s.offset += take;
                }
            });
            Ok(Ok(take as i64))
        }
        _ => Ok(Err(Errno::EROFS)),
    }
}

fn ensure_fb0_dumb(session_id: u32) -> Result<(u32, u32, u32), Errno> {
    let existing = with_step43_state(|state| {
        let w = state.seat.drm.mode.width;
        let h = state.seat.drm.mode.height;
        (
            state.fb0_dumb_handle.or(state.seat.drm.active_fb_handle),
            w,
            h,
        )
    })
    .map_err(|()| Errno::EIO)?;
    if let (Some(handle), w, h) = existing {
        return Ok((handle, w, h));
    }
    let (_, w, h) = existing;
    let (handle, _, _, _) = allocate_and_register_dumb(session_id, w, h, 32)?;
    let _ = with_step43_state(|state| {
        state.fb0_dumb_handle = Some(handle);
    });
    present_dumb_to_gpu(handle, w, h, 0, 0, w, h, true)?;
    Ok((handle, w, h))
}

fn handle_ioctl(raw_fd: u64, req: u64, arg: u64) -> Result<Result<i64, Errno>, ()> {
    let Some(process) = current_process_object() else {
        return Err(());
    };
    let Ok((slot_idx, alias_gen)) = resolve_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let slot_meta = with_step43_state(|state| {
        resolve_slot_mut(state, process, slot_idx, alias_gen).map(|s| *s)
    })?;
    let Some(slot) = slot_meta else {
        return Ok(Err(Errno::EBADF));
    };

    match slot.kind {
        DesktopNodeKind::DrmCard0 => handle_drm_ioctl(slot, req, arg),
        DesktopNodeKind::Fb0 => handle_fb_ioctl(slot, req, arg),
        DesktopNodeKind::InputEvent(idx) => {
            with_step43_state(|state| handle_evdev_ioctl(state, idx, slot, req, arg))
        }
        DesktopNodeKind::SndPcm0 => with_step43_state(|state| match req {
            SNDRV_PCM_IOCTL_PREPARE => {
                state.audio.prepare()?;
                Ok(0)
            }
            SNDRV_PCM_IOCTL_START => {
                state.audio.start()?;
                Ok(0)
            }
            SNDRV_PCM_IOCTL_DROP => {
                state.audio.drop_stream();
                Ok(0)
            }
            _ => Err(Errno::ENOTTY),
        }),
        DesktopNodeKind::None => Ok(Err(Errno::EBADF)),
        _ => Ok(Err(Errno::ENOTTY)),
    }
}

fn handle_drm_ioctl(slot: DesktopFdSlot, req: u64, arg: u64) -> Result<Result<i64, Errno>, ()> {
    if req == DRM_IOCTL_MODE_CREATE_DUMB {
        let mut raw = [0u8; 32];
        if let Err(e) = copy_from_user(&mut raw, arg) {
            return Ok(Err(e));
        }
        let height = u32::from_le_bytes(raw[0..4].try_into().unwrap_or([0; 4]));
        let width = u32::from_le_bytes(raw[4..8].try_into().unwrap_or([0; 4]));
        let bpp = u32::from_le_bytes(raw[8..12].try_into().unwrap_or([0; 4]));
        let (handle, pitch, size, _) =
            match allocate_and_register_dumb(slot.session_id, width, height, bpp) {
                Ok(v) => v,
                Err(e) => return Ok(Err(e)),
            };
        raw[16..20].copy_from_slice(&handle.to_le_bytes());
        raw[20..24].copy_from_slice(&pitch.to_le_bytes());
        raw[24..32].copy_from_slice(&size.to_le_bytes());
        return Ok(copy_to_user(arg, &raw).map(|()| 0));
    }

    if req == DRM_IOCTL_MODE_DESTROY_DUMB || req == DRM_IOCTL_GEM_CLOSE {
        let len = if req == DRM_IOCTL_GEM_CLOSE { 8 } else { 4 };
        let mut raw = [0u8; 8];
        if let Err(e) = copy_from_user(&mut raw[..len], arg) {
            return Ok(Err(e));
        }
        let handle = u32::from_le_bytes(raw[0..4].try_into().unwrap_or([0; 4]));
        return Ok(destroy_dumb_with_backing(slot.session_id, handle).map(|()| 0));
    }

    let mut pending_gpu_present: Option<(u32, u32, u32, bool)> = None;
    let res = with_step43_state(|state| match req {
        DRM_IOCTL_VERSION => handle_drm_version(arg),
        DRM_IOCTL_GET_UNIQUE => {
            let mut raw = [0u8; 16];
            copy_from_user(&mut raw, arg)?;
            raw[0..8].copy_from_slice(&0u64.to_le_bytes());
            copy_to_user(arg, &raw)?;
            Ok(0)
        }
        DRM_IOCTL_GET_MAGIC => {
            copy_to_user(arg, &1u32.to_le_bytes())?;
            Ok(0)
        }
        DRM_IOCTL_GET_CAP => handle_drm_get_cap(arg),
        DRM_IOCTL_SET_CLIENT_CAP => {
            let mut pair = [0u8; 16];
            copy_from_user(&mut pair, arg)?;
            let cap_id = u64::from_le_bytes(pair[0..8].try_into().unwrap_or([0; 8]));
            match cap_id {
                DRM_CLIENT_CAP_STEREO_3D | DRM_CLIENT_CAP_UNIVERSAL_PLANES => Ok(0),
                DRM_CLIENT_CAP_ATOMIC => Err(Errno::EOPNOTSUPP),
                _ => Err(Errno::EINVAL),
            }
        }
        DRM_IOCTL_SET_MASTER => {
            let active_gen = state.seat.seat_generation();
            state.seat.drm.set_master(
                DESKTOP_CTRL_CAP,
                slot.session_id,
                slot.session_gen,
                active_gen,
            )?;
            Ok(0)
        }
        DRM_IOCTL_DROP_MASTER => {
            state.seat.drm.drop_master(slot.session_id)?;
            Ok(0)
        }
        DRM_IOCTL_MODE_GETRESOURCES => handle_drm_get_resources(state, arg),
        DRM_IOCTL_MODE_GETCONNECTOR => handle_drm_get_connector(state, arg),
        DRM_IOCTL_MODE_GETENCODER => handle_drm_get_encoder(arg),
        DRM_IOCTL_MODE_GETCRTC => handle_drm_get_crtc(state, arg),
        DRM_IOCTL_MODE_SETCRTC => {
            let mut raw = [0u8; 104];
            copy_from_user(&mut raw, arg)?;
            let crtc_id = u32::from_le_bytes(raw[12..16].try_into().unwrap_or([0; 4]));
            let fb_id = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
            let x = u32::from_le_bytes(raw[20..24].try_into().unwrap_or([0; 4]));
            let y = u32::from_le_bytes(raw[24..28].try_into().unwrap_or([0; 4]));
            let mode_valid = u32::from_le_bytes(raw[32..36].try_into().unwrap_or([0; 4]));
            let mode_override = if mode_valid != 0 {
                let parsed = DrmModeInfo::from_bytes(&raw[36..104])?;
                Some(DisplayMode {
                    width: u32::from(parsed.hdisplay),
                    height: u32::from(parsed.vdisplay),
                    bpp: 32,
                    refresh_hz: parsed.vrefresh.max(60),
                })
            } else {
                None
            };
            if let Some(fb) = state.seat.drm.set_crtc_by_fb_id(SetCrtcRequest {
                session_id: slot.session_id,
                seat_generation: slot.session_gen,
                crtc_id,
                fb_id,
                x,
                y,
                mode_override,
            })? {
                pending_gpu_present = Some((
                    fb.handle,
                    state.seat.drm.mode.width,
                    state.seat.drm.mode.height,
                    true,
                ));
            }
            Ok(0)
        }
        DRM_IOCTL_MODE_ADDFB => {
            let mut raw = [0u8; 28];
            copy_from_user(&mut raw, arg)?;
            let width = u32::from_le_bytes(raw[4..8].try_into().unwrap_or([0; 4]));
            let height = u32::from_le_bytes(raw[8..12].try_into().unwrap_or([0; 4]));
            let pitch = u32::from_le_bytes(raw[12..16].try_into().unwrap_or([0; 4]));
            let bpp = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
            let depth = u32::from_le_bytes(raw[20..24].try_into().unwrap_or([0; 4]));
            let handle = u32::from_le_bytes(raw[24..28].try_into().unwrap_or([0; 4]));
            let fb = state.seat.drm.add_fb(AddFbRequest {
                session_id: slot.session_id,
                width,
                height,
                pitch,
                bpp,
                depth,
                pixel_format: DRM_FORMAT_XRGB8888,
                handle,
                offset: 0,
            })?;
            raw[0..4].copy_from_slice(&fb.fb_id.to_le_bytes());
            copy_to_user(arg, &raw)?;
            Ok(0)
        }
        DRM_IOCTL_MODE_ADDFB2 => {
            let mut raw = [0u8; 104];
            copy_from_user(&mut raw, arg)?;
            let width = u32::from_le_bytes(raw[4..8].try_into().unwrap_or([0; 4]));
            let height = u32::from_le_bytes(raw[8..12].try_into().unwrap_or([0; 4]));
            let pixel_format = u32::from_le_bytes(raw[12..16].try_into().unwrap_or([0; 4]));
            let handle = u32::from_le_bytes(raw[20..24].try_into().unwrap_or([0; 4]));
            let pitch = u32::from_le_bytes(raw[36..40].try_into().unwrap_or([0; 4]));
            let offset = u32::from_le_bytes(raw[52..56].try_into().unwrap_or([0; 4]));
            let fb = state.seat.drm.add_fb(AddFbRequest {
                session_id: slot.session_id,
                width,
                height,
                pitch,
                bpp: 32,
                depth: 24,
                pixel_format,
                handle,
                offset,
            })?;
            raw[0..4].copy_from_slice(&fb.fb_id.to_le_bytes());
            copy_to_user(arg, &raw)?;
            Ok(0)
        }
        DRM_IOCTL_MODE_RMFB => {
            let mut raw = [0u8; 4];
            copy_from_user(&mut raw, arg)?;
            let fb_id = u32::from_le_bytes(raw);
            state.seat.drm.remove_fb(fb_id)?;
            Ok(0)
        }
        DRM_IOCTL_MODE_GETFB => {
            let mut raw = [0u8; 28];
            copy_from_user(&mut raw, arg)?;
            let fb_id = u32::from_le_bytes(raw[0..4].try_into().unwrap_or([0; 4]));
            let fb = state.seat.drm.lookup_fb(fb_id).ok_or(Errno::ENOENT)?;
            raw[4..8].copy_from_slice(&fb.width.to_le_bytes());
            raw[8..12].copy_from_slice(&fb.height.to_le_bytes());
            raw[12..16].copy_from_slice(&fb.pitch.to_le_bytes());
            raw[16..20].copy_from_slice(&fb.bpp.to_le_bytes());
            raw[20..24].copy_from_slice(&fb.depth.to_le_bytes());
            raw[24..28].copy_from_slice(&fb.handle.to_le_bytes());
            copy_to_user(arg, &raw)?;
            Ok(0)
        }
        DRM_IOCTL_MODE_PAGE_FLIP => {
            let mut raw = [0u8; 24];
            copy_from_user(&mut raw, arg)?;
            let crtc_id = u32::from_le_bytes(raw[0..4].try_into().unwrap_or([0; 4]));
            let fb_id = u32::from_le_bytes(raw[4..8].try_into().unwrap_or([0; 4]));
            let flags = u32::from_le_bytes(raw[8..12].try_into().unwrap_or([0; 4]));
            let user_data = u64::from_le_bytes(raw[16..24].try_into().unwrap_or([0; 8]));
            let mono_ns = kernal_timer_aarch64::monotonic_now_ns().unwrap_or(0);
            let tv_sec = (mono_ns / 1_000_000_000) as u32;
            let tv_usec = ((mono_ns % 1_000_000_000) / 1_000) as u32;
            let fb = state.seat.drm.page_flip(PageFlipRequest {
                session_id: slot.session_id,
                seat_generation: slot.session_gen,
                crtc_id,
                fb_id,
                flags,
                user_data,
                tv_sec,
                tv_usec,
            })?;
            pending_gpu_present = Some((
                fb.handle,
                state.seat.drm.mode.width,
                state.seat.drm.mode.height,
                true,
            ));
            Ok(0)
        }
        DRM_IOCTL_MODE_DIRTYFB => {
            let mut raw = [0u8; 24];
            copy_from_user(&mut raw, arg)?;
            let fb_id = u32::from_le_bytes(raw[0..4].try_into().unwrap_or([0; 4]));
            let fb = state.seat.drm.lookup_fb(fb_id).ok_or(Errno::ENOENT)?;
            pending_gpu_present = Some((
                fb.handle,
                state.seat.drm.mode.width,
                state.seat.drm.mode.height,
                state.seat.drm.active_fb_id == Some(fb_id),
            ));
            Ok(0)
        }
        DRM_IOCTL_MODE_MAP_DUMB => {
            let mut raw = [0u8; 16];
            copy_from_user(&mut raw, arg)?;
            let handle = u32::from_le_bytes(raw[0..4].try_into().unwrap_or([0; 4]));
            let offset = state.seat.drm.map_dumb(slot.session_id, handle)?;
            raw[8..16].copy_from_slice(&offset.to_le_bytes());
            copy_to_user(arg, &raw)?;
            Ok(0)
        }
        DRM_IOCTL_MODE_GETPLANERESOURCES => {
            let mut raw = [0u8; 16];
            copy_from_user(&mut raw, arg)?;
            let plane_ptr = u64::from_le_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
            let count_in = u32::from_le_bytes(raw[8..12].try_into().unwrap_or([0; 4]));
            if plane_ptr != 0 && count_in >= 1 {
                copy_to_user(plane_ptr, &DRM_PRIMARY_PLANE_ID.to_le_bytes())?;
            }
            raw[8..12].copy_from_slice(&1u32.to_le_bytes());
            copy_to_user(arg, &raw)?;
            Ok(0)
        }
        DRM_IOCTL_MODE_GETPLANE => {
            let mut raw = [0u8; 32];
            copy_from_user(&mut raw, arg)?;
            let plane_id = u32::from_le_bytes(raw[0..4].try_into().unwrap_or([0; 4]));
            if plane_id != DRM_PRIMARY_PLANE_ID {
                return Err(Errno::ENOENT);
            }
            let fmt_ptr = u64::from_le_bytes(raw[24..32].try_into().unwrap_or([0; 8]));
            let fmt_cnt = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
            if fmt_ptr != 0 && fmt_cnt >= 2 {
                copy_to_user(fmt_ptr, &DRM_FORMAT_XRGB8888.to_le_bytes())?;
                copy_to_user(
                    fmt_ptr.saturating_add(4),
                    &DRM_FORMAT_ARGB8888.to_le_bytes(),
                )?;
            }
            raw[4..8].copy_from_slice(&DRM_CRTC_ID.to_le_bytes());
            raw[8..12].copy_from_slice(&state.seat.drm.active_fb_id.unwrap_or(0).to_le_bytes());
            raw[12..16].copy_from_slice(&1u32.to_le_bytes()); // possible_crtcs
            raw[16..20].copy_from_slice(&2u32.to_le_bytes());
            copy_to_user(arg, &raw)?;
            Ok(0)
        }
        DRM_IOCTL_MODE_OBJ_GETPROPERTIES => {
            let mut raw = [0u8; 32];
            copy_from_user(&mut raw, arg)?;
            let props_ptr = u64::from_le_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
            let vals_ptr = u64::from_le_bytes(raw[8..16].try_into().unwrap_or([0; 8]));
            let count_in = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
            let obj_id = u32::from_le_bytes(raw[20..24].try_into().unwrap_or([0; 4]));
            if obj_id == DRM_PRIMARY_PLANE_ID {
                if count_in >= 1 {
                    if props_ptr != 0 {
                        copy_to_user(props_ptr, &1u32.to_le_bytes())?;
                    }
                    if vals_ptr != 0 {
                        copy_to_user(vals_ptr, &1u64.to_le_bytes())?;
                    }
                }
                raw[16..20].copy_from_slice(&1u32.to_le_bytes());
            } else {
                raw[16..20].copy_from_slice(&0u32.to_le_bytes());
            }
            copy_to_user(arg, &raw)?;
            Ok(0)
        }
        DRM_IOCTL_MODE_GETPROPERTY => {
            let mut raw = [0u8; 64];
            copy_from_user(&mut raw, arg)?;
            let values_ptr = u64::from_le_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
            let enum_blob_ptr = u64::from_le_bytes(raw[8..16].try_into().unwrap_or([0; 8]));
            let prop_id = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
            if prop_id != 1 {
                return Err(Errno::ENOENT);
            }
            let count_values = u32::from_le_bytes(raw[56..60].try_into().unwrap_or([0; 4]));
            let count_enums = u32::from_le_bytes(raw[60..64].try_into().unwrap_or([0; 4]));
            // flags = DRM_MODE_PROP_ENUM (1 << 3) | DRM_MODE_PROP_IMMUTABLE (1 << 2) = 0x0c
            raw[20..24].copy_from_slice(&0x0cu32.to_le_bytes());
            raw[24..56].fill(0);
            raw[24..28].copy_from_slice(b"type");
            let enums: [(u64, &[u8]); 3] = [(0, b"Overlay"), (1, b"Primary"), (2, b"Cursor")];
            if values_ptr != 0 && count_values >= 3 {
                for (i, (val, _)) in enums.iter().enumerate() {
                    copy_to_user(
                        values_ptr.saturating_add((i * 8) as u64),
                        &val.to_le_bytes(),
                    )?;
                }
            }
            if enum_blob_ptr != 0 && count_enums >= 3 {
                for (i, (val, name)) in enums.iter().enumerate() {
                    let mut entry = [0u8; 40];
                    entry[0..8].copy_from_slice(&val.to_le_bytes());
                    entry[8..8 + name.len()].copy_from_slice(name);
                    copy_to_user(enum_blob_ptr.saturating_add((i * 40) as u64), &entry)?;
                }
            }
            raw[56..60].copy_from_slice(&3u32.to_le_bytes());
            raw[60..64].copy_from_slice(&3u32.to_le_bytes());
            copy_to_user(arg, &raw)?;
            Ok(0)
        }
        DRM_IOCTL_MODE_SETPROPERTY | DRM_IOCTL_MODE_GETPROPBLOB => Err(Errno::ENOENT),
        DRM_IOCTL_MODE_CURSOR | DRM_IOCTL_MODE_CURSOR2 => Ok(0),
        DRM_IOCTL_WAIT_VBLANK => {
            let mut raw = [0u8; 24];
            copy_from_user(&mut raw, arg)?;
            let seq = state.seat.drm.vblank_sequence;
            let mono_ns = kernal_timer_aarch64::monotonic_now_ns().unwrap_or(0);
            let tv_sec = (mono_ns / 1_000_000_000) as i64;
            let tv_usec = ((mono_ns % 1_000_000_000) / 1_000) as i64;
            raw[0..4].copy_from_slice(&0u32.to_le_bytes());
            raw[4..8].copy_from_slice(&seq.to_le_bytes());
            raw[8..16].copy_from_slice(&tv_sec.to_le_bytes());
            raw[16..24].copy_from_slice(&tv_usec.to_le_bytes());
            copy_to_user(arg, &raw)?;
            Ok(0)
        }
        DRM_IOCTL_PRIME_HANDLE_TO_FD | DRM_IOCTL_MODE_ATOMIC => Err(Errno::EOPNOTSUPP),
        _ => Err(Errno::ENOTTY),
    })?;

    if let Some((handle, w, h, set_scanout)) = pending_gpu_present
        && let Err(e) = present_dumb_to_gpu(handle, w, h, 0, 0, w, h, set_scanout)
    {
        return Ok(Err(e));
    }
    Ok(res)
}

fn copy_drm_string_field(dst_ptr: u64, dst_len: &mut u64, src: &[u8]) -> Result<(), Errno> {
    let cap = *dst_len as usize;
    *dst_len = src.len() as u64;
    if dst_ptr != 0 && cap > 0 {
        let take = cap.min(src.len());
        copy_to_user(dst_ptr, &src[..take])?;
    }
    Ok(())
}

fn handle_drm_version(arg: u64) -> Result<i64, Errno> {
    let mut raw = [0u8; 64];
    copy_from_user(&mut raw, arg)?;
    raw[0..4].copy_from_slice(&1i32.to_le_bytes());
    raw[4..8].copy_from_slice(&0i32.to_le_bytes());
    raw[8..12].copy_from_slice(&0i32.to_le_bytes());
    let mut name_len = u64::from_le_bytes(raw[16..24].try_into().unwrap_or([0; 8]));
    let name_ptr = u64::from_le_bytes(raw[24..32].try_into().unwrap_or([0; 8]));
    let mut date_len = u64::from_le_bytes(raw[32..40].try_into().unwrap_or([0; 8]));
    let date_ptr = u64::from_le_bytes(raw[40..48].try_into().unwrap_or([0; 8]));
    let mut desc_len = u64::from_le_bytes(raw[48..56].try_into().unwrap_or([0; 8]));
    let desc_ptr = u64::from_le_bytes(raw[56..64].try_into().unwrap_or([0; 8]));
    copy_drm_string_field(name_ptr, &mut name_len, b"virtio_gpu")?;
    copy_drm_string_field(date_ptr, &mut date_len, b"0")?;
    copy_drm_string_field(desc_ptr, &mut desc_len, b"virtio GPU")?;
    raw[16..24].copy_from_slice(&name_len.to_le_bytes());
    raw[32..40].copy_from_slice(&date_len.to_le_bytes());
    raw[48..56].copy_from_slice(&desc_len.to_le_bytes());
    copy_to_user(arg, &raw)?;
    Ok(0)
}

fn handle_drm_get_cap(arg: u64) -> Result<i64, Errno> {
    let mut pair = [0u8; 16];
    copy_from_user(&mut pair, arg)?;
    let cap_id = u64::from_le_bytes(pair[0..8].try_into().unwrap_or([0; 8]));
    let val: u64 = match cap_id {
        DRM_CAP_DUMB_BUFFER => 1,
        DRM_CAP_VBLANK_HIGH_CRTC => 1,
        DRM_CAP_DUMB_PREFERRED_DEPTH => 24,
        DRM_CAP_DUMB_PREFER_SHADOW => 0,
        DRM_CAP_PRIME => 0,
        DRM_CAP_TIMESTAMP_MONOTONIC => 1,
        DRM_CAP_ASYNC_PAGE_FLIP => 1,
        DRM_CAP_CURSOR_WIDTH | DRM_CAP_CURSOR_HEIGHT => 64,
        DRM_CAP_ADDFB2_MODIFIERS => 0,
        DRM_CAP_CRTC_IN_VBLANK_EVENT => 1,
        _ => 0,
    };
    pair[8..16].copy_from_slice(&val.to_le_bytes());
    copy_to_user(arg, &pair)?;
    Ok(0)
}

fn write_u32_array_if_room(ptr: u64, cap: u32, items: &[u32]) -> Result<u32, Errno> {
    if ptr != 0 && cap > 0 {
        let take = (cap as usize).min(items.len());
        for (i, item) in items[..take].iter().enumerate() {
            copy_to_user(ptr.saturating_add((i * 4) as u64), &item.to_le_bytes())?;
        }
    }
    Ok(items.len() as u32)
}

fn handle_drm_get_resources(state: &Step43State, arg: u64) -> Result<i64, Errno> {
    let mut raw = [0u8; 64];
    copy_from_user(&mut raw, arg)?;
    let fb_ptr = u64::from_le_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
    let crtc_ptr = u64::from_le_bytes(raw[8..16].try_into().unwrap_or([0; 8]));
    let conn_ptr = u64::from_le_bytes(raw[16..24].try_into().unwrap_or([0; 8]));
    let enc_ptr = u64::from_le_bytes(raw[24..32].try_into().unwrap_or([0; 8]));

    let mut fbs = [0u32; 16];
    let fb_total = state.seat.drm.active_fb_ids(&mut fbs);
    let fb_cnt = write_u32_array_if_room(
        fb_ptr,
        u32::from_le_bytes(raw[32..36].try_into().unwrap_or([0; 4])),
        &fbs[..fb_total],
    )?;
    let crtc_cnt = write_u32_array_if_room(
        crtc_ptr,
        u32::from_le_bytes(raw[36..40].try_into().unwrap_or([0; 4])),
        &[DRM_CRTC_ID],
    )?;
    let conn_cnt = write_u32_array_if_room(
        conn_ptr,
        u32::from_le_bytes(raw[40..44].try_into().unwrap_or([0; 4])),
        &[DRM_CONNECTOR_ID],
    )?;
    let enc_cnt = write_u32_array_if_room(
        enc_ptr,
        u32::from_le_bytes(raw[44..48].try_into().unwrap_or([0; 4])),
        &[DRM_ENCODER_ID],
    )?;
    raw[32..36].copy_from_slice(&fb_cnt.to_le_bytes());
    raw[36..40].copy_from_slice(&crtc_cnt.to_le_bytes());
    raw[40..44].copy_from_slice(&conn_cnt.to_le_bytes());
    raw[44..48].copy_from_slice(&enc_cnt.to_le_bytes());
    raw[48..52].copy_from_slice(&320u32.to_le_bytes());
    raw[52..56].copy_from_slice(&4096u32.to_le_bytes());
    raw[56..60].copy_from_slice(&200u32.to_le_bytes());
    raw[60..64].copy_from_slice(&4096u32.to_le_bytes());
    copy_to_user(arg, &raw)?;
    Ok(0)
}

fn handle_drm_get_connector(state: &Step43State, arg: u64) -> Result<i64, Errno> {
    let mut raw = [0u8; 80];
    copy_from_user(&mut raw, arg)?;
    let conn_id = u32::from_le_bytes(raw[48..52].try_into().unwrap_or([0; 4]));
    if conn_id != DRM_CONNECTOR_ID {
        return Err(Errno::ENOENT);
    }
    let encoders_ptr = u64::from_le_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
    let modes_ptr = u64::from_le_bytes(raw[8..16].try_into().unwrap_or([0; 8]));
    let count_modes = u32::from_le_bytes(raw[32..36].try_into().unwrap_or([0; 4]));
    let count_encoders = u32::from_le_bytes(raw[40..44].try_into().unwrap_or([0; 4]));

    let _ = write_u32_array_if_room(encoders_ptr, count_encoders, &[DRM_ENCODER_ID])?;
    if modes_ptr != 0 && count_modes >= 1 {
        let mode = DrmModeInfo::from_display_mode(state.seat.drm.mode);
        copy_to_user(modes_ptr, &mode.to_bytes())?;
    }
    let mm_w = state.seat.drm.mode.width.saturating_mul(254) / 960;
    let mm_h = state.seat.drm.mode.height.saturating_mul(254) / 960;

    raw[32..36].copy_from_slice(&1u32.to_le_bytes()); // count_modes
    raw[36..40].copy_from_slice(&0u32.to_le_bytes()); // count_props
    raw[40..44].copy_from_slice(&1u32.to_le_bytes()); // count_encoders
    raw[44..48].copy_from_slice(&DRM_ENCODER_ID.to_le_bytes());
    raw[52..56].copy_from_slice(&DRM_MODE_CONNECTOR_VIRTUAL.to_le_bytes());
    raw[56..60].copy_from_slice(&1u32.to_le_bytes()); // connector_type_id
    raw[60..64].copy_from_slice(&DRM_MODE_CONNECTED.to_le_bytes());
    raw[64..68].copy_from_slice(&mm_w.to_le_bytes());
    raw[68..72].copy_from_slice(&mm_h.to_le_bytes());
    raw[72..76].copy_from_slice(&1u32.to_le_bytes()); // subpixel = unknown
    copy_to_user(arg, &raw)?;
    Ok(0)
}

fn handle_drm_get_encoder(arg: u64) -> Result<i64, Errno> {
    let mut raw = [0u8; 20];
    copy_from_user(&mut raw, arg)?;
    let enc_id = u32::from_le_bytes(raw[0..4].try_into().unwrap_or([0; 4]));
    if enc_id != DRM_ENCODER_ID {
        return Err(Errno::ENOENT);
    }
    raw[4..8].copy_from_slice(&DRM_MODE_ENCODER_VIRTUAL.to_le_bytes());
    raw[8..12].copy_from_slice(&DRM_CRTC_ID.to_le_bytes());
    raw[12..16].copy_from_slice(&1u32.to_le_bytes()); // possible_crtcs
    raw[16..20].copy_from_slice(&0u32.to_le_bytes()); // possible_clones
    copy_to_user(arg, &raw)?;
    Ok(0)
}

fn handle_drm_get_crtc(state: &Step43State, arg: u64) -> Result<i64, Errno> {
    let mut raw = [0u8; 104];
    copy_from_user(&mut raw, arg)?;
    let crtc_id = u32::from_le_bytes(raw[12..16].try_into().unwrap_or([0; 4]));
    if crtc_id != DRM_CRTC_ID {
        return Err(Errno::ENOENT);
    }
    raw[16..20].copy_from_slice(&state.seat.drm.active_fb_id.unwrap_or(0).to_le_bytes());
    raw[20..24].copy_from_slice(&state.seat.drm.crtc_x.to_le_bytes());
    raw[24..28].copy_from_slice(&state.seat.drm.crtc_y.to_le_bytes());
    raw[28..32].copy_from_slice(&0u32.to_le_bytes());
    raw[32..36].copy_from_slice(&u32::from(state.seat.drm.mode_valid).to_le_bytes());
    if state.seat.drm.mode_valid {
        let mode = DrmModeInfo::from_display_mode(state.seat.drm.mode);
        raw[36..104].copy_from_slice(&mode.to_bytes());
    }
    copy_to_user(arg, &raw)?;
    Ok(0)
}

fn handle_fb_ioctl(slot: DesktopFdSlot, req: u64, arg: u64) -> Result<Result<i64, Errno>, ()> {
    if req == FBIOPAN_DISPLAY {
        let (handle, w, h) = match ensure_fb0_dumb(slot.session_id) {
            Ok(v) => v,
            Err(e) => return Ok(Err(e)),
        };
        return Ok(present_dumb_to_gpu(handle, w, h, 0, 0, w, h, true).map(|()| 0));
    }
    with_step43_state(|state| {
        let mode = state.seat.drm.mode;
        match req {
            FBIOGET_VSCREENINFO => {
                let mut vinfo = [0u8; 160];
                vinfo[0..4].copy_from_slice(&mode.width.to_le_bytes());
                vinfo[4..8].copy_from_slice(&mode.height.to_le_bytes());
                vinfo[8..12].copy_from_slice(&mode.width.to_le_bytes());
                vinfo[12..16].copy_from_slice(&mode.height.to_le_bytes());
                vinfo[24..28].copy_from_slice(&mode.bpp.to_le_bytes());
                // XRGB8888: B@0:8, G@8:8, R@16:8
                vinfo[32..36].copy_from_slice(&16u32.to_le_bytes());
                vinfo[36..40].copy_from_slice(&8u32.to_le_bytes());
                vinfo[44..48].copy_from_slice(&8u32.to_le_bytes());
                vinfo[48..52].copy_from_slice(&8u32.to_le_bytes());
                vinfo[56..60].copy_from_slice(&0u32.to_le_bytes());
                vinfo[60..64].copy_from_slice(&8u32.to_le_bytes());
                copy_to_user(arg, &vinfo)?;
                Ok(0)
            }
            FBIOGET_FSCREENINFO => {
                let mut finfo = [0u8; 80];
                let id = b"virtiodrmfb\0";
                finfo[..id.len()].copy_from_slice(id);
                let line_len = mode.width.saturating_mul(mode.bpp / 8);
                let smem_len = line_len.saturating_mul(mode.height);
                finfo[24..28].copy_from_slice(&smem_len.to_le_bytes());
                finfo[32..36].copy_from_slice(&2u32.to_le_bytes()); // FB_VISUAL_TRUECOLOR
                finfo[44..48].copy_from_slice(&line_len.to_le_bytes());
                copy_to_user(arg, &finfo)?;
                Ok(0)
            }
            _ => Err(Errno::ENOTTY),
        }
    })
}

fn handle_evdev_ioctl(
    state: &mut Step43State,
    idx: u8,
    slot: DesktopFdSlot,
    req: u64,
    arg: u64,
) -> Result<i64, Errno> {
    let Some(decoded) = EvdevIoctl::decode(req) else {
        return Err(Errno::ENOTTY);
    };
    let dev_idx = usize::from(idx);
    if dev_idx >= state.input_count {
        return Err(Errno::ENODEV);
    }
    let meta = state.seat.evdevs[dev_idx].meta;
    match decoded {
        EvdevIoctl::GetVersion => {
            copy_to_user(arg, &0x01_0001u32.to_le_bytes())?;
            Ok(0)
        }
        EvdevIoctl::GetId => {
            let id = meta.encode_id();
            copy_to_user(arg, &id)?;
            Ok(0)
        }
        EvdevIoctl::GetRep => {
            let mut rep = [0u8; 8];
            rep[0..4].copy_from_slice(&250u32.to_le_bytes());
            rep[4..8].copy_from_slice(&33u32.to_le_bytes());
            copy_to_user(arg, &rep)?;
            Ok(0)
        }
        EvdevIoctl::GetName(len) => {
            let mut out = [0u8; 128];
            let copy_len = meta.name_len.min(out.len().saturating_sub(1));
            out[..copy_len].copy_from_slice(&meta.name[..copy_len]);
            let total = (copy_len + 1).min(len.max(1)).min(out.len());
            copy_to_user(arg, &out[..total])?;
            Ok(total as i64)
        }
        EvdevIoctl::GetPhys(len) => {
            let mut phys = [0u8; 32];
            let pfx = b"virtio-mmio/input";
            phys[..pfx.len()].copy_from_slice(pfx);
            phys[pfx.len()] = b'0' + idx;
            let total = (pfx.len() + 2).min(len.max(1)).min(phys.len());
            copy_to_user(arg, &phys[..total])?;
            Ok(total as i64)
        }
        EvdevIoctl::GetUniq(len) => {
            if len > 0 {
                copy_to_user(arg, &[0u8])?;
            }
            Ok(1)
        }
        EvdevIoctl::GetProp(len) => {
            let take = len.min(meta.prop_bits.len());
            if take > 0 {
                copy_to_user(arg, &meta.prop_bits[..take])?;
            }
            Ok(take as i64)
        }
        EvdevIoctl::GetMtSlots(_) => Ok(0),
        EvdevIoctl::GetStateBits { len, .. } => {
            let zeros = [0u8; 128];
            let take = len.min(zeros.len());
            if take > 0 {
                copy_to_user(arg, &zeros[..take])?;
            }
            Ok(take as i64)
        }
        EvdevIoctl::GetBit { ev_type, len } => {
            let mut buf = [0u8; 128];
            let take = len.min(buf.len());
            let _ = meta.copy_ev_bitmask(ev_type, &mut buf[..take]);
            if take > 0 {
                copy_to_user(arg, &buf[..take])?;
            }
            Ok(take as i64)
        }
        EvdevIoctl::GetAbs { axis } => {
            let info = match axis {
                0 => meta.abs_x,
                1 => meta.abs_y,
                _ => InputAbsAxisInfo::default(),
            };
            copy_to_user(arg, &info.encode())?;
            Ok(0)
        }
        EvdevIoctl::GetEffects => {
            copy_to_user(arg, &0i32.to_le_bytes())?;
            Ok(0)
        }
        EvdevIoctl::Grab => {
            state.seat.evdevs[dev_idx].grab(
                slot.session_id,
                slot.session_gen,
                state.seat.active_session(),
                arg != 0,
            )?;
            Ok(0)
        }
        EvdevIoctl::RevokeOrMask => Ok(0),
        EvdevIoctl::SetClockId => {
            let mut raw = [0u8; 4];
            copy_from_user(&mut raw, arg)?;
            state.evdev_clock_ids[dev_idx] = i32::from_le_bytes(raw);
            Ok(0)
        }
    }
}

fn handle_lseek(raw_fd: u64, offset: i64, whence: i32) -> Result<Result<i64, Errno>, ()> {
    let Some(process) = current_process_object() else {
        return Err(());
    };
    let Ok((slot_idx, alias_gen)) = resolve_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    with_step43_state(|state| {
        let Some(slot) = resolve_slot_mut(state, process, slot_idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        let slot_copy = *slot;
        match slot_copy.kind {
            DesktopNodeKind::Seat0Status => {
                let mut data = [0u8; 128];
                let total = state.seat.format_seat0_status(&mut data)?;
                let next = seek_bounded(slot_copy.offset, total, offset, whence)?;
                if let Some(s) = resolve_slot_mut(state, process, slot_idx, alias_gen) {
                    s.offset = next;
                }
                Ok(next as i64)
            }
            DesktopNodeKind::Fb0 => {
                let total = (u64::from(state.seat.drm.mode.width)
                    * u64::from(state.seat.drm.mode.height)
                    * 4) as usize;
                let next = seek_bounded(slot_copy.offset, total, offset, whence)?;
                if let Some(s) = resolve_slot_mut(state, process, slot_idx, alias_gen) {
                    s.offset = next;
                }
                Ok(next as i64)
            }
            DesktopNodeKind::None => Err(Errno::EBADF),
            _ => Err(Errno::ESPIPE),
        }
    })
}

fn handle_close(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    let Some(process) = current_process_object() else {
        return Err(());
    };
    if !is_desktop_fd(raw_fd) {
        return Ok(Err(Errno::EBADF));
    }
    let idx = (linux_signed_int(raw_fd) - DESKTOP_FD_BASE) as usize;
    with_step43_state(|state| {
        let Some(entry) = resolve_slot_mut(state, process, idx, None) else {
            return Err(Errno::EBADF);
        };
        if !entry.owners.close_owner(process) {
            return Err(Errno::EBADF);
        }
        retire_slot_if_unused(state, idx);
        Ok(0)
    })
}

fn handle_fstat(raw_fd: u64, user_stat: u64) -> Result<Result<i64, Errno>, ()> {
    let Some(process) = current_process_object() else {
        return Err(());
    };
    let Ok((slot_idx, alias_gen)) = resolve_slot_idx(process, raw_fd) else {
        return Ok(Err(Errno::EBADF));
    };
    let meta = with_step43_state(|state| {
        let Some(entry) = resolve_slot_mut(state, process, slot_idx, alias_gen) else {
            return Err(Errno::EBADF);
        };
        let kind = entry.kind;
        Ok(desktop_stat_meta(state, kind))
    })?;
    match meta {
        Ok(m) => Ok(write_aarch64_stat_meta(user_stat, &m)),
        Err(e) => Ok(Err(e)),
    }
}

fn lookup_desktop_stat_meta(
    dirfd: u64,
    user_path: u64,
    flags: u64,
) -> Result<Option<Result<StatMeta, Errno>>, ()> {
    let mut path_buf = [0u8; 64];
    let len = if user_path == 0 {
        0
    } else {
        let Ok(len) = read_user_cstr(user_path, &mut path_buf) else {
            return Ok(None);
        };
        len
    };
    if len == 0 && (flags & AT_EMPTY_PATH) != 0 && is_desktop_fd_or_alias(dirfd) {
        let Some(process) = current_process_object() else {
            return Err(());
        };
        let Ok((slot_idx, alias_gen)) = resolve_slot_idx(process, dirfd) else {
            return Ok(Some(Err(Errno::EBADF)));
        };
        let meta = with_step43_state(|state| {
            let Some(entry) = resolve_slot_mut(state, process, slot_idx, alias_gen) else {
                return Err(Errno::EBADF);
            };
            let kind = entry.kind;
            Ok(desktop_stat_meta(state, kind))
        })?;
        return Ok(Some(meta));
    }
    let path = &path_buf[..len];
    Ok(with_step43_state(|state| {
        match_desktop_path(state, path).map(|kind| Ok(desktop_stat_meta(state, kind)))
    })?)
}

fn handle_newfstatat_if_desktop(
    dirfd: u64,
    user_path: u64,
    user_stat: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let Some(res) = lookup_desktop_stat_meta(dirfd, user_path, flags)? else {
        return Ok(None);
    };
    let out = match res {
        Ok(m) => write_aarch64_stat_meta(user_stat, &m),
        Err(e) => Err(e),
    };
    Ok(Some(encode_result(out)))
}

fn handle_statx_if_desktop(
    dirfd: u64,
    user_path: u64,
    flags: u64,
    user_statx: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let Some(res) = lookup_desktop_stat_meta(dirfd, user_path, flags)? else {
        return Ok(None);
    };
    let out = match res {
        Ok(m) => write_aarch64_statx_meta(user_statx, &m),
        Err(e) => Err(e),
    };
    Ok(Some(encode_result(out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_fd_window_and_device_numbers_are_valid() {
        assert!(!is_desktop_fd(240));
        assert!(!is_desktop_fd(255));
        assert!(is_desktop_fd(DESKTOP_FD_BASE as u64));
        assert!(is_desktop_fd((DESKTOP_FD_BASE + 15) as u64));
        assert!(!is_desktop_fd((DESKTOP_FD_BASE + 16) as u64));

        assert_eq!(DesktopNodeKind::DrmCard0.rdev_and_ino().0, 226 << 8);
        assert_eq!(DesktopNodeKind::Fb0.rdev_and_ino().0, 29 << 8);
        assert_eq!(
            DesktopNodeKind::InputEvent(1).rdev_and_ino().0,
            (13 << 8) | 65
        );
    }
}
