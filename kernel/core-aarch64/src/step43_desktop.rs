// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::step_fd_util::{
    S_IFCHR_MODE, S_IFREG_MODE, copy_from_user, copy_to_user, encode_result, read_user_cstr,
    seek_bounded, write_aarch64_stat,
};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_capability::{CapRights, Capability, ObjectId};
use kernal_linux_abi::{Errno, SyscallRequest, SyscallReturn, linux_signed_int};
use kernal_linux_desktop::{
    DRM_CAP_DUMB_BUFFER, DRM_IOCTL_DROP_MASTER, DRM_IOCTL_GET_CAP, DRM_IOCTL_MODE_CREATE_DUMB,
    DRM_IOCTL_MODE_DESTROY_DUMB, DRM_IOCTL_MODE_GETRESOURCES, DRM_IOCTL_MODE_MAP_DUMB,
    DRM_IOCTL_SET_MASTER, DRM_IOCTL_VERSION, EVIOCGNAME, EVIOCGRAB, EVIOCGVERSION,
    FBIOGET_VSCREENINFO, PcmAudioDevice, PcmFormat, PcmParams, SNDRV_PCM_IOCTL_DROP,
    SNDRV_PCM_IOCTL_PREPARE, SNDRV_PCM_IOCTL_START, SeatManager,
};

/// Dedicated file-descriptor base for optional Step-43 desktop DRM/evdev/audio/seat descriptors
/// (`256..272`), cleanly isolated above `HW_FD_BASE` (`240..256`).
pub(super) const DESKTOP_FD_BASE: i32 = 256;
const MAX_DESKTOP_FDS: usize = 16;

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
    InputEvent0,
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
}

#[derive(Clone, Copy)]
struct DesktopFdSlot {
    kind: DesktopNodeKind,
    session_id: u32,
    session_gen: u32,
    offset: usize,
}

impl DesktopFdSlot {
    const EMPTY: Self = Self {
        kind: DesktopNodeKind::None,
        session_id: 0,
        session_gen: 0,
        offset: 0,
    };
}

struct Step43State {
    initialized: bool,
    seat: SeatManager,
    audio: PcmAudioDevice,
    default_session_id: u32,
    default_session_gen: u32,
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
            fds: [DesktopFdSlot::EMPTY; MAX_DESKTOP_FDS],
        }
    }

    fn ensure_initialized(&mut self) {
        if !self.initialized {
            if let Ok(opened) = self.seat.open_session(DESKTOP_CTRL_CAP, 0, 1)
                && let Ok(active) = self
                    .seat
                    .activate_session(DESKTOP_CTRL_CAP, opened.session_id)
            {
                self.default_session_id = active.session_id;
                self.default_session_gen = active.generation;
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
    }
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

fn desktop_fd_idx(raw_fd: u64) -> Result<usize, Errno> {
    if !is_desktop_fd(raw_fd) {
        return Err(Errno::EBADF);
    }
    Ok((linux_signed_int(raw_fd) - DESKTOP_FD_BASE) as usize)
}

fn match_desktop_path(path: &[u8]) -> Option<DesktopNodeKind> {
    match path {
        b"/dev/dri/card0" => Some(DesktopNodeKind::DrmCard0),
        b"/dev/fb0" => Some(DesktopNodeKind::Fb0),
        b"/dev/input/event0" => Some(DesktopNodeKind::InputEvent0),
        b"/dev/snd/pcmC0D0p" => Some(DesktopNodeKind::SndPcm0),
        b"/run/systemd/seats/seat0" => Some(DesktopNodeKind::Seat0Status),
        _ => None,
    }
}

pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        29 if is_desktop_fd(request.args[0]) => Ok(Some(encode_result(handle_ioctl(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        56 => handle_openat_if_desktop(request.args[1]),
        57 if is_desktop_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_close(request.args[0])?)))
        }
        62 if is_desktop_fd(request.args[0]) => Ok(Some(encode_result(handle_lseek(
            request.args[0],
            request.args[1] as i64,
            linux_signed_int(request.args[2]),
        )?))),
        63 if is_desktop_fd(request.args[0]) => Ok(Some(encode_result(handle_read(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        64 if is_desktop_fd(request.args[0]) => Ok(Some(encode_result(handle_write(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        79 => handle_newfstatat_if_desktop(request.args[1], request.args[2]),
        80 if is_desktop_fd(request.args[0]) => Ok(Some(encode_result(handle_fstat(
            request.args[0],
            request.args[1],
        )?))),
        _ => Ok(None),
    }
}

fn handle_openat_if_desktop(user_path: u64) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; 64];
    let Ok(len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    let Some(kind) = match_desktop_path(&path_buf[..len]) else {
        return Ok(None);
    };
    let res = with_step43_state(|state| {
        let Some((idx, slot)) = state
            .fds
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.kind == DesktopNodeKind::None)
        else {
            return Err(Errno::EMFILE);
        };
        *slot = DesktopFdSlot {
            kind,
            session_id: state.default_session_id,
            session_gen: state.default_session_gen,
            offset: 0,
        };
        Ok(i64::from(DESKTOP_FD_BASE + (idx as i32)))
    })?;
    Ok(Some(encode_result(res)))
}

fn handle_read(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match desktop_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step43_state(|state| {
        let slot = state.fds[idx];
        match slot.kind {
            DesktopNodeKind::None => Err(Errno::EBADF),
            DesktopNodeKind::Seat0Status => {
                let mut data = [0u8; 128];
                let total = state.seat.format_seat0_status(&mut data)?;
                let avail = &data[slot.offset.min(total)..total];
                let take = avail.len().min(count as usize);
                if take > 0 {
                    copy_to_user(user_buf, &avail[..take])?;
                    state.fds[idx].offset += take;
                }
                Ok(take as i64)
            }
            DesktopNodeKind::InputEvent0 => {
                let ev = state.seat.evdev.read_event(
                    slot.session_id,
                    slot.session_gen,
                    state.seat.active_session(),
                )?;
                let encoded = ev.encode();
                if (count as usize) < encoded.len() {
                    return Err(Errno::EINVAL);
                }
                copy_to_user(user_buf, &encoded)?;
                Ok(encoded.len() as i64)
            }
            _ => Err(Errno::EINVAL),
        }
    })
}

fn handle_write(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match desktop_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step43_state(|state| {
        let slot = state.fds[idx];
        match slot.kind {
            DesktopNodeKind::None => Err(Errno::EBADF),
            DesktopNodeKind::SndPcm0 => {
                let mut buf = [0u8; 256];
                let take = (count as usize).min(buf.len());
                copy_from_user(&mut buf[..take], user_buf)?;
                let _frames = state.audio.write_frames(DESKTOP_CTRL_CAP, &buf[..take])?;
                Ok(take as i64)
            }
            _ => Err(Errno::EROFS),
        }
    })
}

fn handle_ioctl(raw_fd: u64, req: u64, arg: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match desktop_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step43_state(|state| {
        let slot = state.fds[idx];
        match slot.kind {
            DesktopNodeKind::DrmCard0 => match req {
                DRM_IOCTL_VERSION => {
                    let mut out = [0u8; 64];
                    out[0..4].copy_from_slice(&1i32.to_le_bytes());
                    out[4..8].copy_from_slice(&0i32.to_le_bytes());
                    copy_to_user(arg, &out)?;
                    Ok(0)
                }
                DRM_IOCTL_GET_CAP => {
                    let mut pair = [0u8; 16];
                    copy_from_user(&mut pair, arg)?;
                    let cap_id = u64::from_le_bytes(pair[0..8].try_into().unwrap_or([0; 8]));
                    let val = if cap_id == DRM_CAP_DUMB_BUFFER {
                        1u64
                    } else {
                        0u64
                    };
                    pair[8..16].copy_from_slice(&val.to_le_bytes());
                    copy_to_user(arg, &pair)?;
                    Ok(0)
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
                DRM_IOCTL_MODE_GETRESOURCES => Ok(0),
                DRM_IOCTL_MODE_CREATE_DUMB => {
                    let mut raw = [0u8; 32];
                    copy_from_user(&mut raw, arg)?;
                    let height = u32::from_le_bytes(raw[0..4].try_into().unwrap_or([0; 4]));
                    let width = u32::from_le_bytes(raw[4..8].try_into().unwrap_or([0; 4]));
                    let bpp = u32::from_le_bytes(raw[8..12].try_into().unwrap_or([0; 4]));
                    let created =
                        state
                            .seat
                            .drm
                            .create_dumb(slot.session_id, width, height, bpp)?;
                    raw[16..20].copy_from_slice(&created.handle.to_le_bytes());
                    raw[20..24].copy_from_slice(&created.pitch.to_le_bytes());
                    raw[24..32].copy_from_slice(&created.size.to_le_bytes());
                    copy_to_user(arg, &raw)?;
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
                DRM_IOCTL_MODE_DESTROY_DUMB => {
                    let mut raw = [0u8; 4];
                    copy_from_user(&mut raw, arg)?;
                    let handle = u32::from_le_bytes(raw);
                    state.seat.drm.destroy_dumb(slot.session_id, handle)?;
                    Ok(0)
                }
                _ => Err(Errno::ENOTTY),
            },
            DesktopNodeKind::Fb0 => match req {
                FBIOGET_VSCREENINFO => {
                    let mut vinfo = [0u8; 16];
                    vinfo[0..4].copy_from_slice(&state.seat.drm.mode.width.to_le_bytes());
                    vinfo[4..8].copy_from_slice(&state.seat.drm.mode.height.to_le_bytes());
                    copy_to_user(arg, &vinfo)?;
                    Ok(0)
                }
                _ => Err(Errno::ENOTTY),
            },
            DesktopNodeKind::InputEvent0 => match req {
                EVIOCGVERSION => {
                    copy_to_user(arg, &0x01_0001u32.to_le_bytes())?;
                    Ok(0)
                }
                EVIOCGNAME => {
                    let name = b"kernal-virt-input\0";
                    copy_to_user(arg, name)?;
                    Ok(name.len() as i64)
                }
                EVIOCGRAB => {
                    state.seat.evdev.grab(
                        slot.session_id,
                        slot.session_gen,
                        state.seat.active_session(),
                        arg != 0,
                    )?;
                    Ok(0)
                }
                _ => Err(Errno::ENOTTY),
            },
            DesktopNodeKind::SndPcm0 => match req {
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
            },
            DesktopNodeKind::None => Err(Errno::EBADF),
            _ => Err(Errno::ENOTTY),
        }
    })
}

fn handle_lseek(raw_fd: u64, offset: i64, whence: i32) -> Result<Result<i64, Errno>, ()> {
    let idx = match desktop_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step43_state(|state| {
        let slot = state.fds[idx];
        match slot.kind {
            DesktopNodeKind::Seat0Status => {
                let mut data = [0u8; 128];
                let total = state.seat.format_seat0_status(&mut data)?;
                let next = seek_bounded(slot.offset, total, offset, whence)?;
                state.fds[idx].offset = next;
                Ok(next as i64)
            }
            DesktopNodeKind::None => Err(Errno::EBADF),
            _ => Err(Errno::ESPIPE),
        }
    })
}

fn handle_close(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match desktop_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step43_state(|state| {
        if state.fds[idx].kind == DesktopNodeKind::None {
            return Err(Errno::EBADF);
        }
        state.fds[idx] = DesktopFdSlot::EMPTY;
        Ok(0)
    })
}

fn handle_fstat(raw_fd: u64, user_stat: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match desktop_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let meta = with_step43_state(|state| {
        let kind = state.fds[idx].kind;
        if kind == DesktopNodeKind::None {
            return Err(Errno::EBADF);
        }
        let sz = if kind == DesktopNodeKind::Seat0Status {
            let mut data = [0u8; 128];
            state.seat.format_seat0_status(&mut data)? as u64
        } else {
            0
        };
        Ok((kind.stat_mode(), sz))
    })?;
    match meta {
        Ok((mode, sz)) => Ok(write_aarch64_stat(user_stat, mode, sz)),
        Err(e) => Ok(Err(e)),
    }
}

fn handle_newfstatat_if_desktop(
    user_path: u64,
    user_stat: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; 64];
    let Ok(len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    let Some(kind) = match_desktop_path(&path_buf[..len]) else {
        return Ok(None);
    };
    let sz = with_step43_state(|state| {
        if kind == DesktopNodeKind::Seat0Status {
            let mut data = [0u8; 128];
            state.seat.format_seat0_status(&mut data).unwrap_or(0) as u64
        } else {
            0
        }
    })?;
    Ok(Some(encode_result(write_aarch64_stat(
        user_stat,
        kind.stat_mode(),
        sz,
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_fd_window_is_disjoint() {
        assert!(!is_desktop_fd(240));
        assert!(!is_desktop_fd(255));
        assert!(is_desktop_fd(DESKTOP_FD_BASE as u64));
        assert!(is_desktop_fd((DESKTOP_FD_BASE + 15) as u64));
        assert!(!is_desktop_fd((DESKTOP_FD_BASE + 16) as u64));
    }
}
