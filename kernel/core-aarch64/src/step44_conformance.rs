// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::step_fd_util::{
    S_IFREG_MODE, copy_to_user, encode_result, read_user_cstr, seek_bounded, write_aarch64_stat,
};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_linux_abi::{Errno, SyscallRequest, SyscallReturn, linux_signed_int};
use kernal_linux_conformance::run_all_gates;

/// Dedicated read-only file-descriptor base for Step-44 conformance & release-gate status
/// (`/proc/kernal/conformance` at `272..280`), cleanly partitioned above `DESKTOP_FD_BASE`.
pub(super) const CONFORMANCE_FD_BASE: i32 = 272;
const MAX_CONFORMANCE_FDS: usize = 8;
const CONFORMANCE_PATH: &[u8] = b"/proc/kernal/conformance";

#[derive(Clone, Copy)]
struct ConformanceFdSlot {
    open: bool,
    offset: usize,
}

impl ConformanceFdSlot {
    const EMPTY: Self = Self {
        open: false,
        offset: 0,
    };
}

struct Step44State {
    cached_len: usize,
    cached_report: [u8; 512],
    fds: [ConformanceFdSlot; MAX_CONFORMANCE_FDS],
}

impl Step44State {
    const fn new() -> Self {
        Self {
            cached_len: 0,
            cached_report: [0u8; 512],
            fds: [ConformanceFdSlot::EMPTY; MAX_CONFORMANCE_FDS],
        }
    }

    fn ensure_report(&mut self) -> usize {
        if self.cached_len == 0 {
            let report = run_all_gates();
            self.cached_len = report.format_summary(&mut self.cached_report);
        }
        self.cached_len
    }
}

struct Step44Cell {
    state: AtomicU8,
    value: UnsafeCell<Step44State>,
}

// SAFETY: lower-EL trap dispatch serializes access cleanly via atomic `0 -> 1 -> 0`.
unsafe impl Sync for Step44Cell {}

static STEP44_STATE: Step44Cell = Step44Cell {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(Step44State::new()),
};

fn with_step44_state<R>(f: impl FnOnce(&mut Step44State) -> R) -> Result<R, ()> {
    if STEP44_STATE
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(());
    }
    // SAFETY: state `1` provides exclusive mutable access inside this synchronous handler scope.
    let state = unsafe { &mut *STEP44_STATE.value.get() };
    let res = f(state);
    STEP44_STATE.state.store(0, Ordering::Release);
    Ok(res)
}

pub(super) const fn is_conformance_fd(raw_fd: u64) -> bool {
    let fd = linux_signed_int(raw_fd);
    fd >= CONFORMANCE_FD_BASE && fd < CONFORMANCE_FD_BASE + (MAX_CONFORMANCE_FDS as i32)
}

pub(super) fn is_open_conformance_fd(raw_fd: u64) -> bool {
    let Ok(idx) = conformance_fd_idx(raw_fd) else {
        return false;
    };
    with_step44_state(|state| state.fds[idx].open).unwrap_or(false)
}

fn conformance_fd_idx(raw_fd: u64) -> Result<usize, Errno> {
    if !is_conformance_fd(raw_fd) {
        return Err(Errno::EBADF);
    }
    Ok((linux_signed_int(raw_fd) - CONFORMANCE_FD_BASE) as usize)
}

pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        56 => handle_openat_if_conformance(request.args[1], request.args[2]),
        57 if is_conformance_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_close(request.args[0])?)))
        }
        62 if is_conformance_fd(request.args[0]) => Ok(Some(encode_result(handle_lseek(
            request.args[0],
            request.args[1] as i64,
            linux_signed_int(request.args[2]),
        )?))),
        63 if is_conformance_fd(request.args[0]) => Ok(Some(encode_result(handle_read(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        64 if is_conformance_fd(request.args[0]) => Ok(Some(SyscallReturn::error(Errno::EROFS))),
        79 => handle_newfstatat_if_conformance(request.args[1], request.args[2]),
        80 if is_conformance_fd(request.args[0]) => Ok(Some(encode_result(handle_fstat(
            request.args[0],
            request.args[1],
        )?))),
        _ => Ok(None),
    }
}

fn handle_openat_if_conformance(user_path: u64, flags: u64) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; 64];
    let Ok(len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    if &path_buf[..len] != CONFORMANCE_PATH {
        return Ok(None);
    }
    if (flags & 0o3) != 0 {
        return Ok(Some(SyscallReturn::error(Errno::EROFS)));
    }
    let res = with_step44_state(|state| {
        state.ensure_report();
        let Some((idx, slot)) = state.fds.iter_mut().enumerate().find(|(_, s)| !s.open) else {
            return Err(Errno::EMFILE);
        };
        *slot = ConformanceFdSlot {
            open: true,
            offset: 0,
        };
        Ok(i64::from(CONFORMANCE_FD_BASE + (idx as i32)))
    })?;
    Ok(Some(encode_result(res)))
}

fn handle_read(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match conformance_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step44_state(|state| {
        if !state.fds[idx].open {
            return Err(Errno::EBADF);
        }
        let total = state.ensure_report();
        let offset = state.fds[idx].offset.min(total);
        let avail = &state.cached_report[offset..total];
        let take = avail.len().min(count as usize);
        if take > 0 {
            copy_to_user(user_buf, &avail[..take])?;
            state.fds[idx].offset += take;
        }
        Ok(take as i64)
    })
}

fn handle_lseek(raw_fd: u64, offset: i64, whence: i32) -> Result<Result<i64, Errno>, ()> {
    let idx = match conformance_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step44_state(|state| {
        if !state.fds[idx].open {
            return Err(Errno::EBADF);
        }
        let total = state.ensure_report();
        let next = seek_bounded(state.fds[idx].offset, total, offset, whence)?;
        state.fds[idx].offset = next;
        Ok(next as i64)
    })
}

fn handle_close(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match conformance_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step44_state(|state| {
        if !state.fds[idx].open {
            return Err(Errno::EBADF);
        }
        state.fds[idx] = ConformanceFdSlot::EMPTY;
        Ok(0)
    })
}

fn handle_fstat(raw_fd: u64, user_stat: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match conformance_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let size = with_step44_state(|state| {
        if !state.fds[idx].open {
            return Err(Errno::EBADF);
        }
        Ok(state.ensure_report() as u64)
    })?;
    match size {
        Ok(sz) => Ok(write_aarch64_stat(user_stat, S_IFREG_MODE, sz)),
        Err(e) => Ok(Err(e)),
    }
}

fn handle_newfstatat_if_conformance(
    user_path: u64,
    user_stat: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; 64];
    let Ok(len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    if &path_buf[..len] != CONFORMANCE_PATH {
        return Ok(None);
    }
    let sz = with_step44_state(|state| state.ensure_report() as u64)?;
    Ok(Some(encode_result(write_aarch64_stat(
        user_stat,
        S_IFREG_MODE,
        sz,
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conformance_fd_window_is_disjoint() {
        assert!(!is_conformance_fd(256));
        assert!(!is_conformance_fd(271));
        assert!(is_conformance_fd(CONFORMANCE_FD_BASE as u64));
        assert!(is_conformance_fd((CONFORMANCE_FD_BASE + 7) as u64));
        assert!(!is_conformance_fd((CONFORMANCE_FD_BASE + 8) as u64));
    }
}
