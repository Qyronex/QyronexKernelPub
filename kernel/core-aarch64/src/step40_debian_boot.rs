// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_capability::{CapRights, Capability, ObjectId};
use kernal_linux_abi::{Errno, SyscallRequest, SyscallReturn, linux_signed_int};
use kernal_linux_debian_profile::{DebianBootProfile, KernelCmdline};
use kernal_usercopy::Error as UsercopyError;

/// Dedicated file-descriptor base for Step-40 Debian boot/network profile descriptors (`208..224`),
/// cleanly above `KMSG_FD_BASE` (`192..208`) and below `CONTAINER_FD_BASE` (`224..240`).
pub(super) const BOOT_FD_BASE: i32 = 208;
const MAX_BOOT_FDS: usize = 16;
const ARM64_STAT_BYTES: usize = 128;
const S_IFREG_MODE: u32 = 0o100_444;

const BOOT_CONTROL_CAP: Capability = Capability {
    object: ObjectId(40),
    rights: CapRights::CONTROL,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum BootFileKind {
    None,
    ProcCmdline,
    ProcUptime,
    EtcResolvConf,
    EtcHostname,
}

#[derive(Clone, Copy)]
struct BootFdSlot {
    kind: BootFileKind,
    offset: usize,
}

impl BootFdSlot {
    const EMPTY: Self = Self {
        kind: BootFileKind::None,
        offset: 0,
    };
}

struct Step40State {
    initialized: bool,
    profile: DebianBootProfile,
    fds: [BootFdSlot; MAX_BOOT_FDS],
}

impl Step40State {
    const fn new() -> Self {
        Self {
            initialized: false,
            profile: DebianBootProfile::new(KernelCmdline::empty()),
            fds: [BootFdSlot::EMPTY; MAX_BOOT_FDS],
        }
    }

    fn ensure_initialized(&mut self) {
        if !self.initialized {
            self.profile = DebianBootProfile::default();
            let _ = self.profile.begin_boot(BOOT_CONTROL_CAP);
            let _ = self
                .profile
                .add_host_port_forward(BOOT_CONTROL_CAP, 18080, [0, 0, 0, 0], 80);
            self.initialized = true;
        }
    }
}

struct Step40Cell {
    state: AtomicU8,
    value: UnsafeCell<Step40State>,
}

// SAFETY: synchronous lower-EL trap dispatch serializes access with an atomic lock (`0 -> 1 -> 0`).
unsafe impl Sync for Step40Cell {}

static STEP40_STATE: Step40Cell = Step40Cell {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(Step40State::new()),
};

fn with_step40_state<R>(f: impl FnOnce(&mut Step40State) -> R) -> Result<R, ()> {
    if STEP40_STATE
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(());
    }
    // SAFETY: state `1` provides exclusive mutable access inside this synchronous handler scope.
    let state = unsafe { &mut *STEP40_STATE.value.get() };
    state.ensure_initialized();
    let res = f(state);
    STEP40_STATE.state.store(0, Ordering::Release);
    Ok(res)
}

pub(super) const fn is_boot_fd(raw_fd: u64) -> bool {
    let fd = linux_signed_int(raw_fd);
    fd >= BOOT_FD_BASE && fd < BOOT_FD_BASE + (MAX_BOOT_FDS as i32)
}

pub(super) fn is_open_boot_fd(raw_fd: u64) -> bool {
    let Ok(idx) = boot_fd_idx(raw_fd) else {
        return false;
    };
    with_step40_state(|state| state.fds[idx].kind != BootFileKind::None).unwrap_or(false)
}

fn boot_fd_idx(raw_fd: u64) -> Result<usize, Errno> {
    if !is_boot_fd(raw_fd) {
        return Err(Errno::EBADF);
    }
    Ok((linux_signed_int(raw_fd) - BOOT_FD_BASE) as usize)
}

fn match_boot_path(path: &[u8]) -> Option<BootFileKind> {
    match path {
        b"/proc/cmdline" => Some(BootFileKind::ProcCmdline),
        b"/proc/uptime" => Some(BootFileKind::ProcUptime),
        b"/etc/resolv.conf" => Some(BootFileKind::EtcResolvConf),
        b"/etc/hostname" => Some(BootFileKind::EtcHostname),
        _ => None,
    }
}

fn materialize_boot_file(state: &Step40State, kind: BootFileKind, out: &mut [u8; 256]) -> usize {
    match kind {
        BootFileKind::None => 0,
        BootFileKind::ProcCmdline => state.profile.cmdline().format_proc_cmdline(out),
        BootFileKind::ProcUptime => state.profile.format_proc_uptime(out),
        BootFileKind::EtcResolvConf => state.profile.net().format_resolv_conf(out),
        BootFileKind::EtcHostname => {
            let name = state.profile.cmdline().hostname();
            let take = name.len().min(254);
            out[..take].copy_from_slice(&name[..take]);
            out[take] = b'\n';
            take + 1
        }
    }
}

pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        // openat(dirfd, pathname, flags, mode)
        56 => handle_openat_if_boot_file(request.args[1], request.args[2]),
        // close(fd)
        57 if is_boot_fd(request.args[0]) => {
            Ok(Some(encode_result(handle_close(request.args[0])?)))
        }
        // lseek(fd, offset, whence)
        62 if is_boot_fd(request.args[0]) => Ok(Some(encode_result(handle_lseek(
            request.args[0],
            request.args[1] as i64,
            linux_signed_int(request.args[2]),
        )?))),
        // read(fd, buf, count)
        63 if is_boot_fd(request.args[0]) => Ok(Some(encode_result(handle_read(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        // newfstatat(dirfd, pathname, statbuf, flags)
        79 => handle_newfstatat_if_boot_file(request.args[1], request.args[2]),
        // fstat(fd, statbuf)
        80 if is_boot_fd(request.args[0]) => Ok(Some(encode_result(handle_fstat(
            request.args[0],
            request.args[1],
        )?))),
        _ => Ok(None),
    }
}

fn encode_result(res: Result<i64, Errno>) -> SyscallReturn {
    match res {
        Ok(val) => SyscallReturn::success(val).unwrap_or(SyscallReturn::error(Errno::EINVAL)),
        Err(errno) => SyscallReturn::error(errno),
    }
}

pub(super) fn update_network_config(ip: [u8; 4], gw: [u8; 4], dns: [u8; 4], mac: [u8; 6]) {
    let _ = with_step40_state(|state| {
        let net = state.profile.net_mut();
        net.guest_ipv4 = ip;
        net.gateway_ipv4 = gw;
        if dns != [0, 0, 0, 0] {
            net.dns_primary_ipv4 = dns;
            net.dns_fallback_ipv4 = dns;
        }
        net.nic_mac = mac;
        net.nic_up = true;
        net.loopback_up = true;
    });
}

fn handle_openat_if_boot_file(user_path: u64, flags: u64) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; 64];
    let Ok(len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    let Some(kind) = match_boot_path(&path_buf[..len]) else {
        return Ok(None);
    };
    let mut boot_buf = [0u8; 256];
    if kind == BootFileKind::ProcCmdline && super::step42_hardware::copy_bootargs(&mut boot_buf) > 0
    {
        return Ok(None);
    }
    let write_or_create = (flags & 0x3) != 0 || (flags & 0x40) != 0 || (flags & 0x200) != 0;
    if matches!(
        kind,
        BootFileKind::EtcResolvConf | BootFileKind::EtcHostname
    ) && (write_or_create || super::step33_ext4_vfs::ext4_path_exists(&path_buf[..len]))
    {
        return Ok(None);
    }
    let res = with_step40_state(|state| {
        let Some((idx, slot)) = state
            .fds
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.kind == BootFileKind::None)
        else {
            return Err(Errno::EMFILE);
        };
        *slot = BootFdSlot { kind, offset: 0 };
        Ok(i64::from(BOOT_FD_BASE + (idx as i32)))
    })?;
    Ok(Some(encode_result(res)))
}

fn handle_read(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match boot_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step40_state(|state| {
        let slot = state.fds[idx];
        if slot.kind == BootFileKind::None {
            return Err(Errno::EBADF);
        }
        let mut data = [0u8; 256];
        let total = materialize_boot_file(state, slot.kind, &mut data);
        let avail = &data[slot.offset.min(total)..total];
        let to_copy = avail.len().min(count as usize);
        if to_copy > 0 {
            copy_to_user(user_buf, &avail[..to_copy])?;
            state.fds[idx].offset += to_copy;
        }
        Ok(to_copy as i64)
    })
}

fn handle_lseek(raw_fd: u64, offset: i64, whence: i32) -> Result<Result<i64, Errno>, ()> {
    let idx = match boot_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step40_state(|state| {
        let slot = state.fds[idx];
        if slot.kind == BootFileKind::None {
            return Err(Errno::EBADF);
        }
        let mut data = [0u8; 256];
        let total = materialize_boot_file(state, slot.kind, &mut data) as i64;
        let base = match whence {
            0 => 0i64,
            1 => slot.offset as i64,
            2 => total,
            _ => return Err(Errno::EINVAL),
        };
        let next = base.checked_add(offset).ok_or(Errno::EINVAL)?;
        if next < 0 {
            return Err(Errno::EINVAL);
        }
        state.fds[idx].offset = next as usize;
        Ok(next)
    })
}

fn handle_close(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match boot_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step40_state(|state| {
        if state.fds[idx].kind == BootFileKind::None {
            return Err(Errno::EBADF);
        }
        state.fds[idx] = BootFdSlot::EMPTY;
        Ok(0)
    })
}

fn handle_fstat(raw_fd: u64, user_stat: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match boot_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let size = with_step40_state(|state| {
        let kind = state.fds[idx].kind;
        if kind == BootFileKind::None {
            return Err(Errno::EBADF);
        }
        let mut data = [0u8; 256];
        Ok(materialize_boot_file(state, kind, &mut data) as u64)
    })?;
    match size {
        Ok(sz) => Ok(encode_stat(user_stat, sz)),
        Err(e) => Ok(Err(e)),
    }
}

fn handle_newfstatat_if_boot_file(
    user_path: u64,
    user_stat: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; 64];
    let Ok(len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    let Some(kind) = match_boot_path(&path_buf[..len]) else {
        return Ok(None);
    };
    let mut boot_buf = [0u8; 256];
    if kind == BootFileKind::ProcCmdline && super::step42_hardware::copy_bootargs(&mut boot_buf) > 0
    {
        return Ok(None);
    }
    if matches!(
        kind,
        BootFileKind::EtcResolvConf | BootFileKind::EtcHostname
    ) && super::step33_ext4_vfs::ext4_path_exists(&path_buf[..len])
    {
        return Ok(None);
    }
    let sz = with_step40_state(|state| {
        let mut data = [0u8; 256];
        materialize_boot_file(state, kind, &mut data) as u64
    })?;
    Ok(Some(encode_result(encode_stat(user_stat, sz))))
}

fn encode_stat(user_stat: u64, size: u64) -> Result<i64, Errno> {
    let mut buf = [0u8; ARM64_STAT_BYTES];
    buf[16..20].copy_from_slice(&S_IFREG_MODE.to_le_bytes()); // st_mode
    buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // st_nlink
    buf[48..56].copy_from_slice(&(size as i64).to_le_bytes()); // st_size
    buf[56..60].copy_from_slice(&4096i32.to_le_bytes()); // st_blksize
    copy_to_user(user_stat, &buf)?;
    Ok(0)
}

fn read_user_cstr(user_ptr: u64, out: &mut [u8]) -> Result<usize, Errno> {
    if user_ptr == 0 {
        return Err(Errno::EFAULT);
    }
    for (idx, slot) in out.iter_mut().enumerate() {
        let addr = user_ptr.checked_add(idx as u64).ok_or(Errno::EFAULT)?;
        let mut byte = [0u8; 1];
        copy_from_user(&mut byte, addr)?;
        if byte[0] == 0 {
            return Ok(idx);
        }
        *slot = byte[0];
    }
    Err(Errno::ENAMETOOLONG)
}

fn map_usercopy_error(err: UsercopyError) -> Errno {
    match err {
        UsercopyError::NullGuard
        | UsercopyError::Overflow
        | UsercopyError::OutsideUserRange
        | UsercopyError::Fault => Errno::EFAULT,
        UsercopyError::TooLarge
        | UsercopyError::PanUnavailable
        | UsercopyError::PanStateLeak
        | UsercopyError::FaultHandlerUnavailable => Errno::EINVAL,
    }
}

fn copy_from_user(dst: &mut [u8], user_src: u64) -> Result<(), Errno> {
    kernal_usercopy_aarch64::copy_from_user(dst, user_src).map_err(map_usercopy_error)
}

fn copy_to_user(user_dst: u64, src: &[u8]) -> Result<(), Errno> {
    kernal_usercopy_aarch64::copy_to_user(user_dst, src).map_err(map_usercopy_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_fd_window_is_disjoint() {
        assert!(!is_boot_fd(192));
        assert!(!is_boot_fd(207));
        assert!(is_boot_fd(BOOT_FD_BASE as u64));
        assert!(is_boot_fd((BOOT_FD_BASE + 15) as u64));
        assert!(!is_boot_fd((BOOT_FD_BASE + 16) as u64));
    }
}
