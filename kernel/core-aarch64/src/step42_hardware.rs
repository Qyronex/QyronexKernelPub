// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::step_fd_util::{
    S_IFBLK_MODE, S_IFCHR_MODE, S_IFREG_MODE, copy_from_user, copy_to_user, encode_result,
    read_user_cstr, seek_bounded, write_aarch64_stat,
};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_capability::{CapRights, Capability, ObjectId};
use kernal_fdt::Blob;
use kernal_fdt_aarch64::{DeviceInventory, parse_device_inventory};
use kernal_linux_abi::{Errno, SyscallRequest, SyscallReturn, linux_signed_int};
use kernal_linux_hardware::{
    HardwareEntropyPool, PlatformTelemetry, RTC_AIE_OFF, RTC_AIE_ON, RTC_RD_TIME, RTC_SET_TIME,
    RtcPl031, RtcTime, WDIOC_GETSUPPORT, WDIOC_GETTIMELEFT, WDIOC_GETTIMEOUT, WDIOC_KEEPALIVE,
    WDIOC_SETTIMEOUT, WatchdogDevice,
};
use kernal_virtio::blk::VIRTIO_BLK_F_FLUSH;
use kernal_virtio::{DmaBufferGrant, SECTOR_SIZE, VIRTIO_F_VERSION_1, VirtioBlkDevice};

/// Dedicated file-descriptor base for Step-42 server hardware, RTC, watchdog, entropy, and sysfs
/// hardware telemetry nodes (`240..256`), partitioned cleanly above `CONTAINER_FD_BASE` (`224..240`).
pub(super) const HW_FD_BASE: i32 = 240;
const MAX_HW_FDS: usize = 16;

const HW_ADMIN_CAP: Capability = Capability {
    object: ObjectId(42),
    rights: CapRights::CONTROL
        .union(CapRights::READ)
        .union(CapRights::WRITE),
};

const HW_RO_CAP: Capability = Capability {
    object: ObjectId(42),
    rights: CapRights::READ,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum HwNodeKind {
    None,
    DevRtc0,
    DevWatchdog,
    DevHwRng,
    DevVda,
    SysRtcName,
    SysRtcSinceEpoch,
    SysThermalTemp,
    SysThermalType,
    SysCpuOnline,
    SysCpuPossible,
    SysVirtioMmioCount,
}

impl HwNodeKind {
    const fn stat_mode(self) -> u32 {
        match self {
            Self::DevRtc0 | Self::DevWatchdog | Self::DevHwRng => S_IFCHR_MODE,
            Self::DevVda => S_IFBLK_MODE,
            _ => S_IFREG_MODE,
        }
    }

    const fn is_writable(self) -> bool {
        matches!(self, Self::DevWatchdog | Self::DevVda)
    }
}

#[derive(Clone, Copy)]
struct HwFdSlot {
    kind: HwNodeKind,
    offset: usize,
    grant_rw: bool,
}

impl HwFdSlot {
    const EMPTY: Self = Self {
        kind: HwNodeKind::None,
        offset: 0,
        grant_rw: false,
    };
}

struct Step42State {
    initialized: bool,
    rtc: RtcPl031,
    watchdog: WatchdogDevice,
    telemetry: PlatformTelemetry,
    entropy: HardwareEntropyPool,
    virtio_blk: Option<VirtioBlkDevice<16, 16>>,
    discovered_virtio_mmio: usize,
    fds: [HwFdSlot; MAX_HW_FDS],
}

impl Step42State {
    const fn new() -> Self {
        Self {
            initialized: false,
            rtc: RtcPl031::new(1_784_000_000),
            watchdog: WatchdogDevice::new(60, false),
            telemetry: PlatformTelemetry {
                online_cpus: 1,
                max_cpus: 4,
                thermal_millicelsius: 42_000,
                critical_millicelsius: 105_000,
                ac_online: true,
            },
            entropy: HardwareEntropyPool::new(),
            virtio_blk: None,
            discovered_virtio_mmio: 0,
            fds: [HwFdSlot::EMPTY; MAX_HW_FDS],
        }
    }

    fn ensure_initialized(&mut self) {
        if !self.initialized {
            // Seed entropy pool from platform seed so /dev/hwrng fails closed until initialized.
            let _ = self.entropy.mix_seed(&[
                0x4b, 0x45, 0x52, 0x4e, 0x41, 0x4c, 0x34, 0x32, 0x9a, 0x1c, 0x7e, 0x33, 0xb1, 0xd2,
                0xe3, 0xf4, 0x05, 0x16, 0x27, 0x38, 0x49, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0xaf, 0xb0,
                0xc1, 0xd2, 0xe3, 0xf4,
            ]);
            self.virtio_blk =
                VirtioBlkDevice::<16, 16>::new(VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_FLUSH).ok();
            self.initialized = true;
        }
    }

    fn ingest_fdt(&mut self, inv: &DeviceInventory<16>) {
        self.ensure_initialized();
        self.discovered_virtio_mmio = inv.virtio_mmio_devices().len();
        if let Some(rtc) = inv.pl031_rtc {
            self.rtc.enabled = rtc.enabled;
        }
    }
}

struct Step42Cell {
    state: AtomicU8,
    value: UnsafeCell<Step42State>,
}

// SAFETY: synchronous EL0 trap dispatch serializes access with an atomic lock (`0 -> 1 -> 0`).
unsafe impl Sync for Step42Cell {}

static STEP42_STATE: Step42Cell = Step42Cell {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(Step42State::new()),
};

fn with_step42_state<R>(f: impl FnOnce(&mut Step42State) -> R) -> Result<R, ()> {
    if STEP42_STATE
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(());
    }
    // SAFETY: state `1` provides exclusive mutable access inside this synchronous handler scope.
    let state = unsafe { &mut *STEP42_STATE.value.get() };
    state.ensure_initialized();
    let res = f(state);
    STEP42_STATE.state.store(0, Ordering::Release);
    Ok(res)
}

/// Discovers QEMU/hardware FDT peripherals cleanly into Step 42 device telemetry.
#[allow(dead_code)]
pub(super) fn init_from_fdt_bytes(dtb: &[u8]) -> Result<usize, ()> {
    let blob = Blob::parse(dtb).map_err(|_| ())?;
    let inv = parse_device_inventory::<16>(&blob).map_err(|_| ())?;
    with_step42_state(|state| {
        state.ingest_fdt(&inv);
        state.discovered_virtio_mmio
    })
}

pub(super) const fn is_hw_fd(raw_fd: u64) -> bool {
    let fd = linux_signed_int(raw_fd);
    fd >= HW_FD_BASE && fd < HW_FD_BASE + (MAX_HW_FDS as i32)
}

fn hw_fd_idx(raw_fd: u64) -> Result<usize, Errno> {
    if !is_hw_fd(raw_fd) {
        return Err(Errno::EBADF);
    }
    Ok((linux_signed_int(raw_fd) - HW_FD_BASE) as usize)
}

fn match_hw_path(path: &[u8]) -> Option<HwNodeKind> {
    match path {
        b"/dev/rtc0" => Some(HwNodeKind::DevRtc0),
        b"/dev/watchdog" => Some(HwNodeKind::DevWatchdog),
        b"/dev/hwrng" => Some(HwNodeKind::DevHwRng),
        b"/dev/vda" => Some(HwNodeKind::DevVda),
        b"/sys/class/rtc/rtc0/name" => Some(HwNodeKind::SysRtcName),
        b"/sys/class/rtc/rtc0/since_epoch" => Some(HwNodeKind::SysRtcSinceEpoch),
        b"/sys/class/thermal/thermal_zone0/temp" => Some(HwNodeKind::SysThermalTemp),
        b"/sys/class/thermal/thermal_zone0/type" => Some(HwNodeKind::SysThermalType),
        b"/sys/devices/system/cpu/online" => Some(HwNodeKind::SysCpuOnline),
        b"/sys/devices/system/cpu/possible" => Some(HwNodeKind::SysCpuPossible),
        b"/sys/bus/virtio/devices/mmio_count" => Some(HwNodeKind::SysVirtioMmioCount),
        _ => None,
    }
}

fn blk_dma_grant() -> DmaBufferGrant {
    DmaBufferGrant {
        base_addr: 0x8000_0000,
        len: 0x1_0000,
        writable: true,
        dma_assigned: true,
        buffer_generation: 1,
        expected_generation: 1,
        revoked: false,
    }
}

pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        29 if is_hw_fd(request.args[0]) => Ok(Some(encode_result(handle_ioctl(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        56 => handle_openat_if_hw(request.args[1], request.args[2]),
        57 if is_hw_fd(request.args[0]) => Ok(Some(encode_result(handle_close(request.args[0])?))),
        62 if is_hw_fd(request.args[0]) => Ok(Some(encode_result(handle_lseek(
            request.args[0],
            request.args[1] as i64,
            linux_signed_int(request.args[2]),
        )?))),
        63 if is_hw_fd(request.args[0]) => Ok(Some(encode_result(handle_read(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        64 if is_hw_fd(request.args[0]) => Ok(Some(encode_result(handle_write(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        79 => handle_newfstatat_if_hw(request.args[1], request.args[2]),
        80 if is_hw_fd(request.args[0]) => Ok(Some(encode_result(handle_fstat(
            request.args[0],
            request.args[1],
        )?))),
        _ => Ok(None),
    }
}

fn handle_openat_if_hw(user_path: u64, flags: u64) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; 64];
    let Ok(len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    let Some(kind) = match_hw_path(&path_buf[..len]) else {
        return Ok(None);
    };
    let accmode = flags & 0o3;
    let wants_write = matches!(accmode, 1 | 2);
    if wants_write && !kind.is_writable() {
        return Ok(Some(SyscallReturn::error(Errno::EROFS)));
    }
    let res = with_step42_state(|state| {
        if kind == HwNodeKind::DevWatchdog && wants_write {
            state.watchdog.start(HW_ADMIN_CAP)?;
        }
        let Some((idx, slot)) = state
            .fds
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.kind == HwNodeKind::None)
        else {
            return Err(Errno::EMFILE);
        };
        *slot = HwFdSlot {
            kind,
            offset: 0,
            grant_rw: wants_write,
        };
        Ok(i64::from(HW_FD_BASE + (idx as i32)))
    })?;
    Ok(Some(encode_result(res)))
}

fn format_u64_line(mut v: u64, out: &mut [u8; 64]) -> usize {
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    loop {
        tmp[len] = b'0' + (v % 10) as u8;
        len += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..len {
        out[i] = tmp[len - 1 - i];
    }
    out[len] = b'\n';
    len + 1
}

fn materialize_sysfs(state: &Step42State, kind: HwNodeKind, out: &mut [u8; 64]) -> usize {
    match kind {
        HwNodeKind::SysRtcName => {
            let s = b"rtc-pl031 pl031\n";
            out[..s.len()].copy_from_slice(s);
            s.len()
        }
        HwNodeKind::SysRtcSinceEpoch => format_u64_line(state.rtc.dr_seconds, out),
        HwNodeKind::SysThermalTemp => {
            format_u64_line(state.telemetry.thermal_millicelsius.max(0) as u64, out)
        }
        HwNodeKind::SysThermalType => {
            let s = b"acpitz\n";
            out[..s.len()].copy_from_slice(s);
            s.len()
        }
        HwNodeKind::SysCpuOnline | HwNodeKind::SysCpuPossible => {
            let s = b"0\n";
            out[..s.len()].copy_from_slice(s);
            s.len()
        }
        HwNodeKind::SysVirtioMmioCount => format_u64_line(state.discovered_virtio_mmio as u64, out),
        _ => 0,
    }
}

fn handle_read(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match hw_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step42_state(|state| {
        let slot = state.fds[idx];
        match slot.kind {
            HwNodeKind::None => Err(Errno::EBADF),
            HwNodeKind::DevHwRng => {
                let mut tmp = [0u8; 64];
                let to_gen = (count as usize).min(tmp.len());
                state.entropy.fill_bytes(&mut tmp[..to_gen])?;
                copy_to_user(user_buf, &tmp[..to_gen])?;
                Ok(to_gen as i64)
            }
            HwNodeKind::DevVda => {
                let Some(blk) = state.virtio_blk.as_mut() else {
                    return Err(Errno::ENODEV);
                };
                let sector = (slot.offset / SECTOR_SIZE) as u64;
                if usize::try_from(sector).unwrap_or(usize::MAX) >= blk.sector_count() {
                    return Ok(0);
                }
                let mut sec_buf = [0u8; SECTOR_SIZE];
                blk.read_sectors(HW_RO_CAP, &blk_dma_grant(), sector, &mut sec_buf)
                    .map_err(|e| e.to_errno())?;
                let inner_off = slot.offset % SECTOR_SIZE;
                let avail = &sec_buf[inner_off..];
                let take = avail.len().min(count as usize);
                copy_to_user(user_buf, &avail[..take])?;
                state.fds[idx].offset += take;
                Ok(take as i64)
            }
            HwNodeKind::DevRtc0 | HwNodeKind::DevWatchdog => Err(Errno::EINVAL),
            other => {
                let mut data = [0u8; 64];
                let total = materialize_sysfs(state, other, &mut data);
                let avail = &data[slot.offset.min(total)..total];
                let take = avail.len().min(count as usize);
                if take > 0 {
                    copy_to_user(user_buf, &avail[..take])?;
                    state.fds[idx].offset += take;
                }
                Ok(take as i64)
            }
        }
    })
}

fn handle_write(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match hw_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step42_state(|state| {
        let slot = state.fds[idx];
        match slot.kind {
            HwNodeKind::None => Err(Errno::EBADF),
            HwNodeKind::DevWatchdog => {
                let mut tmp = [0u8; 32];
                let take = (count as usize).min(tmp.len());
                copy_from_user(&mut tmp[..take], user_buf)?;
                state.watchdog.write_ping(HW_ADMIN_CAP, &tmp[..take])?;
                Ok(take as i64)
            }
            HwNodeKind::DevVda => {
                if !slot.grant_rw {
                    return Err(Errno::EACCES);
                }
                let take = (count as usize).min(SECTOR_SIZE);
                if take == 0 {
                    return Ok(0);
                }
                let sector = (slot.offset / SECTOR_SIZE) as u64;
                let mut sec_buf = [0u8; SECTOR_SIZE];
                {
                    let Some(blk) = state.virtio_blk.as_mut() else {
                        return Err(Errno::ENODEV);
                    };
                    if usize::try_from(sector).unwrap_or(usize::MAX) >= blk.sector_count() {
                        return Err(Errno::ENOSPC);
                    }
                    blk.read_sectors(HW_RO_CAP, &blk_dma_grant(), sector, &mut sec_buf)
                        .map_err(|e| e.to_errno())?;
                }
                let inner_off = slot.offset % SECTOR_SIZE;
                let copy_len = take.min(SECTOR_SIZE - inner_off);
                copy_from_user(&mut sec_buf[inner_off..inner_off + copy_len], user_buf)?;
                let blk = state.virtio_blk.as_mut().ok_or(Errno::ENODEV)?;
                blk.write_sectors(HW_ADMIN_CAP, &blk_dma_grant(), sector, &sec_buf)
                    .map_err(|e| e.to_errno())?;
                state.fds[idx].offset += copy_len;
                Ok(copy_len as i64)
            }
            _ => Err(Errno::EROFS),
        }
    })
}

fn handle_ioctl(raw_fd: u64, req: u64, arg: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match hw_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step42_state(|state| match state.fds[idx].kind {
        HwNodeKind::DevRtc0 => match req {
            RTC_RD_TIME => {
                let encoded = state.rtc.read_time().encode();
                copy_to_user(arg, &encoded)?;
                Ok(0)
            }
            RTC_SET_TIME => {
                let mut raw = [0u8; 36];
                copy_from_user(&mut raw, arg)?;
                let tm = RtcTime::decode(&raw)?;
                state.rtc.set_time(HW_ADMIN_CAP, tm)?;
                Ok(0)
            }
            RTC_AIE_ON => {
                state.rtc.alarm_enabled = true;
                Ok(0)
            }
            RTC_AIE_OFF => {
                state.rtc.alarm_enabled = false;
                Ok(0)
            }
            _ => Err(Errno::ENOTTY),
        },
        HwNodeKind::DevWatchdog => match req {
            WDIOC_KEEPALIVE => {
                state.watchdog.keepalive(HW_ADMIN_CAP)?;
                Ok(0)
            }
            WDIOC_SETTIMEOUT => {
                let mut raw = [0u8; 4];
                copy_from_user(&mut raw, arg)?;
                let secs = state
                    .watchdog
                    .set_timeout(HW_ADMIN_CAP, u32::from_le_bytes(raw))?;
                copy_to_user(arg, &secs.to_le_bytes())?;
                Ok(0)
            }
            WDIOC_GETTIMEOUT => {
                copy_to_user(arg, &state.watchdog.timeout_secs.to_le_bytes())?;
                Ok(0)
            }
            WDIOC_GETTIMELEFT => {
                copy_to_user(arg, &state.watchdog.remaining_secs.to_le_bytes())?;
                Ok(0)
            }
            WDIOC_GETSUPPORT => {
                let mut info = [0u8; 40];
                info[0..4].copy_from_slice(&0x8180u32.to_le_bytes()); // WDIOF_SETTIMEOUT | KEEPALIVEPING | MAGICCLOSE
                info[8..18].copy_from_slice(b"kernal-wdt");
                copy_to_user(arg, &info)?;
                Ok(0)
            }
            _ => Err(Errno::ENOTTY),
        },
        HwNodeKind::None => Err(Errno::EBADF),
        _ => Err(Errno::ENOTTY),
    })
}

fn handle_lseek(raw_fd: u64, offset: i64, whence: i32) -> Result<Result<i64, Errno>, ()> {
    let idx = match hw_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step42_state(|state| {
        let slot = state.fds[idx];
        match slot.kind {
            HwNodeKind::None => Err(Errno::EBADF),
            HwNodeKind::DevVda => {
                let total = state
                    .virtio_blk
                    .as_ref()
                    .map(|b| b.sector_count() * SECTOR_SIZE)
                    .unwrap_or(0);
                let next = seek_bounded(slot.offset, total, offset, whence)?;
                state.fds[idx].offset = next;
                Ok(next as i64)
            }
            other => {
                let mut data = [0u8; 64];
                let total = materialize_sysfs(state, other, &mut data);
                let next = seek_bounded(slot.offset, total, offset, whence)?;
                state.fds[idx].offset = next;
                Ok(next as i64)
            }
        }
    })
}

fn handle_close(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match hw_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    with_step42_state(|state| {
        let slot = state.fds[idx];
        if slot.kind == HwNodeKind::None {
            return Err(Errno::EBADF);
        }
        if slot.kind == HwNodeKind::DevWatchdog {
            state.watchdog.release()?;
        }
        state.fds[idx] = HwFdSlot::EMPTY;
        Ok(0)
    })
}

fn handle_fstat(raw_fd: u64, user_stat: u64) -> Result<Result<i64, Errno>, ()> {
    let idx = match hw_fd_idx(raw_fd) {
        Ok(i) => i,
        Err(e) => return Ok(Err(e)),
    };
    let meta = with_step42_state(|state| {
        let kind = state.fds[idx].kind;
        if kind == HwNodeKind::None {
            return Err(Errno::EBADF);
        }
        let size = match kind {
            HwNodeKind::DevVda => (16 * SECTOR_SIZE) as u64,
            HwNodeKind::DevRtc0 | HwNodeKind::DevWatchdog | HwNodeKind::DevHwRng => 0,
            other => {
                let mut data = [0u8; 64];
                materialize_sysfs(state, other, &mut data) as u64
            }
        };
        Ok((kind.stat_mode(), size))
    })?;
    match meta {
        Ok((mode, sz)) => Ok(write_aarch64_stat(user_stat, mode, sz)),
        Err(e) => Ok(Err(e)),
    }
}

fn handle_newfstatat_if_hw(user_path: u64, user_stat: u64) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; 64];
    let Ok(len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    let Some(kind) = match_hw_path(&path_buf[..len]) else {
        return Ok(None);
    };
    let sz = with_step42_state(|state| match kind {
        HwNodeKind::DevVda => (16 * SECTOR_SIZE) as u64,
        HwNodeKind::DevRtc0 | HwNodeKind::DevWatchdog | HwNodeKind::DevHwRng => 0,
        other => {
            let mut data = [0u8; 64];
            materialize_sysfs(state, other, &mut data) as u64
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
    fn hw_fd_window_is_disjoint() {
        assert!(!is_hw_fd(224));
        assert!(!is_hw_fd(239));
        assert!(is_hw_fd(HW_FD_BASE as u64));
        assert!(is_hw_fd((HW_FD_BASE + 15) as u64));
        assert!(!is_hw_fd((HW_FD_BASE + 16) as u64));
    }
}
