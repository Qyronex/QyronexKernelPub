// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::step_fd_util::{
    DirectProcessRefs, S_IFBLK_MODE, S_IFCHR_MODE, S_IFREG_MODE, SUBSYS_HW, StatMeta,
    copy_from_user, copy_to_user, current_process_object, encode_result, lookup_aliased_subsystem,
    lookup_aliased_subsystem_current, read_user_cstr, read_user_iovec, seek_bounded,
    write_aarch64_statx_meta,
};
use core::cell::UnsafeCell;
use core::mem::size_of;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_capability::{CapRights, Capability, ObjectId};
use kernal_fdt::Blob;
use kernal_fdt_aarch64::{DeviceInventory, VirtioMmioInfo, parse_device_inventory};
use kernal_linux_abi::{Errno, SyscallRequest, SyscallReturn, linux_signed_int};
use kernal_linux_fd::SubsystemHandle;
use kernal_linux_hardware::{
    HardwareEntropyPool, PlatformTelemetry, RTC_AIE_OFF, RTC_AIE_ON, RTC_RD_TIME, RTC_SET_TIME,
    RtcPl031, RtcTime, WDIOC_GETSUPPORT, WDIOC_GETTIMELEFT, WDIOC_GETTIMEOUT, WDIOC_KEEPALIVE,
    WDIOC_SETTIMEOUT, WatchdogDevice,
};
use kernal_linux_mounts::{BlockDevice, PartitionTable, parse_partitions};
use kernal_protected_boot_aarch64::{ProtectedVirtioMmioMap, runtime_kernel_alias_physical};
use kernal_rpi3b_plus::Rpi3bPlusBoard;
use kernal_virtio::blk::VIRTIO_BLK_F_FLUSH;
use kernal_virtio::{
    DmaBufferGrant, SECTOR_SIZE, VIRTIO_F_VERSION_1, VirtioBlkDevice, VirtioBlkDmaBlock,
    VirtioBlkMmio, VirtioDeviceId, VirtioGpuDmaBlock, VirtioGpuMmio, VirtioInputCaps,
    VirtioInputDmaBlock, VirtioInputEvent, VirtioInputKind, VirtioInputMmio, VirtioMmioTransport,
    VirtioNetDmaBlock, VirtioNetMmio, VolatileMmioBus,
};

/// Dedicated file-descriptor base for Step-42 server hardware, RTC, watchdog, entropy, and sysfs
/// hardware telemetry nodes (`240..256`), partitioned cleanly above `CONTAINER_FD_BASE` (`224..240`).
pub(super) const HW_FD_BASE: i32 = 240;
const MAX_HW_FDS: usize = 16;
const O_CLOEXEC_U64: u64 = 0x0008_0000;
const O_NONBLOCK_U64: u64 = 0x0800;
const O_DIRECTORY_U64: u64 = 0x0000_4000;
const O_PATH_U64: u64 = 0x0020_0000;
const AT_EMPTY_PATH: u64 = 0x1000;

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

const BLKROGET: u64 = 0x125e;
const BLKGETSIZE: u64 = 0x1260;
const BLKFLSBUF: u64 = 0x1261;
const BLKSSZGET: u64 = 0x1268;
const BLKBSZGET: u64 = 0x8008_1270;
const BLKGETSIZE64: u64 = 0x8008_1272;

#[derive(Clone, Copy, Eq, PartialEq)]
enum HwNodeKind {
    None,
    DevRtc0,
    DevWatchdog,
    DevHwRng,
    DevVda,
    DevVdaPart(u8),
    SysRtcName,
    SysRtcSinceEpoch,
    SysThermalTemp,
    SysThermalType,
    SysCpuOnline,
    SysCpuPossible,
    SysVirtioMmioCount,
    SysRpiModel,
    SysRpiRevision,
    SysRpiArmClock,
    SysRpiLan7515Speed,
    SysRpiActLed,
    SysRpi4GenetV5,
    SysRpi5Rp1Pcie,
    SysPcieInternetStatus,
}

impl HwNodeKind {
    const fn stat_mode(self) -> u32 {
        match self {
            Self::DevRtc0 | Self::DevWatchdog | Self::DevHwRng => S_IFCHR_MODE,
            Self::DevVda | Self::DevVdaPart(_) => S_IFBLK_MODE,
            _ => S_IFREG_MODE,
        }
    }

    const fn is_writable(self) -> bool {
        matches!(
            self,
            Self::DevWatchdog | Self::DevVda | Self::DevVdaPart(_) | Self::SysRpiActLed
        )
    }

    const fn block_part_number(self) -> Option<u8> {
        match self {
            Self::DevVda => Some(0),
            Self::DevVdaPart(part) => Some(part),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
struct HwFdSlot {
    live: bool,
    kind: HwNodeKind,
    generation: u64,
    owners: DirectProcessRefs<16>,
    alias_refs: u32,
    offset: usize,
    grant_rw: bool,
    status_flags: u64,
}

impl HwFdSlot {
    const EMPTY: Self = Self {
        live: false,
        kind: HwNodeKind::None,
        generation: 0,
        owners: DirectProcessRefs::empty(),
        alias_refs: 0,
        offset: 0,
        grant_rw: false,
        status_flags: 0,
    };
}

struct HwBlkDmaCell(UnsafeCell<VirtioBlkDmaBlock>);
// SAFETY: all accesses to `HARDWARE_BLK_DMA` occur under `STEP42_STATE` after hardware ownership transfer.
unsafe impl Sync for HwBlkDmaCell {}
static HARDWARE_BLK_DMA: HwBlkDmaCell = HwBlkDmaCell(UnsafeCell::new(VirtioBlkDmaBlock::zeroed()));

struct HwNetDmaCell(UnsafeCell<VirtioNetDmaBlock>);
// SAFETY: all accesses to `HARDWARE_NET_DMA` occur under `HW_NET_CELL` after hardware ownership transfer.
unsafe impl Sync for HwNetDmaCell {}
static HARDWARE_NET_DMA: HwNetDmaCell = HwNetDmaCell(UnsafeCell::new(VirtioNetDmaBlock::zeroed()));

struct HwNetCell {
    state: AtomicU8,
    value: UnsafeCell<Option<VirtioNetMmio<VolatileMmioBus>>>,
}
// SAFETY: synchronous EL0 trap dispatch serializes access via atomic state `0 -> 1 -> 0`.
unsafe impl Sync for HwNetCell {}
static HW_NET_CELL: HwNetCell = HwNetCell {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(None),
};

struct HwGpuDmaCell(UnsafeCell<VirtioGpuDmaBlock>);
// SAFETY: all accesses to `HARDWARE_GPU_DMA` occur under `HW_GPU_CELL` after hardware ownership transfer.
unsafe impl Sync for HwGpuDmaCell {}
static HARDWARE_GPU_DMA: HwGpuDmaCell = HwGpuDmaCell(UnsafeCell::new(VirtioGpuDmaBlock::zeroed()));

struct HwGpuSlot {
    gpu: VirtioGpuMmio<VolatileMmioBus>,
    scanout_w: u32,
    scanout_h: u32,
}

struct HwGpuCell {
    state: AtomicU8,
    value: UnsafeCell<Option<HwGpuSlot>>,
}
// SAFETY: synchronous EL0 trap dispatch serializes access via atomic state `0 -> 1 -> 0`.
unsafe impl Sync for HwGpuCell {}
static HW_GPU_CELL: HwGpuCell = HwGpuCell {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(None),
};

fn with_hw_gpu<R>(f: impl FnOnce(&mut Option<HwGpuSlot>) -> R) -> Result<R, ()> {
    if HW_GPU_CELL
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(());
    }
    // SAFETY: state `1` grants exclusive mutable access to the `HW_GPU_CELL` slot.
    let gpu = unsafe { &mut *HW_GPU_CELL.value.get() };
    let res = f(gpu);
    HW_GPU_CELL.state.store(0, Ordering::Release);
    Ok(res)
}

pub(super) const MAX_HW_INPUT_DEVS: usize = 4;

struct HwInputDmasCell(UnsafeCell<[VirtioInputDmaBlock; MAX_HW_INPUT_DEVS]>);
// SAFETY: each slot is accessed exclusively while `HW_INPUT_CELL` is locked.
unsafe impl Sync for HwInputDmasCell {}
static HARDWARE_INPUT_DMAS: HwInputDmasCell = HwInputDmasCell(UnsafeCell::new([
    VirtioInputDmaBlock::zeroed(),
    VirtioInputDmaBlock::zeroed(),
    VirtioInputDmaBlock::zeroed(),
    VirtioInputDmaBlock::zeroed(),
]));

struct HwInputTable {
    count: usize,
    devs: [Option<VirtioInputMmio<VolatileMmioBus>>; MAX_HW_INPUT_DEVS],
}

impl HwInputTable {
    const fn empty() -> Self {
        Self {
            count: 0,
            devs: [None, None, None, None],
        }
    }
}

struct HwInputCell {
    state: AtomicU8,
    value: UnsafeCell<HwInputTable>,
}
// SAFETY: synchronous EL0 trap dispatch serializes access via atomic state `0 -> 1 -> 0`.
unsafe impl Sync for HwInputCell {}
static HW_INPUT_CELL: HwInputCell = HwInputCell {
    state: AtomicU8::new(0),
    value: UnsafeCell::new(HwInputTable::empty()),
};

fn with_hw_input<R>(f: impl FnOnce(&mut HwInputTable) -> R) -> Result<R, ()> {
    if HW_INPUT_CELL
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(());
    }
    // SAFETY: state `1` grants exclusive mutable access to `HW_INPUT_CELL`.
    let table = unsafe { &mut *HW_INPUT_CELL.value.get() };
    let res = f(table);
    HW_INPUT_CELL.state.store(0, Ordering::Release);
    Ok(res)
}

fn prepare_static_dma<T>(ptr: *mut T) -> Option<(NonNull<T>, u64, DmaBufferGrant)> {
    let dma_virt = NonNull::new(ptr)?;
    let dma_phys = runtime_kernel_alias_physical(ptr as u64)?;
    let grant = DmaBufferGrant {
        base_addr: dma_phys,
        len: size_of::<T>() as u64,
        writable: true,
        dma_assigned: true,
        buffer_generation: 1,
        expected_generation: 1,
        revoked: false,
    };
    Some((dma_virt, dma_phys, grant))
}

fn with_hw_net<R>(
    f: impl FnOnce(&mut Option<VirtioNetMmio<VolatileMmioBus>>) -> R,
) -> Result<R, ()> {
    if HW_NET_CELL
        .state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(());
    }
    // SAFETY: state `1` grants exclusive mutable access to the `HW_NET_CELL` slot.
    let net = unsafe { &mut *HW_NET_CELL.value.get() };
    let res = f(net);
    HW_NET_CELL.state.store(0, Ordering::Release);
    Ok(res)
}

struct MockBlkAdapter<'a>(&'a mut VirtioBlkDevice<16, 16>);

impl BlockDevice for MockBlkAdapter<'_> {
    fn total_sectors(&self) -> u64 {
        self.0.sector_count() as u64
    }

    fn read_only(&self) -> bool {
        self.0.read_only()
    }

    fn read_sectors(&mut self, start_sector: u64, out: &mut [u8]) -> Result<(), Errno> {
        if !out.len().is_multiple_of(SECTOR_SIZE) {
            return Err(Errno::EINVAL);
        }
        let grant = blk_dma_grant();
        for (i, chunk) in out.chunks_exact_mut(SECTOR_SIZE).enumerate() {
            let mut sec = [0u8; SECTOR_SIZE];
            self.0
                .read_sectors(HW_RO_CAP, &grant, start_sector + (i as u64), &mut sec)
                .map_err(|e| e.to_errno())?;
            chunk.copy_from_slice(&sec);
        }
        Ok(())
    }

    fn write_sectors(&mut self, start_sector: u64, data: &[u8]) -> Result<(), Errno> {
        if !data.len().is_multiple_of(SECTOR_SIZE) {
            return Err(Errno::EINVAL);
        }
        let grant = blk_dma_grant();
        for (i, chunk) in data.chunks_exact(SECTOR_SIZE).enumerate() {
            let mut sec = [0u8; SECTOR_SIZE];
            sec.copy_from_slice(chunk);
            self.0
                .write_sectors(HW_ADMIN_CAP, &grant, start_sector + (i as u64), &sec)
                .map_err(|e| e.to_errno())?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Errno> {
        let _ = self.0.flush(HW_ADMIN_CAP, &blk_dma_grant());
        Ok(())
    }
}

struct HwBlkAdapter<'a>(&'a mut VirtioBlkMmio<VolatileMmioBus>);

impl BlockDevice for HwBlkAdapter<'_> {
    fn total_sectors(&self) -> u64 {
        self.0.capacity_sectors()
    }

    fn block_size(&self) -> u32 {
        self.0.blk_size()
    }

    fn read_only(&self) -> bool {
        self.0.read_only()
    }

    fn read_sectors(&mut self, start_sector: u64, out: &mut [u8]) -> Result<(), Errno> {
        self.0
            .read_sectors(start_sector, out)
            .map_err(|e| e.to_errno())
    }

    fn write_sectors(&mut self, start_sector: u64, data: &[u8]) -> Result<(), Errno> {
        self.0
            .write_sectors(start_sector, data)
            .map_err(|e| e.to_errno())
    }

    fn flush(&mut self) -> Result<(), Errno> {
        self.0.flush().map_err(|e| e.to_errno())
    }
}

struct Step42State {
    initialized: bool,
    rtc: RtcPl031,
    watchdog: WatchdogDevice,
    telemetry: PlatformTelemetry,
    entropy: HardwareEntropyPool,
    virtio_blk: Option<VirtioBlkDevice<16, 16>>,
    hw_blk: Option<VirtioBlkMmio<VolatileMmioBus>>,
    partitions: PartitionTable,
    bootargs: [u8; 256],
    bootargs_len: usize,
    discovered_virtio_mmio: usize,
    rpi3b_plus: Rpi3bPlusBoard<4, 2>,
    rpi4b: kernal_linux_hardware::Rpi4BBoard<4, 2>,
    rpi5: kernal_linux_hardware::Rpi5Board<2>,
    next_fd_generation: u64,
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
            hw_blk: None,
            partitions: PartitionTable::EMPTY,
            bootargs: [0; 256],
            bootargs_len: 0,
            discovered_virtio_mmio: 0,
            rpi3b_plus: Rpi3bPlusBoard::new(),
            rpi4b: kernal_linux_hardware::Rpi4BBoard::new(),
            rpi5: kernal_linux_hardware::Rpi5Board::new(),
            next_fd_generation: 1,
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
            let _ = self.rpi3b_plus.initialize_board(HW_ADMIN_CAP);
            self.rpi4b.initialize_board();
            self.rpi5.initialize_board();
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

    fn with_active_block<R>(
        &mut self,
        f: impl FnOnce(&mut dyn BlockDevice, &PartitionTable) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        let partitions = self.partitions;
        if let Some(ref mut hw) = self.hw_blk {
            let mut adapter = HwBlkAdapter(hw);
            return f(&mut adapter, &partitions);
        }
        if let Some(ref mut mock) = self.virtio_blk {
            let mut adapter = MockBlkAdapter(mock);
            return f(&mut adapter, &partitions);
        }
        Err(Errno::ENODEV)
    }

    fn block_window(&self, part_num: u8) -> Option<(u64, u64, bool)> {
        let (total_sectors, ro) = if let Some(ref hw) = self.hw_blk {
            (hw.capacity_sectors(), hw.read_only())
        } else if let Some(ref mock) = self.virtio_blk {
            (mock.sector_count() as u64, mock.read_only())
        } else {
            return None;
        };
        if part_num == 0 {
            return Some((0, total_sectors, ro));
        }
        let entry = self.partitions.by_number(part_num)?;
        Some((entry.start_sector, entry.sector_count, ro))
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

/// Initializes Step 42 VirtIO-MMIO devices (`virtio-blk` and `virtio-net`) and `/chosen/bootargs`
/// from the protected-boot DTB map.
pub(super) fn init_from_protected_virtio(map: &ProtectedVirtioMmioMap) -> Result<Option<u64>, ()> {
    let _ = with_hw_net(|slot| *slot = None);
    let _ = with_hw_gpu(|slot| *slot = None);
    let _ = with_hw_input(|table| {
        table.count = 0;
        for slot in &mut table.devs {
            *slot = None;
        }
    });
    with_step42_state(|state| {
        state.ensure_initialized();
        let bootargs = map.bootargs();
        let copy_len = bootargs.len().min(state.bootargs.len());
        state.bootargs[..copy_len].copy_from_slice(&bootargs[..copy_len]);
        state.bootargs_len = copy_len;

        state.discovered_virtio_mmio = map.entries().iter().filter(|e| e.enabled).count();
        state.hw_blk = None;
        state.partitions = PartitionTable::EMPTY;
        let mut attached_sectors = None;

        for entry in map.entries().iter().copied() {
            if !entry.enabled {
                continue;
            }
            let info = VirtioMmioInfo {
                region: entry.virtual_region,
                irq: entry.irq,
                enabled: entry.enabled,
            };
            // SAFETY: `entry.virtual_region` was permanently mapped as DeviceNgnre RW/NX by
            // `protected_boot_aarch64::map_qemu_virtio_mmio_high_aliases`.
            let Ok(bus) = (unsafe { VolatileMmioBus::new(entry.virtual_region) }) else {
                continue;
            };
            let Ok(probe) = VirtioMmioTransport::probe(info, &bus) else {
                continue;
            };
            match probe.device_id {
                VirtioDeviceId::Blk if state.hw_blk.is_none() => {
                    if let Some((dma_virt, dma_phys, grant)) =
                        prepare_static_dma(HARDWARE_BLK_DMA.0.get())
                    {
                        // SAFETY: `HARDWARE_BLK_DMA` is static 4 KiB-aligned `.bss` exclusively owned under
                        // `STEP42_STATE`, backed by `dma_phys` and covered by `grant`.
                        if let Ok(mut blk) = unsafe {
                            VirtioBlkMmio::initialize(info, bus, dma_virt, dma_phys, grant)
                        } {
                            let mut adapter = HwBlkAdapter(&mut blk);
                            state.partitions =
                                parse_partitions(&mut adapter).unwrap_or(PartitionTable::EMPTY);
                            let sectors = blk.capacity_sectors();
                            state.hw_blk = Some(blk);
                            attached_sectors = Some(sectors);
                        }
                    }
                }
                VirtioDeviceId::Net if !has_hardware_net() => {
                    if let Some((dma_virt, dma_phys, grant)) =
                        prepare_static_dma(HARDWARE_NET_DMA.0.get())
                    {
                        // SAFETY: `HARDWARE_NET_DMA` is static 4 KiB-aligned `.bss` exclusively owned under
                        // `HW_NET_CELL`, backed by `dma_phys` and covered by `grant`.
                        if let Ok(net) = unsafe {
                            VirtioNetMmio::initialize(info, bus, dma_virt, dma_phys, grant)
                        } {
                            let _ = with_hw_net(|slot| *slot = Some(net));
                        }
                    }
                }
                VirtioDeviceId::Gpu if !has_hardware_gpu() => {
                    if let Some((dma_virt, dma_phys, grant)) =
                        prepare_static_dma(HARDWARE_GPU_DMA.0.get())
                    {
                        // SAFETY: `HARDWARE_GPU_DMA` is static 4 KiB-aligned `.bss` exclusively owned under
                        // `HW_GPU_CELL`, backed by `dma_phys` and covered by `grant`.
                        if let Ok(mut gpu) = unsafe {
                            VirtioGpuMmio::initialize(info, bus, dma_virt, dma_phys, grant)
                        } {
                            let (scanout_w, scanout_h) = gpu
                                .get_display_info()
                                .ok()
                                .and_then(|info| {
                                    info.pmodes.iter().find_map(|m| {
                                        (m.enabled != 0 && m.r.width > 0 && m.r.height > 0)
                                            .then_some((m.r.width, m.r.height))
                                    })
                                })
                                .unwrap_or((1280, 800));
                            let _ = with_hw_gpu(|slot| {
                                *slot = Some(HwGpuSlot {
                                    gpu,
                                    scanout_w,
                                    scanout_h,
                                });
                            });
                        }
                    }
                }
                VirtioDeviceId::Input => {
                    let _ = with_hw_input(|table| {
                        if table.count >= MAX_HW_INPUT_DEVS {
                            return;
                        }
                        let idx = table.count;
                        // SAFETY: `HW_INPUT_CELL` is locked and `idx < MAX_HW_INPUT_DEVS`.
                        let dma_ptr = unsafe { (&raw mut (*HARDWARE_INPUT_DMAS.0.get())[idx]) };
                        let Some((dma_virt, dma_phys, grant)) = prepare_static_dma(dma_ptr) else {
                            return;
                        };
                        // SAFETY: `HARDWARE_INPUT_DMAS[idx]` is static 4 KiB-aligned `.bss` owned
                        // under `HW_INPUT_CELL`, backed by `dma_phys` and covered by `grant`.
                        if let Ok(input_dev) = unsafe {
                            VirtioInputMmio::initialize(info, bus, dma_virt, dma_phys, grant)
                        } {
                            table.devs[idx] = Some(input_dev);
                            table.count += 1;
                        }
                    });
                }
                _ => {}
            }
        }
        attached_sectors
    })
}

/// Returns the base UNIX epoch seconds configured on the platform PL031 RTC.
pub(super) fn rtc_epoch_base_seconds() -> u64 {
    with_step42_state(|state| u64::from(state.rtc.dr_seconds)).unwrap_or(1_784_000_000)
}

/// Returns whether the Raspberry Pi 3B+ (`BCM2837B0`) driver suite is initialized.
#[allow(dead_code)]
pub(super) fn has_rpi3b_plus_drivers() -> bool {
    with_step42_state(|state| state.rpi3b_plus.initialized).unwrap_or(false)
}

/// Returns whether a real VirtIO-MMIO network device (`virtio-net`) is initialized.
#[allow(dead_code)]
pub(super) fn has_hardware_net() -> bool {
    with_hw_net(|slot| slot.is_some()).unwrap_or(false)
}

/// Returns whether a real VirtIO-MMIO GPU device (`virtio-gpu`) is initialized.
#[allow(dead_code)]
pub(super) fn has_hardware_gpu() -> bool {
    with_hw_gpu(|slot| slot.is_some()).unwrap_or(false)
}

/// Returns the probed active scanout dimensions `(width, height)` for the hardware `virtio-gpu`.
#[allow(dead_code)]
pub(super) fn hardware_gpu_dimensions() -> Option<(u32, u32)> {
    with_hw_gpu(|slot| slot.as_ref().map(|g| (g.scanout_w, g.scanout_h)))
        .ok()
        .flatten()
}

/// Runs `f` with exclusive access to the attached hardware `virtio-gpu` controller.
#[allow(dead_code)]
pub(super) fn with_hardware_gpu<R>(
    f: impl FnOnce(&mut VirtioGpuMmio<VolatileMmioBus>) -> R,
) -> Result<R, Errno> {
    with_hw_gpu(|slot| match slot.as_mut() {
        Some(gpu_slot) => Ok(f(&mut gpu_slot.gpu)),
        None => Err(Errno::ENODEV),
    })
    .map_err(|_| Errno::EAGAIN)?
}

/// Returns the number of initialized VirtIO-MMIO input devices (`virtio-input`).
#[allow(dead_code)]
pub(super) fn hardware_input_count() -> usize {
    with_hw_input(|table| table.count).unwrap_or(0)
}

/// Returns `(kind, caps)` for hardware `virtio-input` slot `idx`, if initialized.
#[allow(dead_code)]
pub(super) fn hardware_input_info(idx: usize) -> Option<(VirtioInputKind, VirtioInputCaps)> {
    if idx >= MAX_HW_INPUT_DEVS {
        return None;
    }
    with_hw_input(|table| {
        table.devs[idx]
            .as_ref()
            .map(|dev| (dev.kind(), *dev.caps()))
    })
    .ok()
    .flatten()
}

/// Polls one completed input event from hardware `virtio-input` slot `idx`.
#[allow(dead_code)]
pub(super) fn hardware_input_poll_event(idx: usize) -> Option<VirtioInputEvent> {
    if idx >= MAX_HW_INPUT_DEVS {
        return None;
    }
    with_hw_input(|table| {
        let dev = table.devs[idx].as_mut()?;
        let _ = dev.ack_interrupt();
        dev.poll_event().ok().flatten()
    })
    .ok()
    .flatten()
}

/// Returns the hardware MAC address of the attached `virtio-net` controller, if any.
#[allow(dead_code)]
pub(super) fn hardware_net_mac() -> Option<[u8; 6]> {
    with_hw_net(|slot| slot.as_ref().map(|net| net.mac()))
        .ok()
        .flatten()
}

/// Returns the configured MTU of the attached `virtio-net` controller, if any.
#[allow(dead_code)]
pub(super) fn hardware_net_mtu() -> Option<u16> {
    with_hw_net(|slot| slot.as_ref().map(|net| net.mtu()))
        .ok()
        .flatten()
}

/// Returns whether the attached `virtio-net` link is reported up.
#[allow(dead_code)]
pub(super) fn hardware_net_link_up() -> bool {
    with_hw_net(|slot| slot.as_ref().is_some_and(|net| net.link_up())).unwrap_or(false)
}

/// Transmits one raw Ethernet frame over the attached `virtio-net` controller.
#[allow(dead_code)]
pub(super) fn net_send_frame(frame: &[u8]) -> Result<(), Errno> {
    with_hw_net(|slot| match slot.as_mut() {
        Some(net) => net.send_frame(frame).map_err(|e| e.to_errno()),
        None => Err(Errno::ENODEV),
    })
    .map_err(|_| Errno::EAGAIN)?
}

/// Polls for and copies the next incoming Ethernet frame from `virtio-net` TX/RX ring 0.
#[allow(dead_code)]
pub(super) fn net_recv_frame(out: &mut [u8]) -> Result<Option<usize>, Errno> {
    with_hw_net(|slot| match slot.as_mut() {
        Some(net) => net.recv_frame(out).map_err(|e| e.to_errno()),
        None => Err(Errno::ENODEV),
    })
    .map_err(|_| Errno::EAGAIN)?
}

/// Runs `f` with exclusive access to the active block device (`virtio-blk` hardware or mock) and
/// its parsed GPT/MBR partition table.
#[allow(dead_code)]
pub(super) fn with_active_block_device<R>(
    f: impl FnOnce(&mut dyn BlockDevice, &PartitionTable) -> Result<R, Errno>,
) -> Result<R, Errno> {
    with_step42_state(|state| state.with_active_block(f)).map_err(|_| Errno::EIO)?
}

/// Copies QEMU `/chosen/bootargs` into `out` and returns the slice length.
#[allow(dead_code)]
pub(super) fn copy_bootargs(out: &mut [u8; 256]) -> usize {
    with_step42_state(|state| {
        let len = state.bootargs_len.min(out.len());
        out[..len].copy_from_slice(&state.bootargs[..len]);
        len
    })
    .unwrap_or(0)
}

/// Returns `(start_sector, sector_count, read_only)` for `/dev/vda` or `/dev/vda1..16`.
#[allow(dead_code)]
pub(super) fn block_partition_window(path: &[u8]) -> Option<(u64, u64, bool)> {
    with_step42_state(|state| {
        let kind = match_hw_path(state, path)?;
        let part = kind.block_part_number()?;
        state.block_window(part)
    })
    .ok()
    .flatten()
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

pub(super) fn is_open_hw_fd(process: ObjectId, raw_fd: u64) -> bool {
    if !is_hw_fd(raw_fd) {
        return false;
    }
    let idx = (linux_signed_int(raw_fd) - HW_FD_BASE) as usize;
    with_step42_state(|state| resolve_hw_slot_mut(state, process, idx, None).is_some())
        .unwrap_or(false)
}

fn is_hw_fd_or_alias(raw_fd: u64) -> bool {
    is_hw_fd(raw_fd)
        || lookup_aliased_subsystem_current(raw_fd).is_some_and(|h| h.kind == SUBSYS_HW)
}

fn resolve_hw_slot_idx(process: ObjectId, raw_fd: u64) -> Result<(usize, Option<u64>), Errno> {
    if is_hw_fd(raw_fd) {
        let fd = linux_signed_int(raw_fd);
        return Ok(((fd - HW_FD_BASE) as usize, None));
    }
    if let Some(handle) = lookup_aliased_subsystem(process, raw_fd)
        && handle.kind == SUBSYS_HW
    {
        return Ok((handle.slot as usize, Some(handle.generation)));
    }
    Err(Errno::EBADF)
}

fn resolve_hw_slot_mut<'a>(
    state: &'a mut Step42State,
    process: ObjectId,
    slot_idx: usize,
    alias_gen: Option<u64>,
) -> Option<&'a mut HwFdSlot> {
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

fn resolve_hw_slot<'a>(
    state: &'a Step42State,
    process: ObjectId,
    slot_idx: usize,
    alias_gen: Option<u64>,
) -> Option<&'a HwFdSlot> {
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

fn retire_hw_slot_if_unused(state: &mut Step42State, slot_idx: usize) {
    let Some(entry) = state.fds.get(slot_idx).copied() else {
        return;
    };
    if !entry.live || !entry.owners.is_empty() || entry.alias_refs > 0 {
        return;
    }
    if entry.kind == HwNodeKind::DevWatchdog && entry.grant_rw {
        let _ = state.watchdog.release();
    }
    state.fds[slot_idx] = HwFdSlot::EMPTY;
}

fn node_path_bytes(kind: HwNodeKind, buf: &mut [u8; 40]) -> &[u8] {
    match kind {
        HwNodeKind::None => b"",
        HwNodeKind::DevRtc0 => b"/dev/rtc0",
        HwNodeKind::DevWatchdog => b"/dev/watchdog",
        HwNodeKind::DevHwRng => b"/dev/hwrng",
        HwNodeKind::DevVda => b"/dev/vda",
        HwNodeKind::DevVdaPart(part) => {
            let prefix = b"/dev/vda";
            let mut n = prefix.len();
            buf[..n].copy_from_slice(prefix);
            if part >= 10 {
                buf[n] = b'0' + (part / 10);
                n += 1;
            }
            buf[n] = b'0' + (part % 10);
            n += 1;
            &buf[..n]
        }
        HwNodeKind::SysRtcName => b"/sys/class/rtc/rtc0/name",
        HwNodeKind::SysRtcSinceEpoch => b"/sys/class/rtc/rtc0/since_epoch",
        HwNodeKind::SysThermalTemp => b"/sys/class/thermal/thermal_zone0/temp",
        HwNodeKind::SysThermalType => b"/sys/class/thermal/thermal_zone0/type",
        HwNodeKind::SysCpuOnline => b"/sys/devices/system/cpu/online",
        HwNodeKind::SysCpuPossible => b"/sys/devices/system/cpu/possible",
        HwNodeKind::SysVirtioMmioCount => b"/sys/bus/virtio/devices/mmio_count",
        HwNodeKind::SysRpiModel => b"/sys/firmware/devicetree/base/model",
        HwNodeKind::SysRpiRevision => b"/sys/bus/platform/drivers/bcm2837/board_revision",
        HwNodeKind::SysRpiArmClock => b"/sys/bus/platform/drivers/bcm2837/arm_clock_hz",
        HwNodeKind::SysRpiLan7515Speed => b"/sys/bus/platform/drivers/lan7515/link_speed",
        HwNodeKind::SysRpiActLed => b"/sys/class/leds/ACT/brightness",
        HwNodeKind::SysRpi4GenetV5 => b"/sys/bus/platform/drivers/bcm2711/genet_v5",
        HwNodeKind::SysRpi5Rp1Pcie => b"/sys/bus/platform/drivers/bcm2712/rp1_pcie",
        HwNodeKind::SysPcieInternetStatus => b"/sys/bus/pci/drivers/pcie_nic/status",
    }
}

fn retain_hw_slot(
    slot_idx: usize,
    owner: Option<ObjectId>,
    expected_gen: Option<u64>,
) -> Result<(SubsystemHandle, u64), Errno> {
    with_step42_state(|state| {
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
                kind: SUBSYS_HW,
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
    if !is_hw_fd(raw_fd) {
        return Err(Errno::EBADF);
    }
    let slot_idx = (linux_signed_int(raw_fd) - HW_FD_BASE) as usize;
    retain_hw_slot(slot_idx, Some(process), None)
}

pub(super) fn retain_existing_handle(
    handle: SubsystemHandle,
) -> Result<(SubsystemHandle, u64), Errno> {
    if handle.kind != SUBSYS_HW {
        return Err(Errno::EBADF);
    }
    retain_hw_slot(handle.slot as usize, None, Some(handle.generation))
}

pub(super) fn release_alias_handle(handle: SubsystemHandle) {
    if handle.kind != SUBSYS_HW {
        return;
    }
    let slot_idx = handle.slot as usize;
    let _ = with_step42_state(|state| {
        let Some(entry) = state.fds.get_mut(slot_idx) else {
            return;
        };
        if entry.live && entry.generation == handle.generation && entry.alias_refs > 0 {
            entry.alias_refs -= 1;
            retire_hw_slot_if_unused(state, slot_idx);
        }
    });
}

pub(super) fn handle_native_fcntl(
    process: ObjectId,
    raw_fd: u64,
    cmd: u32,
    argi: i32,
) -> Option<Result<i64, Errno>> {
    let Ok((slot_idx, alias_gen)) = resolve_hw_slot_idx(process, raw_fd) else {
        return None;
    };
    if alias_gen.is_some() && !matches!(cmd, 3 | 4) {
        return None;
    }
    let res = with_step42_state(|state| {
        let Some(entry) = resolve_hw_slot_mut(state, process, slot_idx, alias_gen) else {
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

pub(super) fn append_open_hw_fds(process: ObjectId, out: &mut alloc::vec::Vec<i32>) {
    let _ = with_step42_state(|state| {
        for (idx, entry) in state.fds.iter().enumerate() {
            if entry.live && entry.owners.has_owner(process) {
                out.push(HW_FD_BASE + (idx as i32));
            }
        }
    });
}

pub(super) fn describe_hw_slot(
    slot: u16,
    generation: Option<u64>,
    process: Option<ObjectId>,
    out: &mut [u8],
) -> Option<usize> {
    let mut written = None;
    let _ = with_step42_state(|state| {
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
        let mut path_buf = [0u8; 40];
        let path = node_path_bytes(entry.kind, &mut path_buf);
        let take = path.len().min(out.len());
        out[..take].copy_from_slice(&path[..take]);
        written = Some(take);
    });
    written
}

pub(super) fn on_process_fork(parent: ObjectId, child: ObjectId) {
    let _ = with_step42_state(|state| {
        for entry in &mut state.fds {
            if entry.live {
                entry.owners.on_fork(parent, child);
            }
        }
    });
}

pub(super) fn on_process_exec(process: ObjectId) {
    let _ = with_step42_state(|state| {
        for idx in 0..MAX_HW_FDS {
            if state.fds[idx].live {
                state.fds[idx].owners.close_cloexec_for(process);
                retire_hw_slot_if_unused(state, idx);
            }
        }
    });
}

pub(super) fn on_process_exit(process: ObjectId) {
    let _ = with_step42_state(|state| {
        for idx in 0..MAX_HW_FDS {
            if state.fds[idx].live {
                let _ = state.fds[idx].owners.close_owner(process);
                retire_hw_slot_if_unused(state, idx);
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
    let _ = with_step42_state(|state| {
        for idx in 0..MAX_HW_FDS {
            let fd = HW_FD_BASE + (idx as i32);
            if super::step_fd_util::fd_in_close_range(fd, first, last)
                && state.fds[idx].live
                && state.fds[idx]
                    .owners
                    .apply_close_range(process, cloexec_only)
            {
                retire_hw_slot_if_unused(state, idx);
            }
        }
    });
}

fn parse_vda_partition_number(path: &[u8]) -> Option<u8> {
    let suffix = path
        .strip_prefix(b"/dev/vda")
        .or_else(|| path.strip_prefix(b"/dev/mmcblk0p"))?;
    if suffix.is_empty() || suffix.len() > 2 {
        return None;
    }
    let mut num = 0u8;
    for &b in suffix {
        if !b.is_ascii_digit() {
            return None;
        }
        num = num.checked_mul(10)?.checked_add(b - b'0')?;
    }
    (1..=16).contains(&num).then_some(num)
}

fn match_hw_path(state: &Step42State, path: &[u8]) -> Option<HwNodeKind> {
    if let Some(part) = parse_vda_partition_number(path) {
        return state
            .partitions
            .by_number(part)
            .map(|_| HwNodeKind::DevVdaPart(part));
    }
    match path {
        b"/dev/rtc0" => Some(HwNodeKind::DevRtc0),
        b"/dev/watchdog" => Some(HwNodeKind::DevWatchdog),
        b"/dev/hwrng" => Some(HwNodeKind::DevHwRng),
        b"/dev/vda" | b"/dev/mmcblk0" => Some(HwNodeKind::DevVda),
        b"/sys/class/rtc/rtc0/name" => Some(HwNodeKind::SysRtcName),
        b"/sys/class/rtc/rtc0/since_epoch" => Some(HwNodeKind::SysRtcSinceEpoch),
        b"/sys/class/thermal/thermal_zone0/temp" => Some(HwNodeKind::SysThermalTemp),
        b"/sys/class/thermal/thermal_zone0/type" => Some(HwNodeKind::SysThermalType),
        b"/sys/devices/system/cpu/online" => Some(HwNodeKind::SysCpuOnline),
        b"/sys/devices/system/cpu/possible" => Some(HwNodeKind::SysCpuPossible),
        b"/sys/bus/virtio/devices/mmio_count" => Some(HwNodeKind::SysVirtioMmioCount),
        b"/sys/firmware/devicetree/base/model" => Some(HwNodeKind::SysRpiModel),
        b"/sys/bus/platform/drivers/bcm2837/board_revision" => Some(HwNodeKind::SysRpiRevision),
        b"/sys/bus/platform/drivers/bcm2837/arm_clock_hz" => Some(HwNodeKind::SysRpiArmClock),
        b"/sys/bus/platform/drivers/lan7515/link_speed" => Some(HwNodeKind::SysRpiLan7515Speed),
        b"/sys/class/leds/ACT/brightness" => Some(HwNodeKind::SysRpiActLed),
        b"/sys/bus/platform/drivers/bcm2711/genet_v5" => Some(HwNodeKind::SysRpi4GenetV5),
        b"/sys/bus/platform/drivers/bcm2712/rp1_pcie" => Some(HwNodeKind::SysRpi5Rp1Pcie),
        b"/sys/bus/pci/drivers/pcie_nic/status" => Some(HwNodeKind::SysPcieInternetStatus),
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

fn blk_read_at(
    dev: &mut dyn BlockDevice,
    base_sector: u64,
    sector_count: u64,
    pos: usize,
    user_buf: u64,
    count: usize,
) -> Result<usize, Errno> {
    let total_bytes =
        usize::try_from(sector_count.saturating_mul(SECTOR_SIZE as u64)).unwrap_or(usize::MAX);
    if pos >= total_bytes || count == 0 {
        return Ok(0);
    }
    let to_read = count.min(total_bytes - pos).min(65536);
    let mut bounce = [0u8; 4096];
    let mut done = 0usize;
    while done < to_read {
        let cur = pos + done;
        let inner_off = cur % SECTOR_SIZE;
        let rel_sector = (cur / SECTOR_SIZE) as u64;
        if inner_off == 0 && (to_read - done) >= SECTOR_SIZE {
            let sectors_avail = ((to_read - done) / SECTOR_SIZE).min(8);
            let byte_chunk = sectors_avail * SECTOR_SIZE;
            dev.read_sectors(base_sector + rel_sector, &mut bounce[..byte_chunk])?;
            copy_to_user(user_buf + done as u64, &bounce[..byte_chunk])?;
            done += byte_chunk;
        } else {
            dev.read_sectors(base_sector + rel_sector, &mut bounce[..SECTOR_SIZE])?;
            let take = (SECTOR_SIZE - inner_off).min(to_read - done);
            copy_to_user(user_buf + done as u64, &bounce[inner_off..inner_off + take])?;
            done += take;
        }
    }
    Ok(done)
}

fn blk_write_at(
    dev: &mut dyn BlockDevice,
    base_sector: u64,
    sector_count: u64,
    pos: usize,
    user_buf: u64,
    count: usize,
) -> Result<usize, Errno> {
    if dev.read_only() {
        return Err(Errno::EROFS);
    }
    let total_bytes =
        usize::try_from(sector_count.saturating_mul(SECTOR_SIZE as u64)).unwrap_or(usize::MAX);
    if pos >= total_bytes || count == 0 {
        return Err(Errno::ENOSPC);
    }
    let to_write = count.min(total_bytes - pos).min(65536);
    let mut bounce = [0u8; 4096];
    let mut done = 0usize;
    while done < to_write {
        let cur = pos + done;
        let inner_off = cur % SECTOR_SIZE;
        let rel_sector = (cur / SECTOR_SIZE) as u64;
        if inner_off == 0 && (to_write - done) >= SECTOR_SIZE {
            let sectors_avail = ((to_write - done) / SECTOR_SIZE).min(8);
            let byte_chunk = sectors_avail * SECTOR_SIZE;
            copy_from_user(&mut bounce[..byte_chunk], user_buf + done as u64)?;
            dev.write_sectors(base_sector + rel_sector, &bounce[..byte_chunk])?;
            done += byte_chunk;
        } else {
            dev.read_sectors(base_sector + rel_sector, &mut bounce[..SECTOR_SIZE])?;
            let take = (SECTOR_SIZE - inner_off).min(to_write - done);
            copy_from_user(
                &mut bounce[inner_off..inner_off + take],
                user_buf + done as u64,
            )?;
            dev.write_sectors(base_sector + rel_sector, &bounce[..SECTOR_SIZE])?;
            done += take;
        }
    }
    Ok(done)
}

pub(super) fn try_handle_syscall(request: SyscallRequest) -> Result<Option<SyscallReturn>, ()> {
    match request.number {
        29 if is_hw_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_ioctl(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        56 => handle_openat_if_hw(request.args[1], request.args[2]),
        57 if is_hw_fd(request.args[0]) => Ok(Some(encode_result(handle_close(request.args[0])?))),
        62 if is_hw_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_lseek(
            request.args[0],
            request.args[1] as i64,
            linux_signed_int(request.args[2]),
        )?))),
        63 if is_hw_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_read(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        64 if is_hw_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_write(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        65 if is_hw_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_readv(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        66 if is_hw_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_writev(
            request.args[0],
            request.args[1],
            request.args[2],
        )?))),
        67 if is_hw_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_pread64(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3] as usize,
        )?))),
        68 if is_hw_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_pwrite64(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3] as usize,
        )?))),
        79 => handle_newfstatat_if_hw(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
        ),
        80 if is_hw_fd_or_alias(request.args[0]) => Ok(Some(encode_result(handle_fstat(
            request.args[0],
            request.args[1],
        )?))),
        82 | 83 if is_hw_fd_or_alias(request.args[0]) => {
            Ok(Some(encode_result(handle_fsync(request.args[0])?)))
        }
        291 => handle_statx_if_hw(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[4],
        ),
        _ => Ok(None),
    }
}

pub(super) fn try_open_dev_bytes_if_block(
    path: &[u8],
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let is_path = (flags & O_PATH_U64) != 0;
    let accmode = flags & 0o3;
    let wants_write = !is_path && matches!(accmode, 1 | 2);
    let cloexec = (flags & O_CLOEXEC_U64) != 0;
    let status_flags = if is_path {
        O_PATH_U64
    } else {
        accmode | (flags & O_NONBLOCK_U64)
    };
    let res = with_step42_state(|state| {
        let Some(kind) = match_hw_path(state, path) else {
            return Ok(None);
        };
        if (flags & O_DIRECTORY_U64) != 0 {
            return Ok(Some(Err(Errno::ENOTDIR)));
        }
        let Some(process) = current_process_object() else {
            return Err(());
        };
        if wants_write && !kind.is_writable() {
            return Ok(Some(Err(Errno::EROFS)));
        }
        if kind == HwNodeKind::DevWatchdog
            && wants_write
            && let Err(e) = state.watchdog.start(HW_ADMIN_CAP)
        {
            return Ok(Some(Err(e)));
        }
        let Some((idx, _)) = state.fds.iter().enumerate().find(|(_, s)| !s.live) else {
            return Ok(Some(Err(Errno::EMFILE)));
        };
        let generation = state.next_fd_generation;
        state.next_fd_generation = state.next_fd_generation.saturating_add(1).max(1);
        let mut owners = DirectProcessRefs::empty();
        owners.init(process, cloexec);
        state.fds[idx] = HwFdSlot {
            live: true,
            kind,
            generation,
            owners,
            alias_refs: 0,
            offset: 0,
            grant_rw: wants_write,
            status_flags,
        };
        Ok(Some(Ok(i64::from(HW_FD_BASE + (idx as i32)))))
    })?;
    match res {
        Ok(Some(inner)) => Ok(Some(encode_result(inner))),
        Ok(None) => Ok(None),
        Err(()) => Err(()),
    }
}

fn handle_openat_if_hw(user_path: u64, flags: u64) -> Result<Option<SyscallReturn>, ()> {
    let mut path_buf = [0u8; 64];
    let Ok(len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    try_open_dev_bytes_if_block(&path_buf[..len], flags)
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
            let count = super::super::online_cpu_count();
            if count <= 1 {
                let s = b"0\n";
                out[..s.len()].copy_from_slice(s);
                s.len()
            } else {
                let last = b'0' + count.saturating_sub(1);
                let s = [b'0', b'-', last, b'\n'];
                out[..s.len()].copy_from_slice(&s);
                s.len()
            }
        }
        HwNodeKind::SysVirtioMmioCount => format_u64_line(state.discovered_virtio_mmio as u64, out),
        HwNodeKind::SysRpiModel => {
            let s = b"Raspberry Pi 3 Model B Plus Rev 1.3\n";
            out[..s.len()].copy_from_slice(s);
            s.len()
        }
        HwNodeKind::SysRpiRevision => {
            let s = b"00a020d3\n";
            out[..s.len()].copy_from_slice(s);
            s.len()
        }
        HwNodeKind::SysRpiArmClock => {
            format_u64_line(u64::from(state.rpi3b_plus.mailbox.arm_clock_hz), out)
        }
        HwNodeKind::SysRpiLan7515Speed => {
            format_u64_line(u64::from(state.rpi3b_plus.lan7515_nic.speed_mbps), out)
        }
        HwNodeKind::SysRpiActLed => {
            let on = state.rpi3b_plus.gpio.act_led_is_on();
            format_u64_line(u64::from(on), out)
        }
        HwNodeKind::SysRpi4GenetV5 => {
            let s = if state.rpi4b.genet_v5.link_up && state.rpi4b.pcie_rc.vl805_enumerated {
                b"bcm2711-genet-v5:1000Mbps pcie-vl805:1106:3483\n".as_slice()
            } else {
                b"down\n".as_slice()
            };
            out[..s.len()].copy_from_slice(s);
            s.len()
        }
        HwNodeKind::SysRpi5Rp1Pcie => {
            let s = if state.rpi5.rp1.enumerated && state.rpi5.rp1.eth_gem.link_up {
                b"rp1-pcie:1de4:0001-gen2x4 gem:1000Mbps xhci:2\n".as_slice()
            } else {
                b"down\n".as_slice()
            };
            out[..s.len()].copy_from_slice(s);
            s.len()
        }
        HwNodeKind::SysPcieInternetStatus => {
            let s = b"ipv4=10.0.2.15/24 gw=10.0.2.2 dns=10.0.2.3 nics=e1000e,igc,virtio_net,bcmgenet,macb_rp1\n";
            let take = s.len().min(out.len());
            out[..take].copy_from_slice(&s[..take]);
            take
        }
        _ => 0,
    }
}

fn read_slot_slice(
    state: &mut Step42State,
    slot_idx: usize,
    user_buf: u64,
    count: usize,
) -> Result<usize, Errno> {
    let slot = state.fds[slot_idx];
    if (slot.status_flags & O_PATH_U64) != 0 {
        return Err(Errno::EBADF);
    }
    match slot.kind {
        HwNodeKind::None => Err(Errno::EBADF),
        HwNodeKind::DevHwRng => {
            let mut tmp = [0u8; 64];
            let to_gen = count.min(tmp.len());
            state.entropy.fill_bytes(&mut tmp[..to_gen])?;
            copy_to_user(user_buf, &tmp[..to_gen])?;
            Ok(to_gen)
        }
        kind if kind.block_part_number().is_some() => {
            let part = kind.block_part_number().unwrap_or(0);
            let Some((base_sec, sec_count, _ro)) = state.block_window(part) else {
                return Err(Errno::ENODEV);
            };
            let read_bytes = state.with_active_block(|dev, _| {
                blk_read_at(dev, base_sec, sec_count, slot.offset, user_buf, count)
            })?;
            state.fds[slot_idx].offset += read_bytes;
            Ok(read_bytes)
        }
        HwNodeKind::DevRtc0 | HwNodeKind::DevWatchdog => Err(Errno::EINVAL),
        other => {
            let mut data = [0u8; 64];
            let total = materialize_sysfs(state, other, &mut data);
            let avail = &data[slot.offset.min(total)..total];
            let take = avail.len().min(count);
            if take > 0 {
                copy_to_user(user_buf, &avail[..take])?;
                state.fds[slot_idx].offset += take;
            }
            Ok(take)
        }
    }
}

fn write_slot_slice(
    state: &mut Step42State,
    slot_idx: usize,
    user_buf: u64,
    count: usize,
) -> Result<usize, Errno> {
    let slot = state.fds[slot_idx];
    if (slot.status_flags & O_PATH_U64) != 0 {
        return Err(Errno::EBADF);
    }
    match slot.kind {
        HwNodeKind::None => Err(Errno::EBADF),
        HwNodeKind::DevWatchdog => {
            let mut tmp = [0u8; 32];
            let take = count.min(tmp.len());
            copy_from_user(&mut tmp[..take], user_buf)?;
            state.watchdog.write_ping(HW_ADMIN_CAP, &tmp[..take])?;
            Ok(take)
        }
        HwNodeKind::SysRpiActLed => {
            if !slot.grant_rw {
                return Err(Errno::EACCES);
            }
            let mut tmp = [0u8; 8];
            let take = count.min(tmp.len());
            if take == 0 {
                return Ok(0);
            }
            copy_from_user(&mut tmp[..take], user_buf)?;
            let on = tmp[0] != b'0';
            state
                .rpi3b_plus
                .gpio
                .set_act_led(HW_ADMIN_CAP, on)
                .map_err(|e| e.to_errno())?;
            let _ = state.rpi3b_plus.mmio_hal.mmio_gpio_write_pin(
                HW_ADMIN_CAP,
                kernal_rpi3b_plus::RPI3B_PLUS_ACT_LED_PIN,
                on,
            );
            Ok(count)
        }
        kind if kind.block_part_number().is_some() => {
            if !slot.grant_rw {
                return Err(Errno::EACCES);
            }
            if count == 0 {
                return Ok(0);
            }
            let part = kind.block_part_number().unwrap_or(0);
            let Some((base_sec, sec_count, _ro)) = state.block_window(part) else {
                return Err(Errno::ENODEV);
            };
            let written = state.with_active_block(|dev, _| {
                blk_write_at(dev, base_sec, sec_count, slot.offset, user_buf, count)
            })?;
            state.fds[slot_idx].offset += written;
            Ok(written)
        }
        _ => Err(Errno::EROFS),
    }
}

fn resolve_slot_for_current(
    state: &Step42State,
    raw_fd: u64,
) -> Result<(ObjectId, usize, HwFdSlot), Errno> {
    let Some(process) = current_process_object() else {
        return Err(Errno::EPERM);
    };
    let (slot_idx, alias_gen) = resolve_hw_slot_idx(process, raw_fd)?;
    let Some(slot) = resolve_hw_slot(state, process, slot_idx, alias_gen).copied() else {
        return Err(Errno::EBADF);
    };
    Ok((process, slot_idx, slot))
}

fn handle_read(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    with_step42_state(|state| {
        let (_process, slot_idx, _) = resolve_slot_for_current(state, raw_fd)?;
        Ok(read_slot_slice(state, slot_idx, user_buf, count as usize)? as i64)
    })
}

fn handle_write(raw_fd: u64, user_buf: u64, count: u64) -> Result<Result<i64, Errno>, ()> {
    with_step42_state(|state| {
        let (_process, slot_idx, _) = resolve_slot_for_current(state, raw_fd)?;
        Ok(write_slot_slice(state, slot_idx, user_buf, count as usize)? as i64)
    })
}

fn handle_readv(raw_fd: u64, user_iov: u64, raw_iovcnt: u64) -> Result<Result<i64, Errno>, ()> {
    let iovcnt = linux_signed_int(raw_iovcnt);
    if !(0..=1024).contains(&iovcnt) {
        return Ok(Err(Errno::EINVAL));
    }
    with_step42_state(|state| {
        let (_process, slot_idx, _) = resolve_slot_for_current(state, raw_fd)?;
        let mut total = 0usize;
        for idx in 0..(iovcnt as usize) {
            let (base, len) = read_user_iovec(user_iov, idx)?;
            if len == 0 {
                continue;
            }
            let got = read_slot_slice(state, slot_idx, base, len)?;
            total = total.saturating_add(got);
            if got < len {
                break;
            }
        }
        Ok(total as i64)
    })
}

fn handle_writev(raw_fd: u64, user_iov: u64, raw_iovcnt: u64) -> Result<Result<i64, Errno>, ()> {
    let iovcnt = linux_signed_int(raw_iovcnt);
    if !(0..=1024).contains(&iovcnt) {
        return Ok(Err(Errno::EINVAL));
    }
    with_step42_state(|state| {
        let (_process, slot_idx, _) = resolve_slot_for_current(state, raw_fd)?;
        let mut total = 0usize;
        for idx in 0..(iovcnt as usize) {
            let (base, len) = read_user_iovec(user_iov, idx)?;
            if len == 0 {
                continue;
            }
            let put = write_slot_slice(state, slot_idx, base, len)?;
            total = total.saturating_add(put);
            if put < len {
                break;
            }
        }
        Ok(total as i64)
    })
}

fn handle_pread64(
    raw_fd: u64,
    user_buf: u64,
    count: u64,
    offset: usize,
) -> Result<Result<i64, Errno>, ()> {
    with_step42_state(|state| {
        let (_process, _slot_idx, slot) = resolve_slot_for_current(state, raw_fd)?;
        if (slot.status_flags & O_PATH_U64) != 0 {
            return Err(Errno::EBADF);
        }
        let Some(part) = slot.kind.block_part_number() else {
            return Err(Errno::ESPIPE);
        };
        let Some((base_sec, sec_count, _ro)) = state.block_window(part) else {
            return Err(Errno::ENODEV);
        };
        let n = state.with_active_block(|dev, _| {
            blk_read_at(dev, base_sec, sec_count, offset, user_buf, count as usize)
        })?;
        Ok(n as i64)
    })
}

fn handle_pwrite64(
    raw_fd: u64,
    user_buf: u64,
    count: u64,
    offset: usize,
) -> Result<Result<i64, Errno>, ()> {
    with_step42_state(|state| {
        let (_process, _slot_idx, slot) = resolve_slot_for_current(state, raw_fd)?;
        if (slot.status_flags & O_PATH_U64) != 0 {
            return Err(Errno::EBADF);
        }
        let Some(part) = slot.kind.block_part_number() else {
            return Err(Errno::ESPIPE);
        };
        if !slot.grant_rw {
            return Err(Errno::EACCES);
        }
        let Some((base_sec, sec_count, _ro)) = state.block_window(part) else {
            return Err(Errno::ENODEV);
        };
        let n = state.with_active_block(|dev, _| {
            blk_write_at(dev, base_sec, sec_count, offset, user_buf, count as usize)
        })?;
        Ok(n as i64)
    })
}

fn handle_fsync(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    with_step42_state(|state| {
        let (_process, _slot_idx, slot) = resolve_slot_for_current(state, raw_fd)?;
        if slot.kind.block_part_number().is_some() {
            state.with_active_block(|dev, _| dev.flush())?;
            Ok(0)
        } else {
            Ok(0)
        }
    })
}

fn handle_ioctl(raw_fd: u64, req: u64, arg: u64) -> Result<Result<i64, Errno>, ()> {
    with_step42_state(|state| {
        let (_process, _slot_idx, slot) = resolve_slot_for_current(state, raw_fd)?;
        if (slot.status_flags & O_PATH_U64) != 0 {
            return Err(Errno::EBADF);
        }
        match slot.kind {
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
            kind if kind.block_part_number().is_some() => {
                let part = kind.block_part_number().unwrap_or(0);
                let Some((_, sec_count, ro)) = state.block_window(part) else {
                    return Err(Errno::ENODEV);
                };
                match req {
                    BLKROGET => {
                        copy_to_user(arg, &(ro as i32).to_le_bytes())?;
                        Ok(0)
                    }
                    BLKGETSIZE => {
                        copy_to_user(arg, &(sec_count as usize).to_le_bytes())?;
                        Ok(0)
                    }
                    BLKFLSBUF => {
                        state.with_active_block(|dev, _| dev.flush())?;
                        Ok(0)
                    }
                    BLKSSZGET => {
                        copy_to_user(arg, &(SECTOR_SIZE as u32).to_le_bytes())?;
                        Ok(0)
                    }
                    BLKBSZGET => {
                        copy_to_user(arg, &4096usize.to_le_bytes())?;
                        Ok(0)
                    }
                    BLKGETSIZE64 => {
                        copy_to_user(
                            arg,
                            &sec_count.saturating_mul(SECTOR_SIZE as u64).to_le_bytes(),
                        )?;
                        Ok(0)
                    }
                    _ => Err(Errno::ENOTTY),
                }
            }
            HwNodeKind::None => Err(Errno::EBADF),
            _ => Err(Errno::ENOTTY),
        }
    })
}

fn handle_lseek(raw_fd: u64, offset: i64, whence: i32) -> Result<Result<i64, Errno>, ()> {
    with_step42_state(|state| {
        let (_process, slot_idx, slot) = resolve_slot_for_current(state, raw_fd)?;
        match slot.kind {
            HwNodeKind::None => Err(Errno::EBADF),
            kind if kind.block_part_number().is_some() => {
                let part = kind.block_part_number().unwrap_or(0);
                let total = state
                    .block_window(part)
                    .map(|(_, secs, _)| {
                        usize::try_from(secs.saturating_mul(SECTOR_SIZE as u64))
                            .unwrap_or(usize::MAX)
                    })
                    .unwrap_or(0);
                let next = seek_bounded(slot.offset, total, offset, whence)?;
                state.fds[slot_idx].offset = next;
                Ok(next as i64)
            }
            other => {
                let mut data = [0u8; 64];
                let total = materialize_sysfs(state, other, &mut data);
                let next = seek_bounded(slot.offset, total, offset, whence)?;
                state.fds[slot_idx].offset = next;
                Ok(next as i64)
            }
        }
    })
}

fn handle_close(raw_fd: u64) -> Result<Result<i64, Errno>, ()> {
    if !is_hw_fd(raw_fd) {
        return Ok(Err(Errno::EBADF));
    }
    let slot_idx = (linux_signed_int(raw_fd) - HW_FD_BASE) as usize;
    let Some(process) = current_process_object() else {
        return Err(());
    };
    with_step42_state(|state| {
        let Some(entry) = resolve_hw_slot_mut(state, process, slot_idx, None) else {
            return Err(Errno::EBADF);
        };
        let _ = entry.owners.close_owner(process);
        retire_hw_slot_if_unused(state, slot_idx);
        Ok(0)
    })
}

fn node_stat_meta(state: &Step42State, kind: HwNodeKind) -> StatMeta {
    let size = match kind {
        other if other.block_part_number().is_some() => {
            let part = other.block_part_number().unwrap_or(0);
            state
                .block_window(part)
                .map(|(_, secs, _)| secs.saturating_mul(SECTOR_SIZE as u64))
                .unwrap_or(0)
        }
        HwNodeKind::DevRtc0 | HwNodeKind::DevWatchdog | HwNodeKind::DevHwRng => 0,
        other => {
            let mut data = [0u8; 64];
            materialize_sysfs(state, other, &mut data) as u64
        }
    };
    let (rdev, ino) = match kind {
        HwNodeKind::DevVda => ((254u64 << 8) | 0, 42_000),
        HwNodeKind::DevVdaPart(p) => ((254u64 << 8) | u64::from(p), 42_000 + u64::from(p)),
        HwNodeKind::DevRtc0 => ((253u64 << 8) | 0, 42_100),
        HwNodeKind::DevWatchdog => ((10u64 << 8) | 130, 42_101),
        HwNodeKind::DevHwRng => ((10u64 << 8) | 183, 42_102),
        _ => (0, 42_200),
    };
    StatMeta {
        dev: 1,
        ino,
        mode: kind.stat_mode(),
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev,
        size,
        blksize: 4096,
        blocks: size.div_ceil(512),
        atime_sec: 1_784_000_000,
        atime_nsec: 0,
        mtime_sec: 1_784_000_000,
        mtime_nsec: 0,
        ctime_sec: 1_784_000_000,
        ctime_nsec: 0,
        mnt_id: 0,
        is_mount_root: false,
    }
}

fn fill_hw_mount_meta(meta: &mut StatMeta, kind: HwNodeKind) {
    let fstype = match kind {
        HwNodeKind::DevVda
        | HwNodeKind::DevVdaPart(_)
        | HwNodeKind::DevRtc0
        | HwNodeKind::DevWatchdog
        | HwNodeKind::DevHwRng => kernal_linux_mounts::FilesystemType::Devtmpfs,
        _ => kernal_linux_mounts::FilesystemType::Sysfs,
    };
    let (dev, _, _, mnt_id) = super::step33_mounts::dev_and_mnt_id_for_fstype(fstype);
    meta.dev = dev;
    meta.mnt_id = mnt_id;
}

pub(super) fn try_stat_hw_bytes(path: &[u8], user_stat: u64) -> Result<Option<SyscallReturn>, ()> {
    let found = with_step42_state(|state| {
        match_hw_path(state, path).map(|kind| (kind, node_stat_meta(state, kind)))
    })?;
    let Some((kind, mut meta)) = found else {
        return Ok(None);
    };
    fill_hw_mount_meta(&mut meta, kind);
    Ok(Some(encode_result(
        super::step_fd_util::write_aarch64_stat_meta(user_stat, &meta),
    )))
}

pub(super) fn try_statx_hw_bytes(
    path: &[u8],
    user_statx: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let found = with_step42_state(|state| {
        match_hw_path(state, path).map(|kind| (kind, node_stat_meta(state, kind)))
    })?;
    let Some((kind, mut meta)) = found else {
        return Ok(None);
    };
    fill_hw_mount_meta(&mut meta, kind);
    Ok(Some(encode_result(write_aarch64_statx_meta(
        user_statx, &meta,
    ))))
}

fn lookup_stat_meta_for_at(
    dirfd: u64,
    user_path: u64,
    flags: u64,
) -> Result<Option<Result<StatMeta, Errno>>, ()> {
    let mut path_buf = [0u8; 64];
    let Ok(len) = read_user_cstr(user_path, &mut path_buf) else {
        return Ok(None);
    };
    if len == 0 && (flags & AT_EMPTY_PATH) != 0 && is_hw_fd_or_alias(dirfd) {
        let res = with_step42_state(|state| {
            let (_process, _slot_idx, slot) = resolve_slot_for_current(state, dirfd)?;
            Ok((slot.kind, node_stat_meta(state, slot.kind)))
        })?;
        return Ok(Some(res.map(|(kind, mut meta)| {
            fill_hw_mount_meta(&mut meta, kind);
            meta
        })));
    }
    let meta = with_step42_state(|state| {
        match_hw_path(state, &path_buf[..len]).map(|kind| (kind, node_stat_meta(state, kind)))
    })?;
    Ok(meta.map(|(kind, mut m)| {
        fill_hw_mount_meta(&mut m, kind);
        Ok(m)
    }))
}

fn handle_fstat(raw_fd: u64, user_stat: u64) -> Result<Result<i64, Errno>, ()> {
    let meta = with_step42_state(|state| {
        let (_process, _slot_idx, slot) = resolve_slot_for_current(state, raw_fd)?;
        Ok((slot.kind, node_stat_meta(state, slot.kind)))
    })?;
    match meta {
        Ok((kind, mut m)) => {
            fill_hw_mount_meta(&mut m, kind);
            Ok(super::step_fd_util::write_aarch64_stat_meta(user_stat, &m))
        }
        Err(e) => Ok(Err(e)),
    }
}

fn handle_newfstatat_if_hw(
    dirfd: u64,
    user_path: u64,
    user_stat: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let Some(res) = lookup_stat_meta_for_at(dirfd, user_path, flags)? else {
        return Ok(None);
    };
    let out = match res {
        Ok(m) => super::step_fd_util::write_aarch64_stat_meta(user_stat, &m),
        Err(e) => Err(e),
    };
    Ok(Some(encode_result(out)))
}

fn handle_statx_if_hw(
    dirfd: u64,
    user_path: u64,
    flags: u64,
    user_statx: u64,
) -> Result<Option<SyscallReturn>, ()> {
    let Some(res) = lookup_stat_meta_for_at(dirfd, user_path, flags)? else {
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
    fn hw_fd_window_is_disjoint() {
        assert!(!is_hw_fd(224));
        assert!(!is_hw_fd(239));
        assert!(is_hw_fd(HW_FD_BASE as u64));
        assert!(is_hw_fd((HW_FD_BASE + 15) as u64));
        assert!(!is_hw_fd((HW_FD_BASE + 16) as u64));
    }
}
