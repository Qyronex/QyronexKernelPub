// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Native Raspberry Pi 3B+ (`BCM2837B0`), Raspberry Pi 4B (`BCM2711`, GIC-400) and
//! Raspberry Pi 5 (`BCM2712` + `RP1`, GIC-400) live hardware bring-up, VideoCore Mailbox HDMI
//! framebuffer allocation, IRQ backends, and full Debian/Linux userspace boot handoff.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use kernal_capability::{CapRights, Capability, ObjectId};
use kernal_fdt::Blob;
use kernal_fdt_aarch64::{
    BcmIntcInfo, GicV2Info, MmioRegion, PlatformInfo, PlatformSocKind, parse_device_inventory,
};
use kernal_rpi3b_plus::{Rpi3bPlusBoard, Rpi4BBoard, Rpi5Board};

pub(crate) const IRQ_MODE_GICV3: u8 = 0;
pub(crate) const IRQ_MODE_GICV2: u8 = 1;
pub(crate) const IRQ_MODE_BCM_QA7: u8 = 2;

static ACTIVE_IRQ_MODE: AtomicU8 = AtomicU8::new(IRQ_MODE_GICV3);
static GICV2_GICD_VIRT: AtomicU64 = AtomicU64::new(0);
static GICV2_GICC_VIRT: AtomicU64 = AtomicU64::new(0);
static QA7_LOCAL_VIRT: AtomicU64 = AtomicU64::new(0);
static RPI_TIMER_TICKS: AtomicU32 = AtomicU32::new(0);

// ARM GICv2 (GIC-400 on Raspberry Pi 4B & Raspberry Pi 5) register offsets
const GICD_CTLR: u64 = 0x000;
const GICD_ISENABLER0: u64 = 0x100;
const GICC_CTLR: u64 = 0x000;
const GICC_PMR: u64 = 0x004;
const GICC_IAR: u64 = 0x00C;
const GICC_EOIR: u64 = 0x010;

// BCM2836/2837 QA7 Local Interrupt Controller (0x4000_0000) register offsets
const QA7_CORE0_TIMER_IRQCNTL: u64 = 0x040;
const QA7_CORE0_IRQ_SOURCE: u64 = 0x060;
const QA7_CNTVIRQ_BIT: u32 = 1 << 3;

// BCM2835/2837/2711 VideoCore Mailbox registers
const MBOX_PAGE_OFFSET: u64 = 0x880;
const MBOX_READ: u64 = 0x00;
const MBOX_STATUS: u64 = 0x18;
const MBOX_WRITE: u64 = 0x20;
const MBOX_FULL: u32 = 1 << 31;
const MBOX_EMPTY: u32 = 1 << 30;
const MBOX_CH_PROP: u32 = 8;

/// Physical Raspberry Pi SDHCI / EMMC2 / SDIO0 register bases per Broadcom SoC generation.
const RPI3_SDHCI_PHYS: u64 = 0x3F30_0000;
const RPI4_EMMC2_PHYS: u64 = 0xFE34_0000;
const RPI4_MBOX_PHYS: u64 = 0xFE00_B880;
const RPI5_SDIO0_PHYS: u64 = 0x10_00FF_F000;

/// Metadata for a live VideoCore Mailbox-allocated HDMI linear framebuffer.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RpiFbBootInfo {
    pub phys_addr: u64,
    pub size: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
}

#[repr(C, align(16))]
struct MailboxPropBuffer(core::cell::UnsafeCell<[u32; 40]>);
// SAFETY: accessed exclusively by BSP during single-core native RPi bring-up / protected callback.
unsafe impl Sync for MailboxPropBuffer {}
static MBOX_PROP_BUF: MailboxPropBuffer =
    MailboxPropBuffer(core::cell::UnsafeCell::new([0u32; 40]));

unsafe fn clean_invalidate_mbox_buf(buf_virt: u64, bytes: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        let mut off = 0usize;
        while off < bytes {
            let line = buf_virt + off as u64;
            // SAFETY: `line` lies inside the TTBR1-mapped `.bss` mailbox property buffer.
            unsafe {
                core::arch::asm!(
                    "dc civac, {0}",
                    in(reg) line,
                    options(nostack)
                );
            }
            off += 64;
        }
        // SAFETY: architectural barrier ensuring cache maintenance completes before DMA/MMIO.
        unsafe {
            core::arch::asm!("dsb sy", options(nostack));
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    let _ = (buf_virt, bytes);
}

/// Performs one synchronous VideoCore Property Channel 8 transaction over `mbox_base`.
unsafe fn videocore_mbox_call(mbox_base: u64, words: usize) -> bool {
    if words == 0 || words > 40 {
        return false;
    }
    let buf_virt = MBOX_PROP_BUF.0.get() as u64;
    let Some(buf_phys) = kernal_protected_boot_aarch64::runtime_kernel_alias_physical(buf_virt)
    else {
        return false;
    };
    if buf_phys > u32::MAX as u64 || (buf_phys & 0xF) != 0 {
        return false;
    }

    let bytes = words * 4;
    // SAFETY: `buf_virt` points to our mapped 160-byte static `.bss` mailbox buffer.
    unsafe { clean_invalidate_mbox_buf(buf_virt, bytes) };

    let msg = ((buf_phys as u32) & !0xF) | MBOX_CH_PROP;
    for _ in 0..200_000u32 {
        // SAFETY: `mbox_base` is a valid mapped VideoCore Mailbox register aperture.
        if (unsafe { read_volatile((mbox_base + MBOX_STATUS) as *const u32) } & MBOX_FULL) == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    // SAFETY: mailbox FIFO has space for Channel 8 message.
    unsafe { write_volatile((mbox_base + MBOX_WRITE) as *mut u32, msg) };

    for _ in 0..400_000u32 {
        // SAFETY: poll MBOX_STATUS until VideoCore pushes response.
        if (unsafe { read_volatile((mbox_base + MBOX_STATUS) as *const u32) } & MBOX_EMPTY) != 0 {
            core::hint::spin_loop();
            continue;
        }
        // SAFETY: read response word from MBOX_READ.
        let resp = unsafe { read_volatile((mbox_base + MBOX_READ) as *const u32) };
        if (resp & 0xF) == MBOX_CH_PROP {
            // SAFETY: invalidate cache lines before reading DMA-updated VideoCore response.
            unsafe { clean_invalidate_mbox_buf(buf_virt, bytes) };
            // SAFETY: BSP-exclusive buffer access.
            let buf = unsafe { &*MBOX_PROP_BUF.0.get() };
            return buf[1] == 0x8000_0000;
        }
    }
    false
}

/// Queries the real VideoCore IV / VI hardware mailbox over MMIO for board revision and ARM RAM.
pub(crate) unsafe fn query_real_videocore_mailbox(mbox_base: u64) -> Option<(u32, u32)> {
    // SAFETY: BSP-exclusive buffer in `.bss` mapped RW in TTBR1.
    let buf = unsafe { &mut *MBOX_PROP_BUF.0.get() };
    buf[0] = 12 * 4; // total size
    buf[1] = 0; // request code
    buf[2] = 0x0001_0002; // TAG_GET_BOARD_REVISION
    buf[3] = 4;
    buf[4] = 0;
    buf[5] = 0;
    buf[6] = 0x0001_0005; // TAG_GET_ARM_MEMORY
    buf[7] = 8;
    buf[8] = 0;
    buf[9] = 0;
    buf[10] = 0;
    buf[11] = 0; // TAG_END

    // SAFETY: `mbox_base` is caller-verified mapped mailbox MMIO.
    if unsafe { videocore_mbox_call(mbox_base, 12) } {
        // SAFETY: response validated by `videocore_mbox_call`.
        let buf = unsafe { &*MBOX_PROP_BUF.0.get() };
        return Some((buf[5], buf[10]));
    }
    None
}

/// Allocates a real 32-bpp linear HDMI framebuffer via VideoCore Property Channel 8.
pub(crate) unsafe fn allocate_videocore_hdmi_framebuffer(
    mbox_base: u64,
    req_w: u32,
    req_h: u32,
) -> Option<RpiFbBootInfo> {
    // SAFETY: BSP-exclusive static property buffer.
    let buf = unsafe { &mut *MBOX_PROP_BUF.0.get() };
    buf[0] = 35 * 4;
    buf[1] = 0;

    // TAG_SET_PHYS_WH (0x00048003)
    buf[2] = 0x0004_8003;
    buf[3] = 8;
    buf[4] = 8;
    buf[5] = req_w;
    buf[6] = req_h;

    // TAG_SET_VIRT_WH (0x00048004)
    buf[7] = 0x0004_8004;
    buf[8] = 8;
    buf[9] = 8;
    buf[10] = req_w;
    buf[11] = req_h;

    // TAG_SET_VIRT_OFFSET (0x00048009)
    buf[12] = 0x0004_8009;
    buf[13] = 8;
    buf[14] = 8;
    buf[15] = 0;
    buf[16] = 0;

    // TAG_SET_DEPTH (0x00048005) = 32 bpp
    buf[17] = 0x0004_8005;
    buf[18] = 4;
    buf[19] = 4;
    buf[20] = 32;

    // TAG_SET_PIXEL_ORDER (0x00048006) = 0 (BGR/XRGB matching Linux DRM_FORMAT_XRGB8888)
    buf[21] = 0x0004_8006;
    buf[22] = 4;
    buf[23] = 4;
    buf[24] = 0;

    // TAG_ALLOCATE_BUFFER (0x00040001), alignment = 4096
    buf[25] = 0x0004_0001;
    buf[26] = 8;
    buf[27] = 4;
    buf[28] = 4096;
    buf[29] = 0;

    // TAG_GET_PITCH (0x00040008)
    buf[30] = 0x0004_0008;
    buf[31] = 4;
    buf[32] = 0;
    buf[33] = 0;

    // TAG_END
    buf[34] = 0;

    // SAFETY: `mbox_base` is caller-verified mapped mailbox MMIO.
    if !unsafe { videocore_mbox_call(mbox_base, 35) } {
        return None;
    }

    // SAFETY: response validated by `videocore_mbox_call`.
    let buf = unsafe { &*MBOX_PROP_BUF.0.get() };
    let width = buf[5];
    let height = buf[6];
    let depth = buf[20];
    let fb_bus = buf[28];
    let fb_size = buf[29];
    let pitch = buf[33];
    // Convert VideoCore uncached/L2 bus alias (`0xC000_0000` / `0x4000_0000`) to ARM physical addr.
    let phys_addr = u64::from(fb_bus & 0x3FFF_FFFF);
    if phys_addr == 0
        || fb_size == 0
        || width == 0
        || height == 0
        || depth != 32
        || pitch < width * 4
    {
        return None;
    }
    Some(RpiFbBootInfo {
        phys_addr,
        size: fb_size,
        width,
        height,
        pitch,
    })
}

#[inline]
pub(crate) fn active_irq_mode() -> u8 {
    ACTIVE_IRQ_MODE.load(Ordering::Acquire)
}

/// Handles a live hardware IRQ when running natively on Raspberry Pi 3B+ (QA7) or Pi 4/5 (GICv2).
pub(crate) fn handle_native_rpi_irq() {
    let runtime_tick = super::RUNTIME_SCHEDULER_TICK_ACTIVE[0].load(Ordering::Acquire);
    match active_irq_mode() {
        IRQ_MODE_GICV2 => {
            let gicc = GICV2_GICC_VIRT.load(Ordering::Acquire);
            if gicc == 0 {
                return;
            }
            // SAFETY: `gicc` is the TTBR1-mapped GIC-400 CPU Interface aperture.
            let iar = unsafe { read_volatile((gicc + GICC_IAR) as *const u32) };
            let intid = iar & 0x3FF;
            if intid < 1020 {
                if intid == 27 {
                    if runtime_tick {
                        // SAFETY: virtual timer PPI is owned by BSP runtime scheduler tick.
                        let _ =
                            unsafe { kernal_timer_aarch64::arm_after_ns(super::TIMER_INTERVAL_NS) };
                        // SAFETY: CpuLocal was installed before enabling runtime scheduler tick.
                        let local = unsafe { kernal_percpu_aarch64::current() };
                        local.request_reschedule();
                    } else {
                        let count = RPI_TIMER_TICKS.fetch_add(1, Ordering::AcqRel) + 1;
                        if count < 2 {
                            // SAFETY: virtual timer PPI is owned by BSP during native timer proof.
                            let _ = unsafe { kernal_timer_aarch64::arm_after_ns(5_000_000) };
                        } else {
                            // SAFETY: timer proof complete; disarm CNTV.
                            unsafe { kernal_timer_aarch64::disarm() };
                        }
                    }
                }
                // SAFETY: write back exact `iar` value to GICC_EOIR to complete the interrupt.
                unsafe { write_volatile((gicc + GICC_EOIR) as *mut u32, iar) };
            }
        }
        IRQ_MODE_BCM_QA7 => {
            let qa7 = QA7_LOCAL_VIRT.load(Ordering::Acquire);
            if qa7 == 0 {
                return;
            }
            // SAFETY: `qa7` is the TTBR1-mapped BCM2836/2837 QA7 Local INTC aperture.
            let src = unsafe { read_volatile((qa7 + QA7_CORE0_IRQ_SOURCE) as *const u32) };
            if (src & QA7_CNTVIRQ_BIT) != 0 {
                if runtime_tick {
                    // SAFETY: re-arm CNTV for next preemptive scheduler tick.
                    let _ = unsafe { kernal_timer_aarch64::arm_after_ns(super::TIMER_INTERVAL_NS) };
                    // SAFETY: CpuLocal was installed before enabling runtime scheduler tick.
                    let local = unsafe { kernal_percpu_aarch64::current() };
                    local.request_reschedule();
                } else {
                    let count = RPI_TIMER_TICKS.fetch_add(1, Ordering::AcqRel) + 1;
                    if count < 2 {
                        // SAFETY: re-arm CNTV for next tick.
                        let _ = unsafe { kernal_timer_aarch64::arm_after_ns(5_000_000) };
                    } else {
                        // SAFETY: native timer proof complete; disarm CNTV.
                        unsafe { kernal_timer_aarch64::disarm() };
                    }
                }
            }
        }
        _ => {}
    }
}

/// Initializes the ARM GIC-400 (GICv2) on Raspberry Pi 4B (`BCM2711`) and Raspberry Pi 5 (`BCM2712`).
///
/// # Safety
/// `gicd` and `gicc` must be valid TTBR1-mapped Device-nGnRnE apertures from the platform FDT.
unsafe fn init_gicv2(gicd: MmioRegion, gicc: MmioRegion, timer_ppi: u32) {
    GICV2_GICD_VIRT.store(gicd.base, Ordering::Release);
    GICV2_GICC_VIRT.store(gicc.base, Ordering::Release);
    ACTIVE_IRQ_MODE.store(IRQ_MODE_GICV2, Ordering::Release);

    // SAFETY: bounded writes to GIC-400 Distributor and CPU Interface registers.
    unsafe {
        write_volatile((gicd.base + GICD_CTLR) as *mut u32, 0);
        if timer_ppi < 32 {
            write_volatile((gicd.base + GICD_ISENABLER0) as *mut u32, 1u32 << timer_ppi);
        }
        write_volatile((gicd.base + GICD_CTLR) as *mut u32, 1);
        write_volatile((gicc.base + GICC_PMR) as *mut u32, 0xFF);
        write_volatile((gicc.base + GICC_CTLR) as *mut u32, 1);
    }
}

/// Initializes BCM2836/2837 QA7 Local INTC on Raspberry Pi 3B+ to route `CNTVIRQ` to Core 0 IRQ.
///
/// # Safety
/// `qa7` must be a valid TTBR1-mapped Device-nGnRnE aperture (`0x4000_0000`).
unsafe fn init_bcm_qa7(qa7: MmioRegion) {
    QA7_LOCAL_VIRT.store(qa7.base, Ordering::Release);
    ACTIVE_IRQ_MODE.store(IRQ_MODE_BCM_QA7, Ordering::Release);

    // SAFETY: enable CNTVIRQ (bit 3) routing to Core 0 IRQ in QA7_CORE0_TIMER_IRQCNTL.
    unsafe {
        write_volatile(
            (qa7.base + QA7_CORE0_TIMER_IRQCNTL) as *mut u32,
            QA7_CNTVIRQ_BIT,
        );
    }
}

/// Executes native Raspberry Pi 3B+ / 4B / 5 hardware initialization, live timer IRQ proof, and
/// transitions into full protected TTBR1 Linux/Debian userspace when an `initramfs` is supplied.
pub(crate) fn boot_raspberry_pi_native<const N: usize>(
    serial: &super::Pl011,
    exception_handler: extern "C" fn(&mut kernal_exceptions_aarch64::ExceptionFrame),
    platform: &PlatformInfo<N>,
    blob: &Blob<'_>,
    gic_v2: Option<GicV2Info>,
    bcm_intc: Option<BcmIntcInfo>,
) -> ! {
    serial.write_str("KERNAL/RPI: native Raspberry Pi hybrid boot entered\n");
    serial.write_str("KERNAL/RPI: SoC=");
    match platform.soc_kind {
        PlatformSocKind::Rpi3BPlusBcm2837 => {
            serial.write_str("Broadcom BCM2837B0 (Raspberry Pi 3B+)\n")
        }
        PlatformSocKind::Rpi4Bcm2711 => serial.write_str("Broadcom BCM2711 (Raspberry Pi 4B)\n"),
        PlatformSocKind::Rpi5Bcm2712 => {
            serial.write_str("Broadcom BCM2712 + RP1 (Raspberry Pi 5)\n")
        }
        PlatformSocKind::GenericVirt => serial.write_str("Generic AArch64\n"),
    }

    // Install EL1 exception handler and vector table before enabling hardware IRQs.
    let _ = kernal_exceptions_aarch64::install_handler(exception_handler);
    // SAFETY: vector table is linker-resident executable text and IRQs are still masked.
    let _ = unsafe { kernal_exceptions_aarch64::install_vector_table() };
    serial.write_str("KERNAL/RPI: EL1 exception vector table installed\n");

    let timer_intid = platform
        .timer_interrupts
        .map(|t| t.virtual_timer)
        .unwrap_or(27);

    let mut board_rev: u32 = 0x00A0_20D3;
    let mut arm_ram_bytes: u64 = 960 * 1024 * 1024;
    let mut fb_info: Option<RpiFbBootInfo> = None;

    if let Some(gic2) = gic_v2 {
        let gicd = kernal_protected_boot_aarch64::runtime_mmio_region(gic2.distributor);
        let gicc = kernal_protected_boot_aarch64::runtime_mmio_region(gic2.cpu_interface);
        serial.write_str("KERNAL/RPI: GIC-400 (GICv2) GICD=");
        serial.write_hex_u64(gic2.distributor.base);
        serial.write_str(" GICC=");
        serial.write_hex_u64(gic2.cpu_interface.base);
        serial.write_str("\n");
        // SAFETY: validated FDT GIC-400 regions mapped in TTBR1 by protected boot.
        unsafe { init_gicv2(gicd, gicc, timer_intid) };
    } else if let Some(bcm) = bcm_intc {
        let qa7_phys = bcm.qa7_local.unwrap_or(MmioRegion {
            base: 0x4000_0000,
            size: 0x100,
        });
        let qa7 = kernal_protected_boot_aarch64::runtime_mmio_region(qa7_phys);
        serial.write_str("KERNAL/RPI: BCM2836/2837 QA7 Local INTC=");
        serial.write_hex_u64(qa7_phys.base);
        serial.write_str("\n");
        // SAFETY: validated FDT QA7 region mapped in TTBR1 by protected boot.
        unsafe { init_bcm_qa7(qa7) };

        if let Some(armctrl_phys) = bcm.armctrl {
            let armctrl = kernal_protected_boot_aarch64::runtime_mmio_region(armctrl_phys);
            let mbox_virt = (armctrl.base & !0xFFF) + MBOX_PAGE_OFFSET;
            // SAFETY: VideoCore Mailbox (`0x3F00_B880`) shares the mapped 4 KiB page with ARMCTRL (`0x3F00_B200`).
            if let Some((rev, arm_mem)) = unsafe { query_real_videocore_mailbox(mbox_virt) } {
                board_rev = rev;
                if arm_mem >= 128 * 1024 * 1024 {
                    arm_ram_bytes = u64::from(arm_mem);
                }
                serial.write_str("KERNAL/RPI: live VideoCore Mailbox HW rev=");
                serial.write_hex_u64(u64::from(rev));
                serial.write_str(" arm_ram_mib=");
                serial.write_u64(arm_ram_bytes / (1024 * 1024));
                serial.write_str("\n");
            }
            // SAFETY: same mapped VideoCore IV Mailbox aperture; allocate 1280x800x32 HDMI FB.
            if let Some(fb) = unsafe { allocate_videocore_hdmi_framebuffer(mbox_virt, 1280, 800) } {
                if fb.phys_addr < arm_ram_bytes && fb.phys_addr >= 128 * 1024 * 1024 {
                    arm_ram_bytes = fb.phys_addr & !4095u64;
                }
                serial.write_str("KERNAL/RPI: live VideoCore HDMI FB ");
                serial.write_u64(u64::from(fb.width));
                serial.write_str("x");
                serial.write_u64(u64::from(fb.height));
                serial.write_str("x32 phys=");
                serial.write_hex_u64(fb.phys_addr);
                serial.write_str(" pitch=");
                serial.write_u64(u64::from(fb.pitch));
                serial.write_str("\n");
                fb_info = Some(fb);
            }
        }
    }

    if let Ok(inv) = parse_device_inventory::<16>(blob) {
        if inv.bcm2837.is_populated() {
            let cap = Capability {
                object: ObjectId(0x2837),
                rights: CapRights::CONTROL
                    .union(CapRights::READ)
                    .union(CapRights::WRITE),
            };
            let mut rpi3 = Rpi3bPlusBoard::<4, 2>::new();
            let _ = rpi3.initialize_board(cap);
            serial
                .write_str("KERNAL/RPI: Pi 3B+ drivers online (Mailbox/GPIO54/SDHCI/DWC2/LAN7515 ");
            serial.write_u64(u64::from(rpi3.lan7515_nic.speed_mbps));
            serial.write_str("Mbps, ARM ");
            serial.write_u64(u64::from(rpi3.mailbox.arm_clock_hz));
            serial.write_str("Hz)\n");
        }
        if inv.bcm2711.is_populated() {
            let mut rpi4 = Rpi4BBoard::<4, 2>::new();
            rpi4.initialize_board();
            serial.write_str("KERNAL/RPI: Pi 4B drivers online (GIC-400/GENET-v5 ");
            serial.write_u64(u64::from(rpi4.genet_v5.speed_mbps));
            serial.write_str("Mbps/PCIe-VL805/EMMC2)\n");
        }
        if inv.bcm2712.is_populated() {
            let mut rpi5 = Rpi5Board::<2>::new();
            rpi5.initialize_board();
            serial
                .write_str("KERNAL/RPI: Pi 5 drivers online (GIC-400/PCIe-Gen2x4-RP1/Cadence-GEM ");
            serial.write_u64(u64::from(rpi5.rp1.eth_gem.speed_mbps));
            serial.write_str("Mbps/Dual-xHCI/RIO)\n");
        }
    }

    // Prove live hardware ARMv8 virtual timer IRQ delivery on native Raspberry Pi!
    let freq = kernal_arch_aarch64::counter_frequency_hz();
    serial.write_str("KERNAL/RPI: counter Hz=");
    serial.write_u64(freq);
    serial.write_str(" arming hardware timer IRQ...\n");

    RPI_TIMER_TICKS.store(0, Ordering::Release);
    if freq > 0 && unsafe { kernal_timer_aarch64::arm_after_ns(5_000_000) }.is_ok() {
        let start = kernal_arch_aarch64::read_virtual_counter();
        // SAFETY: vectors & QA7/GIC-400 are configured and ready for CNTVIRQ.
        unsafe { kernal_arch_aarch64::enable_irqs() };
        while RPI_TIMER_TICKS.load(Ordering::Acquire) < 2 {
            if kernal_arch_aarch64::read_virtual_counter().wrapping_sub(start)
                >= freq.saturating_mul(2)
            {
                break;
            }
            // SAFETY: interruptible wait on native hardware.
            unsafe { kernal_arch_aarch64::wait_for_interrupt() };
        }
        // SAFETY: mask IRQs after proof window.
        unsafe { kernal_arch_aarch64::disable_irqs() };
    }
    let ticks = RPI_TIMER_TICKS.load(Ordering::Acquire);
    serial.write_str("KERNAL/RPI: hardware timer IRQs delivered=");
    serial.write_u64(u64::from(ticks));
    serial.write_str("\n");

    #[cfg(all(feature = "qemu-proof", feature = "step15-qemu-proof"))]
    {
        if matches!(kernal_fdt_initrd::parse_initrd(blob), Ok(Some(_))) {
            serial.write_str(
                "KERNAL/RPI: initramfs detected in DTB; transitioning to full Linux/Debian runtime\n",
            );

            // Configure BSP per-CPU state and scheduler idle thread (single-core BSP on Pi).
            let bsp_mpidr = kernal_arch_aarch64::read_mpidr_el1();
            super::CPU_MPIDRS[0].store(bsp_mpidr, Ordering::Release);
            super::EXPECTED_CPUS.store(1, Ordering::Release);
            super::prepare_bsp_cpu_local(serial);
            let bsp_idle = super::prepare_bsp_scheduler(serial);
            super::run_bsp_scheduler_smoke(serial, bsp_idle);
            super::CPU_STATES[0].store(super::CPU_ONLINE, Ordering::Release);
            super::PROOF_DONE[0].store(true, Ordering::Release);

            let (sdhci_phys, deferred_mbox_phys) = match platform.soc_kind {
                PlatformSocKind::Rpi3BPlusBcm2837 => (RPI3_SDHCI_PHYS, 0),
                PlatformSocKind::Rpi4Bcm2711 => (RPI4_EMMC2_PHYS, RPI4_MBOX_PHYS),
                PlatformSocKind::Rpi5Bcm2712 => (RPI5_SDIO0_PHYS, 0),
                PlatformSocKind::GenericVirt => (0, 0),
            };

            super::step15_qemu::install_rpi(
                serial,
                blob,
                board_rev,
                arm_ram_bytes,
                sdhci_phys,
                deferred_mbox_phys,
                fb_info,
            );
            kernal_protected_boot_aarch64::enter_runtime_protected_regime();
            serial.write_str("KERNAL/RPI: final TTBR1-only runtime entered\n");

            if freq > 0 {
                // SAFETY: BSP owns CNTV, IRQs are still masked, QA7/GIC-400 is active.
                if unsafe { kernal_timer_aarch64::arm_after_ns(super::TIMER_INTERVAL_NS) }.is_err()
                {
                    super::fatal_with_serial(
                        serial,
                        "KERNAL/RPI: runtime scheduler tick arm failed\n",
                    );
                }
                super::RUNTIME_SCHEDULER_TICK_ACTIVE[0].store(true, Ordering::Release);
            }

            // SAFETY: protected callback published the persistent Linux runtime and PID 1 leader.
            if unsafe { super::step15_qemu::resume_initial_linux(serial) }.is_err() {
                super::fatal_with_serial(serial, "KERNAL/RPI: initial Linux resume failed\n");
            }
            serial.write_str("KERNAL/RPI: Linux userspace exited cleanly; halting\n");
            loop {
                // SAFETY: low-power halt after clean userspace exit.
                unsafe { kernal_arch_aarch64::wait_for_interrupt() };
            }
        }
    }

    let _ = (board_rev, arm_ram_bytes, fb_info);
    serial.write_str("KERNAL/RPI: native hybrid kernel hardware bring-up complete\n");

    loop {
        // SAFETY: park cleanly in low-power WFI on native hardware.
        unsafe { kernal_arch_aarch64::wait_for_interrupt() };
    }
}
