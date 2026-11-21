// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Native Raspberry Pi 3B+ (`BCM2837B0`), Raspberry Pi 4B (`BCM2711`, GIC-400) and
//! Raspberry Pi 5 (`BCM2712` + `RP1`, GIC-400) live hardware bring-up and IRQ backends.

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

// BCM2835/2837 VideoCore IV Mailbox registers (at page 0x3F00_B000 + 0x880)
const MBOX_PAGE_OFFSET: u64 = 0x880;
const MBOX_READ: u64 = 0x00;
const MBOX_STATUS: u64 = 0x18;
const MBOX_WRITE: u64 = 0x20;
const MBOX_FULL: u32 = 1 << 31;
const MBOX_EMPTY: u32 = 1 << 30;
const MBOX_CH_PROP: u32 = 8;

#[repr(C, align(16))]
struct MailboxPropBuffer(core::cell::UnsafeCell<[u32; 16]>);
// SAFETY: accessed exclusively by BSP during early single-core native RPi bring-up.
unsafe impl Sync for MailboxPropBuffer {}
static MBOX_PROP_BUF: MailboxPropBuffer =
    MailboxPropBuffer(core::cell::UnsafeCell::new([0u32; 16]));

/// Queries the real VideoCore IV / VI hardware mailbox over MMIO (`0x3F00_B880`) for board
/// revision and ARM memory size.
unsafe fn query_real_videocore_mailbox(armctrl_virt_base: u64) -> Option<(u32, u32)> {
    let mbox_base = (armctrl_virt_base & !0xFFF) + MBOX_PAGE_OFFSET;
    let buf_virt = MBOX_PROP_BUF.0.get() as u64;
    let buf_phys = kernal_protected_boot_aarch64::runtime_kernel_alias_physical(buf_virt)?;
    if buf_phys > u32::MAX as u64 || (buf_phys & 0xF) != 0 {
        return None;
    }

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

    // Clean & invalidate data cache line so VideoCore DMA sees the request buffer on real silicon.
    #[cfg(target_arch = "aarch64")]
    // SAFETY: `buf_virt` is a valid mapped kernel data address.
    unsafe {
        core::arch::asm!(
            "dc civac, {0}",
            "dsb sy",
            in(reg) buf_virt,
            options(nostack)
        );
    }

    let msg = ((buf_phys as u32) & !0xF) | MBOX_CH_PROP;
    for _ in 0..100_000u32 {
        // SAFETY: `mbox_base` is inside the TTBR1-mapped `0x3F00_B000` device page.
        if (unsafe { read_volatile((mbox_base + MBOX_STATUS) as *const u32) } & MBOX_FULL) == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    // SAFETY: mailbox is ready to accept Channel 8 message.
    unsafe { write_volatile((mbox_base + MBOX_WRITE) as *mut u32, msg) };

    for _ in 0..200_000u32 {
        // SAFETY: poll MBOX_STATUS until response arrives.
        if (unsafe { read_volatile((mbox_base + MBOX_STATUS) as *const u32) } & MBOX_EMPTY) != 0 {
            core::hint::spin_loop();
            continue;
        }
        // SAFETY: read response word from MBOX_READ.
        let resp = unsafe { read_volatile((mbox_base + MBOX_READ) as *const u32) };
        if (resp & 0xF) == MBOX_CH_PROP {
            #[cfg(target_arch = "aarch64")]
            // SAFETY: invalidate cache line before reading VideoCore response.
            unsafe {
                core::arch::asm!(
                    "dc civac, {0}",
                    "dsb sy",
                    in(reg) buf_virt,
                    options(nostack)
                );
            }
            if buf[1] == 0x8000_0000 {
                return Some((buf[5], buf[10]));
            }
            return None;
        }
    }
    None
}

#[inline]
pub(crate) fn active_irq_mode() -> u8 {
    ACTIVE_IRQ_MODE.load(Ordering::Acquire)
}

/// Handles a live hardware IRQ when running natively on Raspberry Pi 3B+ (QA7) or Pi 4/5 (GICv2).
pub(crate) fn handle_native_rpi_irq() {
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
                // Disarm virtual timer if this is the PPI virtual timer interrupt (27).
                if intid == 27 {
                    let count = RPI_TIMER_TICKS.fetch_add(1, Ordering::AcqRel) + 1;
                    if count < 2 {
                        // SAFETY: virtual timer PPI is owned by BSP during native timer proof.
                        let _ = unsafe { kernal_timer_aarch64::arm_after_ns(5_000_000) };
                    } else {
                        // SAFETY: timer proof complete; disarm CNTV.
                        unsafe { kernal_timer_aarch64::disarm() };
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

/// Executes native Raspberry Pi 3B+ / 4B / 5 hardware initialization and live timer IRQ proof.
pub(crate) fn boot_raspberry_pi_native<const N: usize>(
    write_str: impl Fn(&str),
    write_u64: impl Fn(u64),
    write_hex: impl Fn(u64),
    exception_handler: extern "C" fn(&mut kernal_exceptions_aarch64::ExceptionFrame),
    platform: &PlatformInfo<N>,
    blob: &Blob<'_>,
    gic_v2: Option<GicV2Info>,
    bcm_intc: Option<BcmIntcInfo>,
) -> ! {
    write_str("KERNAL/RPI: native Raspberry Pi hybrid boot entered\n");
    write_str("KERNAL/RPI: SoC=");
    match platform.soc_kind {
        PlatformSocKind::Rpi3BPlusBcm2837 => write_str("Broadcom BCM2837B0 (Raspberry Pi 3B+)\n"),
        PlatformSocKind::Rpi4Bcm2711 => write_str("Broadcom BCM2711 (Raspberry Pi 4B)\n"),
        PlatformSocKind::Rpi5Bcm2712 => write_str("Broadcom BCM2712 + RP1 (Raspberry Pi 5)\n"),
        PlatformSocKind::GenericVirt => write_str("Generic AArch64\n"),
    }

    // Install EL1 exception handler and vector table before enabling hardware IRQs.
    let _ = kernal_exceptions_aarch64::install_handler(exception_handler);
    // SAFETY: vector table is linker-resident executable text and IRQs are still masked.
    let _ = unsafe { kernal_exceptions_aarch64::install_vector_table() };
    write_str("KERNAL/RPI: EL1 exception vector table installed\n");

    let timer_intid = platform
        .timer_interrupts
        .map(|t| t.virtual_timer)
        .unwrap_or(27);

    if let Some(gic2) = gic_v2 {
        let gicd = kernal_protected_boot_aarch64::runtime_mmio_region(gic2.distributor);
        let gicc = kernal_protected_boot_aarch64::runtime_mmio_region(gic2.cpu_interface);
        write_str("KERNAL/RPI: GIC-400 (GICv2) GICD=");
        write_hex(gic2.distributor.base);
        write_str(" GICC=");
        write_hex(gic2.cpu_interface.base);
        write_str("\n");
        // SAFETY: validated FDT GIC-400 regions mapped in TTBR1 by protected boot.
        unsafe { init_gicv2(gicd, gicc, timer_intid) };
    } else if let Some(bcm) = bcm_intc {
        let qa7_phys = bcm.qa7_local.unwrap_or(MmioRegion {
            base: 0x4000_0000,
            size: 0x100,
        });
        let qa7 = kernal_protected_boot_aarch64::runtime_mmio_region(qa7_phys);
        write_str("KERNAL/RPI: BCM2836/2837 QA7 Local INTC=");
        write_hex(qa7_phys.base);
        write_str("\n");
        // SAFETY: validated FDT QA7 region mapped in TTBR1 by protected boot.
        unsafe { init_bcm_qa7(qa7) };

        if let Some(armctrl_phys) = bcm.armctrl {
            let armctrl = kernal_protected_boot_aarch64::runtime_mmio_region(armctrl_phys);
            // SAFETY: VideoCore Mailbox (`0x3F00_B880`) resides in the same mapped 4 KiB page as ARMCTRL (`0x3F00_B200`).
            if let Some((board_rev, arm_mem_bytes)) =
                unsafe { query_real_videocore_mailbox(armctrl.base) }
            {
                write_str("KERNAL/RPI: live VideoCore Mailbox HW rev=");
                write_hex(u64::from(board_rev));
                write_str(" arm_ram_mib=");
                write_u64(u64::from(arm_mem_bytes) / (1024 * 1024));
                write_str("\n");
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
            write_str("KERNAL/RPI: Pi 3B+ drivers online (Mailbox/GPIO54/SDHCI/DWC2/LAN7515 ");
            write_u64(u64::from(rpi3.lan7515_nic.speed_mbps));
            write_str("Mbps, ARM ");
            write_u64(u64::from(rpi3.mailbox.arm_clock_hz));
            write_str("Hz)\n");
        }
        if inv.bcm2711.is_populated() {
            let mut rpi4 = Rpi4BBoard::<4, 2>::new();
            rpi4.initialize_board();
            write_str("KERNAL/RPI: Pi 4B drivers online (GIC-400/GENET-v5 ");
            write_u64(u64::from(rpi4.genet_v5.speed_mbps));
            write_str("Mbps/PCIe-VL805/EMMC2)\n");
        }
        if inv.bcm2712.is_populated() {
            let mut rpi5 = Rpi5Board::<2>::new();
            rpi5.initialize_board();
            write_str("KERNAL/RPI: Pi 5 drivers online (GIC-400/PCIe-Gen2x4-RP1/Cadence-GEM ");
            write_u64(u64::from(rpi5.rp1.eth_gem.speed_mbps));
            write_str("Mbps/Dual-xHCI/RIO)\n");
        }
    }

    // Prove live hardware ARMv8 virtual timer IRQ delivery on native Raspberry Pi!
    let freq = kernal_arch_aarch64::counter_frequency_hz();
    write_str("KERNAL/RPI: counter Hz=");
    write_u64(freq);
    write_str(" arming hardware timer IRQ...\n");

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
    write_str("KERNAL/RPI: hardware timer IRQs delivered=");
    write_u64(u64::from(ticks));
    write_str("\n");
    write_str("KERNAL/RPI: native hybrid kernel hardware bring-up complete\n");

    loop {
        // SAFETY: park cleanly in low-power WFI on native hardware.
        unsafe { kernal_arch_aarch64::wait_for_interrupt() };
    }
}
