// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Raspberry Pi 3 Model B+ (`Broadcom BCM2837B0` SoC, 1.4 GHz Quad-Core ARM Cortex-A53)
//! Driver Suite for Qyronex OS.
//!
//! Designed with hardware-accurate register/protocol state machines and Qyronex capability +
//! IOMMU/DMA mediation so the complete driver stack runs deterministically inside QEMU (`virt`)
//! as well as on BCM2837 MMIO layouts:
//! - VideoCore IV Mailbox Property Interface (`0x3F00_B880`, channel 8),
//! - 54-pin BCM2837 GPIO controller (`0x3F20_0000`, `GPFSEL0..5`, `GPSET`, `GPCLR`, `GPPUD`, ACT LED),
//! - Dual UART: PrimeCell PL011 `UART0` (`0x3F20_1000`) & AUX Mini-UART `UART1` (`0x3F21_5040`),
//! - Dual Interrupt Controller: BCM2835/2837 ARM Peripheral IC (`0x3F00_B200`) & Quad-A53 `QA7`
//!   Local Interrupt Controller / SMP Mailbox (`0x4000_0000`),
//! - Arasan SDHCI / EMMC SDHC block storage controller (`0x3F30_0000`),
//! - Synopsys DWC2 USB 2.0 Host (`0x3F98_0000`) + on-board Microchip `LAN7515` (`0424:7800`)
//!   USB 2.0 4-port Hub & Gigabit Ethernet controller (`1000BASE-T` RGMII PHY),
//! - 1 MHz System Timer (`0x3F00_3000`), Power Management / Watchdog (`0x3F10_0000`),
//!   Hardware RNG (`0x3F10_4000`), BSC I2C Master (`0x3F80_4000`), and SPI0 Master (`0x3F20_4000`).

pub mod bus_peripherals;
pub mod gpio;
pub mod intc;
pub mod lan7515;
pub mod mailbox;
pub mod mmio;
pub mod rpi4_bcm2711;
pub mod rpi5_bcm2712;
pub mod sdhci;
pub mod uart;

pub use bus_peripherals::{
    BSC_FIFO_SIZE, Bcm2837BscI2c, Bcm2837HwRng, Bcm2837PmWatchdog, Bcm2837Spi0, Bcm2837SysTimer,
    PM_PASSWORD, PM_RSTC_WRCFG_FULL_RESET, PM_WDOG_TICKS_PER_SEC, RNG_CTRL_EN, RNG_WARMUP_COUNT,
    SYSTIMER_FREQ_HZ,
};
pub use gpio::{
    BCM2837_GPIO_PIN_COUNT, Bcm2837Gpio, GpioFunction, GpioPull, RPI3B_PLUS_ACT_LED_PIN,
};
pub use intc::{
    BCM2837_CORE_COUNT, Bcm2837ArmCtrlIc, GPU_IRQ_ARASAN_SDHCI, GPU_IRQ_AUX_MINI_UART, GPU_IRQ_I2C,
    GPU_IRQ_PL011_UART0, GPU_IRQ_SPI, GPU_IRQ_SYSTIMER_C1, GPU_IRQ_SYSTIMER_C3, GPU_IRQ_USB_DWC2,
    QA7_IRQ_SRC_CNTPNSIRQ, QA7_IRQ_SRC_CNTVIRQ, QA7_IRQ_SRC_GPU, QA7_IRQ_SRC_MBOX0, Qa7LocalIntc,
};
pub use lan7515::{
    Bcm2837Dwc2UsbHost, ETH_DEFAULT_MTU, ETH_MAX_FRAME_BYTES, ETH_MIN_FRAME_BYTES,
    LAN7515_CHIP_ID_REV, LAN7515_HUB_PORT_COUNT, LAN7515_USB_PRODUCT_ID, LAN7515_USB_VENDOR_ID,
    Lan7515GigabitNic, MII_BMCR, MII_BMSR, MII_CTRL1000, MII_PHYID1, MII_PHYID2, MII_STAT1000,
};
pub use mailbox::{
    ClockDomain, MBOX_CH_PROP, MBOX_REQUEST_CODE, MBOX_RESPONSE_SUCCESS, MBOX_TAG_RESPONSE_BIT,
    PowerDomain, TAG_ALLOCATE_BUFFER, TAG_END, TAG_GET_ARM_MEMORY, TAG_GET_BOARD_MAC,
    TAG_GET_BOARD_MODEL, TAG_GET_BOARD_REVISION, TAG_GET_BOARD_SERIAL, TAG_GET_CLOCK_RATE,
    TAG_GET_FIRMWARE_REV, TAG_GET_MAX_CLOCK_RATE, TAG_GET_MAX_TEMPERATURE, TAG_GET_PHYS_WH,
    TAG_GET_PITCH, TAG_GET_POWER_STATE, TAG_GET_TEMPERATURE, TAG_GET_VC_MEMORY, TAG_SET_CLOCK_RATE,
    TAG_SET_DEPTH, TAG_SET_PHYS_WH, TAG_SET_PIXEL_ORDER, TAG_SET_POWER_STATE, TAG_SET_VIRT_WH,
    VcFramebufferInfo, VideoCoreMailbox,
};
pub use mmio::{
    OFF_ARASAN_EMMC, OFF_ARMCTRL_IC, OFF_AUX, OFF_BSC1_I2C, OFF_DWC2_USB, OFF_GPIO, OFF_MBOX,
    OFF_PL011_UART0, OFF_PM_WDOG, OFF_QA7_LOCAL, OFF_RNG, OFF_SPI0, OFF_SYSTIMER, Rpi3bPlusMmioHal,
    RpiMmioBus, SimulatedRpiMmioBus, TOTAL_RPI3B_PLUS_MMIO_SPAN, VolatileRpiMmioBus,
};
pub use rpi4_bcm2711::{
    BCM2711_EMMC2_BASE, BCM2711_GENET_V5_BASE, BCM2711_GIC400_BASE, BCM2711_GIC400_GICC_BASE,
    BCM2711_GIC400_GICD_BASE, BCM2711_PCIE_BASE, BCM2711_PCIE_OUTBOUND_MMIO_BASE,
    BCM2711_PERIPHERAL_BASE, BCM54213PE_PHY_ID1, BCM54213PE_PHY_ID2, Bcm2711Emmc2Controller,
    Bcm2711GenetV5Nic, Bcm2711PcieRootComplex, RPI4B_BOARD_REVISION, RPI4B_COMPATIBLE,
    RPI4B_DEFAULT_MAC, RPI4B_MAX_CLOCK_ARM_HZ, RPI4B_MODEL_STRING, Rpi4BBoard, VIA_VL805_DEVICE_ID,
    VIA_VL805_VENDOR_ID, translate_bcm2711_vc_bus_to_arm_phys,
};
pub use rpi5_bcm2712::{
    BCM2712_GIC_GICC_BASE, BCM2712_GIC_GICD_BASE, BCM2712_PCIE_EXT_BASE, BCM2712_PCIE_RP1_BASE,
    BCM2712_PERIPHERAL_BASE, BCM2712_SDIO_BASE, RP1_BAR1_APERTURE_BASE, RP1_BAR1_APERTURE_SIZE,
    RP1_CHIP_ID, RP1_ETH_CADENCE_GEM_BASE, RP1_GPIO_BANK0_PIN_COUNT, RP1_IO_BANK0_BASE,
    RP1_PCI_DEVICE_ID, RP1_PCI_VENDOR_ID, RP1_SYS_RIO0_BASE, RP1_XHCI0_BASE, RP1_XHCI1_BASE,
    RPI5_BOARD_REVISION, RPI5_COMPATIBLE, RPI5_DEFAULT_MAC, RPI5_MAX_CLOCK_ARM_HZ,
    RPI5_MODEL_STRING, Rp1CadenceGemNic, Rp1DualXhciUsb3Host, Rp1PcieSouthbridge, Rp1RioGpio,
    Rpi5Board,
};
pub use sdhci::{
    Bcm2837ArasanSdhci, SD_ACMD_SD_SEND_OP_COND, SD_CMD_ALL_SEND_CID, SD_CMD_APP_CMD,
    SD_CMD_GO_IDLE_STATE, SD_CMD_READ_MULTIPLE_BLOCK, SD_CMD_READ_SINGLE_BLOCK, SD_CMD_SELECT_CARD,
    SD_CMD_SEND_IF_COND, SD_CMD_SEND_RELATIVE_ADDR, SD_CMD_SET_BLOCKLEN, SD_CMD_WRITE_BLOCK,
    SD_CMD_WRITE_MULTIPLE_BLOCK, SD_SECTOR_BYTES, SdCardState,
};
pub use uart::{
    MiniUart1, Pl011Uart0, UART_FIFO_CAPACITY, compute_mini_uart_baud_reg,
    compute_pl011_baud_dividers,
};

use kernal_capability::Capability;
use kernal_iommu::{DmaMapping, DmaPerms};
use kernal_linux_abi::Errno;

// BCM2837 SoC physical memory map constants
pub const BCM2837_PERIPHERAL_BASE: u64 = 0x3F00_0000;
pub const BCM2837_PERIPHERAL_SIZE: u64 = 0x0100_0000; // 16 MiB
pub const BCM2837_VC_BUS_PERIPHERAL_BASE: u32 = 0x7E00_0000;
pub const BCM2837_VC_SDRAM_UNCACHED_BASE: u32 = 0xC000_0000;
pub const BCM2837_ARM_LOCAL_BASE: u64 = 0x4000_0000;
pub const BCM2837_ARM_LOCAL_SIZE: u64 = 0x0000_0100;

pub const BCM2837_SYSTIMER_BASE: u64 = BCM2837_PERIPHERAL_BASE + 0x0000_3000;
pub const BCM2837_ARMCTRL_IC_BASE: u64 = BCM2837_PERIPHERAL_BASE + 0x0000_B200;
pub const BCM2837_MBOX_BASE: u64 = BCM2837_PERIPHERAL_BASE + 0x0000_B880;
pub const BCM2837_PM_WDOG_BASE: u64 = BCM2837_PERIPHERAL_BASE + 0x0010_0000;
pub const BCM2837_RNG_BASE: u64 = BCM2837_PERIPHERAL_BASE + 0x0010_4000;
pub const BCM2837_GPIO_BASE: u64 = BCM2837_PERIPHERAL_BASE + 0x0020_0000;
pub const BCM2837_PL011_UART0_BASE: u64 = BCM2837_PERIPHERAL_BASE + 0x0020_1000;
pub const BCM2837_SPI0_BASE: u64 = BCM2837_PERIPHERAL_BASE + 0x0020_4000;
pub const BCM2837_BSC0_I2C_BASE: u64 = BCM2837_PERIPHERAL_BASE + 0x0020_5000;
pub const BCM2837_AUX_BASE: u64 = BCM2837_PERIPHERAL_BASE + 0x0021_5000;
pub const BCM2837_ARASAN_EMMC_BASE: u64 = BCM2837_PERIPHERAL_BASE + 0x0030_0000;
pub const BCM2837_BSC1_I2C_BASE: u64 = BCM2837_PERIPHERAL_BASE + 0x0080_4000;
pub const BCM2837_BSC2_I2C_BASE: u64 = BCM2837_PERIPHERAL_BASE + 0x0080_5000;
pub const BCM2837_DWC2_USB_BASE: u64 = BCM2837_PERIPHERAL_BASE + 0x0098_0000;

// Official Raspberry Pi 3 Model B+ hardware identity constants
pub const RPI3B_PLUS_MODEL_STRING: &str = "Raspberry Pi 3 Model B Plus Rev 1.3";
pub const RPI3B_PLUS_COMPATIBLE: &str = "raspberrypi,3-model-b-plus\0brcm,bcm2837";
pub const RPI3B_PLUS_BOARD_MODEL: u32 = 0x0000_000D;
pub const RPI3B_PLUS_BOARD_REVISION: u32 = 0x00A0_20D3; // Pi 3B+ Rev 1.3, 1GB, Sony UK, BCM2837B0
pub const RPI3B_PLUS_FIRMWARE_REV: u32 = 0x6640_A3B0;
pub const RPI3B_PLUS_DEFAULT_MAC: [u8; 6] = [0xB8, 0x27, 0xEB, 0x3B, 0x13, 0x01];
pub const BOARD_SERIAL_DEFAULT: u64 = 0x0000_0000_3B13_01D3;

pub const ARM_MEM_SIZE_DEFAULT: u32 = 0x3B40_0000; // 948 MiB ARM DRAM
pub const VC_MEM_BASE_DEFAULT: u32 = 0x3B40_0000;
pub const VC_MEM_SIZE_DEFAULT: u32 = 0x04C0_0000; // 76 MiB VideoCore IV SDRAM
pub const MAX_CLOCK_ARM_HZ: u32 = 1_400_000_000; // 1.4 GHz Cortex-A53 on Pi 3B+
pub const CORE_CLOCK_HZ_DEFAULT: u32 = 400_000_000;
pub const EMMC_CLOCK_HZ_DEFAULT: u32 = 200_000_000;
pub const UART_CLOCK_HZ_DEFAULT: u32 = 48_000_000;

/// Converts an ARM physical SDRAM address (`0x0000_0000..0x3F00_0000`) to a VideoCore uncached bus address.
pub const fn arm_phys_to_vc_bus(arm_phys: u32) -> u32 {
    (arm_phys & 0x3FFF_FFFF) | BCM2837_VC_SDRAM_UNCACHED_BASE
}

/// Converts a VideoCore bus address back to an ARM physical SDRAM address.
pub const fn vc_bus_to_arm_phys(vc_bus: u32) -> u32 {
    vc_bus & !BCM2837_VC_SDRAM_UNCACHED_BASE
}

/// Unified fail-closed error surface across all Raspberry Pi 3B+ (`BCM2837B0`) drivers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpiError {
    PermissionDenied,
    InvalidArgument,
    OutOfRange,
    PinOutOfRange,
    CoreOutOfRange,
    UnalignedBuffer,
    BufferTooSmall,
    MalformedPropertyBuffer,
    UnsupportedTag,
    DeviceNotReady,
    StaleGeneration,
    DmaViolation,
    ReadOnly,
    LinkDown,
    InvalidFrame,
    FilteredFrame,
    QueueFull,
    QueueEmpty,
    InvalidWatchdogPassword,
}

impl RpiError {
    pub const fn to_errno(self) -> Errno {
        match self {
            Self::PermissionDenied | Self::StaleGeneration | Self::DmaViolation => Errno::EACCES,
            Self::ReadOnly => Errno::EROFS,
            Self::QueueFull | Self::QueueEmpty | Self::DeviceNotReady => Errno::EAGAIN,
            Self::LinkDown => Errno::EIO,
            Self::UnsupportedTag => Errno::EOPNOTSUPP,
            Self::InvalidArgument
            | Self::OutOfRange
            | Self::PinOutOfRange
            | Self::CoreOutOfRange
            | Self::UnalignedBuffer
            | Self::BufferTooSmall
            | Self::MalformedPropertyBuffer
            | Self::InvalidFrame
            | Self::FilteredFrame
            | Self::InvalidWatchdogPassword => Errno::EINVAL,
        }
    }
}

/// Validates that `[iova, iova + len)` lies within `dma` and grants `req` permissions.
pub fn verify_dma_window(
    dma: &DmaMapping,
    iova: u64,
    len: usize,
    req: DmaPerms,
) -> Result<(), RpiError> {
    if (dma.perms.bits() & req.bits()) == 0 {
        return Err(RpiError::DmaViolation);
    }
    let end = iova.checked_add(len as u64).ok_or(RpiError::DmaViolation)?;
    let map_end = dma.iova_end().ok_or(RpiError::DmaViolation)?;
    if iova < dma.iova || end > map_end {
        return Err(RpiError::DmaViolation);
    }
    Ok(())
}

/// Composite Raspberry Pi 3 Model B+ (`BCM2837B0`) board driver bundle.
///
/// Can be instantiated and driven directly inside QEMU (`virt`) as well as on BCM2837 targets.
pub struct Rpi3bPlusBoard<const SD_SECTORS: usize = 16, const NIC_RING: usize = 4> {
    pub initialized: bool,
    pub mailbox: VideoCoreMailbox,
    pub gpio: Bcm2837Gpio,
    pub uart0: Pl011Uart0,
    pub mini_uart1: MiniUart1,
    pub armctrl_ic: Bcm2837ArmCtrlIc,
    pub qa7_intc: Qa7LocalIntc,
    pub sdhci: Bcm2837ArasanSdhci<SD_SECTORS>,
    pub dwc2_usb: Bcm2837Dwc2UsbHost,
    pub lan7515_nic: Lan7515GigabitNic<NIC_RING>,
    pub systimer: Bcm2837SysTimer,
    pub pm_watchdog: Bcm2837PmWatchdog,
    pub hwrng: Bcm2837HwRng,
    pub i2c1: Bcm2837BscI2c,
    pub spi0: Bcm2837Spi0,
    pub mmio_hal: Rpi3bPlusMmioHal<SimulatedRpiMmioBus>,
}

impl<const SD_SECTORS: usize, const NIC_RING: usize> Default
    for Rpi3bPlusBoard<SD_SECTORS, NIC_RING>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const SD_SECTORS: usize, const NIC_RING: usize> Rpi3bPlusBoard<SD_SECTORS, NIC_RING> {
    pub const fn new() -> Self {
        Self {
            initialized: false,
            mailbox: VideoCoreMailbox::new(),
            gpio: Bcm2837Gpio::new(),
            uart0: Pl011Uart0::new(),
            mini_uart1: MiniUart1::new(),
            armctrl_ic: Bcm2837ArmCtrlIc::new(),
            qa7_intc: Qa7LocalIntc::new(),
            sdhci: Bcm2837ArasanSdhci::new(false),
            dwc2_usb: Bcm2837Dwc2UsbHost::new(),
            lan7515_nic: Lan7515GigabitNic::new(RPI3B_PLUS_DEFAULT_MAC),
            systimer: Bcm2837SysTimer::new(),
            pm_watchdog: Bcm2837PmWatchdog::new(),
            hwrng: Bcm2837HwRng::new(),
            i2c1: Bcm2837BscI2c::new(),
            spi0: Bcm2837Spi0::new(),
            mmio_hal: Rpi3bPlusMmioHal::new(SimulatedRpiMmioBus::new()),
        }
    }

    /// Executes native BCM2837 MMIO register initialization on any [`RpiMmioBus`]
    /// ([`VolatileRpiMmioBus`] on real Raspberry Pi 3B+ hardware or [`SimulatedRpiMmioBus`] in QEMU).
    pub fn initialize_on_mmio_bus<B: RpiMmioBus>(
        &mut self,
        cap: Capability,
        hal: &mut Rpi3bPlusMmioHal<B>,
    ) -> Result<u32, RpiError> {
        hal.mmio_initialize_board(cap)
    }

    /// Brings up all Raspberry Pi 3B+ SoC peripherals:
    /// 1. Powers on SD Card, UART0, UART1, USB HCD, I2C1, and SPI0 via VideoCore Mailbox,
    /// 2. Configures GPIO muxing for PL011 UART0, Arasan SDHCI/EMMC (GPIO48..53), I2C1 (GPIO2/3),
    ///    SPI0 (GPIO7..11), and turns on the green Activity LED (GPIO29),
    /// 3. Configures PL011 UART0 (48 MHz @ 115200) and AUX Mini-UART1 (400 MHz @ 115200),
    /// 4. Enables BCM2837 GPU IRQs for System Timer, DWC2 USB, AUX, I2C, SPI, UART0, and SDHCI,
    /// 5. Initializes the Arasan SDHCI card to `SdCardState::Transfer`,
    /// 6. Enumerates the DWC2 USB Host + Microchip LAN7515 Gigabit Ethernet controller (`1000 Mbps`),
    /// 7. Seeds and enables the BCM2837 Hardware RNG.
    pub fn initialize_board(&mut self, cap: Capability) -> Result<(), RpiError> {
        for dom in [
            PowerDomain::SdCard,
            PowerDomain::Uart0,
            PowerDomain::Uart1,
            PowerDomain::UsbHcd,
            PowerDomain::I2c1,
            PowerDomain::Spi,
        ] {
            self.mailbox.set_domain_power(cap, dom, true)?;
        }
        self.gpio.configure_pl011_uart0(cap)?;
        self.gpio.configure_sdhci_emmc(cap)?;
        self.gpio.configure_i2c1(cap)?;
        self.gpio.configure_spi0(cap)?;
        self.gpio.set_act_led(cap, true)?;

        self.uart0
            .configure(cap, self.mailbox.uart_clock_hz, 115_200)?;
        self.mini_uart1
            .configure(cap, self.mailbox.core_clock_hz, 115_200)?;

        for irq in [
            GPU_IRQ_SYSTIMER_C1,
            GPU_IRQ_SYSTIMER_C3,
            GPU_IRQ_USB_DWC2,
            GPU_IRQ_AUX_MINI_UART,
            GPU_IRQ_I2C,
            GPU_IRQ_SPI,
            GPU_IRQ_PL011_UART0,
            GPU_IRQ_ARASAN_SDHCI,
        ] {
            self.armctrl_ic.enable_gpu_irq(cap, irq)?;
        }
        self.qa7_intc.route_gpu_irqs_to_core(cap, 0)?;

        self.sdhci.initialize_sdhc_card(cap)?;
        self.dwc2_usb.initialize_and_enumerate_lan7515(cap)?;
        self.lan7515_nic
            .set_mac_address(cap, self.mailbox.mac_address)?;
        self.hwrng.enable(cap, self.mailbox.board_serial)?;
        let chip_id = self.mmio_hal.mmio_initialize_board(cap)?;
        if chip_id != LAN7515_CHIP_ID_REV {
            return Err(RpiError::DeviceNotReady);
        }
        self.initialized = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_capability::{CapRights, ObjectId};
    use kernal_iommu::{DmaMapping, DmaPerms};

    fn admin_cap() -> Capability {
        Capability {
            object: ObjectId(0x2837),
            rights: CapRights::CONTROL
                .union(CapRights::READ)
                .union(CapRights::WRITE),
        }
    }

    fn ro_cap() -> Capability {
        Capability {
            object: ObjectId(0x2837),
            rights: CapRights::READ,
        }
    }

    #[test]
    fn videocore_mailbox_queries_board_revision_clocks_power_and_framebuffer() {
        let mut mbox = VideoCoreMailbox::new();
        let cap = admin_cap();
        let mut prop_buf = [
            12 * 4,
            MBOX_REQUEST_CODE,
            TAG_GET_BOARD_REVISION,
            4,
            0,
            0,
            TAG_GET_CLOCK_RATE,
            8,
            0,
            ClockDomain::Arm as u32,
            0,
            TAG_END,
        ];
        // Unaligned physical address must fail closed.
        assert_eq!(
            mbox.process_property_buffer(cap, 0x1004, &mut prop_buf),
            Err(RpiError::UnalignedBuffer)
        );
        mbox.process_property_buffer(cap, 0x1000, &mut prop_buf)
            .unwrap();
        assert_eq!(prop_buf[1], MBOX_RESPONSE_SUCCESS);
        assert_eq!(prop_buf[5], RPI3B_PLUS_BOARD_REVISION);
        assert_eq!(prop_buf[10], MAX_CLOCK_ARM_HZ);

        // Allocate 1920x1080x32bpp VideoCore framebuffer via property tags.
        let mut fb_buf = [
            19 * 4,
            MBOX_REQUEST_CODE,
            TAG_SET_PHYS_WH,
            8,
            0,
            1920,
            1080,
            TAG_SET_VIRT_WH,
            8,
            0,
            1920,
            1080,
            TAG_ALLOCATE_BUFFER,
            8,
            0,
            16,
            0,
            TAG_END,
            0,
        ];
        mbox.process_property_buffer(cap, 0x2000, &mut fb_buf)
            .unwrap();
        assert_eq!(fb_buf[1], MBOX_RESPONSE_SUCCESS);
        assert_eq!(fb_buf[16], 1920 * 1080 * 4);
        assert_eq!(vc_bus_to_arm_phys(fb_buf[15]), mbox.fb.arm_phys_base);
    }

    #[test]
    fn gpio_muxing_uart0_mini_uart1_and_interrupt_routing_work() {
        let cap = admin_cap();
        let mut board = Rpi3bPlusBoard::<16, 4>::new();
        board.initialize_board(cap).unwrap();
        assert!(board.initialized);
        assert_eq!(board.gpio.get_function(14).unwrap(), GpioFunction::Alt0);
        assert_eq!(board.gpio.get_function(15).unwrap(), GpioFunction::Alt0);
        assert_eq!(board.gpio.get_pull(15).unwrap(), GpioPull::PullUp);
        assert_eq!(board.gpio.get_function(48).unwrap(), GpioFunction::Alt3);
        assert_eq!(board.gpio.get_function(53).unwrap(), GpioFunction::Alt3);
        assert!(board.gpio.act_led_is_on());

        // PL011 UART0 TX/RX roundtrip & baud dividers (48 MHz @ 115200 -> IBRD=26, FBRD=3)
        assert_eq!((board.uart0.ibrd, board.uart0.fbrd), (26, 3));
        assert_eq!(
            board.uart0.write_bytes(cap, b"RPI3B+ UART0 OK").unwrap(),
            15
        );
        let mut tx_out = [0u8; 32];
        assert_eq!(board.uart0.drain_tx(&mut tx_out), 15);
        assert_eq!(&tx_out[..15], b"RPI3B+ UART0 OK");

        board.uart0.inject_rx(b"vcgencmd");
        let mut rx_out = [0u8; 16];
        assert_eq!(board.uart0.read_bytes(ro_cap(), &mut rx_out).unwrap(), 8);
        assert_eq!(&rx_out[..8], b"vcgencmd");

        // QA7 Local INTC routes GPU IRQs to Core 0 and wakes secondary Cortex-A53 cores 1..=3.
        board
            .armctrl_ic
            .assert_gpu_irq(GPU_IRQ_ARASAN_SDHCI)
            .unwrap();
        let src0 = board
            .qa7_intc
            .core_irq_source(0, &board.armctrl_ic)
            .unwrap();
        assert_ne!(src0 & QA7_IRQ_SRC_GPU, 0);

        board
            .qa7_intc
            .wake_secondary_core(cap, 1, 0x0008_0000)
            .unwrap();
        assert!(board.qa7_intc.core_online[1]);
        assert_eq!(board.qa7_intc.mailboxes[1][3], 0x0008_0000);
    }

    #[test]
    fn arasan_sdhci_and_lan7515_gigabit_nic_enforce_capabilities_and_dma() {
        let cap = admin_cap();
        let ro = ro_cap();
        let dma_rw =
            DmaMapping::new(0x3000_0000, 0x1000_0000, 0x4000, DmaPerms::READ_WRITE).unwrap();
        let dma_ro = DmaMapping::new(0x4000_0000, 0x1000_4000, 0x4000, DmaPerms::READ).unwrap();

        let mut board = Rpi3bPlusBoard::<16, 4>::new();
        board.initialize_board(cap).unwrap();
        assert_eq!(board.sdhci.state, SdCardState::Transfer);
        let sd_gen = board.sdhci.generation;

        let sector_in = [0xA5u8; SD_SECTOR_BYTES];
        board
            .sdhci
            .write_blocks(cap, &dma_rw, sd_gen, 0x3000_0000, 2, &sector_in)
            .unwrap();
        let mut sector_out = [0u8; SD_SECTOR_BYTES];
        board
            .sdhci
            .read_blocks(ro, &dma_rw, sd_gen, 0x3000_0000, 2, &mut sector_out)
            .unwrap();
        assert_eq!(sector_out, sector_in);

        // Read blocks into read-only DMA mapping must fail with DmaViolation.
        assert_eq!(
            board
                .sdhci
                .read_blocks(ro, &dma_ro, sd_gen, 0x4000_0000, 2, &mut sector_out),
            Err(RpiError::DmaViolation)
        );

        // LAN7515 USB 2.0 Gigabit Ethernet TX/RX & MAC filtering.
        assert!(board.dwc2_usb.lan7515_hub_enumerated);
        assert_eq!(board.lan7515_nic.speed_mbps, 1000);
        assert_eq!(board.lan7515_nic.mdio_read(MII_PHYID1).unwrap(), 0x0007);

        let mut frame = [0u8; 64];
        frame[0..6].copy_from_slice(&board.lan7515_nic.mac);
        frame[6..12].copy_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);

        let nic_gen = board.lan7515_nic.generation;
        board
            .lan7515_nic
            .transmit_frame(cap, &dma_rw, nic_gen, 0x3000_0000, &frame)
            .unwrap();
        let mut wire_buf = [0u8; 128];
        assert_eq!(board.lan7515_nic.pop_wire_tx(&mut wire_buf).unwrap(), 64);

        board.lan7515_nic.push_wire_rx(&frame).unwrap();
        let mut rx_buf = [0u8; 128];
        assert_eq!(
            board
                .lan7515_nic
                .receive_frame(ro, &dma_rw, nic_gen, 0x3000_0000, &mut rx_buf)
                .unwrap(),
            64
        );
        assert_eq!(&rx_buf[..64], &frame[..]);

        // Unmatched unicast MAC must be filtered by LAN7515 RFE when not promiscuous.
        let mut foreign_frame = frame;
        foreign_frame[0..6].copy_from_slice(&[0x00, 0x12, 0x34, 0x56, 0x78, 0x9A]);
        assert_eq!(
            board.lan7515_nic.push_wire_rx(&foreign_frame),
            Err(RpiError::FilteredFrame)
        );
    }

    #[test]
    fn systimer_watchdog_hwrng_i2c_and_spi_peripherals_work() {
        let cap = admin_cap();
        let mut board = Rpi3bPlusBoard::<16, 4>::new();
        board.initialize_board(cap).unwrap();

        // System timer compare channel 1 match at 500 us.
        board.systimer.arm_compare(cap, 1, 500).unwrap();
        assert_eq!(board.systimer.advance_us(200) & (1 << 1), 0);
        assert_ne!(board.systimer.advance_us(300) & (1 << 1), 0);
        board.systimer.clear_match(cap, 1 << 1).unwrap();
        assert_eq!(board.systimer.match_status, 0);

        // PM Watchdog rejects wrong password and triggers reset on expiry.
        assert_eq!(
            board.pm_watchdog.write_wdog(cap, 0x1234_0100),
            Err(RpiError::InvalidWatchdogPassword)
        );
        board
            .pm_watchdog
            .write_wdog(cap, PM_PASSWORD | 1000)
            .unwrap();
        board
            .pm_watchdog
            .write_rstc(cap, PM_PASSWORD | PM_RSTC_WRCFG_FULL_RESET)
            .unwrap();
        assert!(board.pm_watchdog.is_armed());
        assert!(!board.pm_watchdog.tick(400));
        assert!(board.pm_watchdog.tick(600));
        assert!(board.pm_watchdog.reset_triggered);

        // Hardware RNG generates non-repeating words.
        let w1 = board.hwrng.read_word(ro_cap()).unwrap();
        let w2 = board.hwrng.read_word(ro_cap()).unwrap();
        assert_ne!(w1, w2);

        // BSC1 I2C and SPI0 transfers.
        assert_eq!(
            board.i2c1.write_transfer(cap, 0x68, &[0x00, 0x42]).unwrap(),
            2
        );
        assert_eq!(board.i2c1.last_written(), &[0x00, 0x42]);

        let mut spi_rx = [0u8; 4];
        board
            .spi0
            .transfer_full_duplex(cap, &[0x9F, 0x01, 0x02, 0x03], &mut spi_rx)
            .unwrap();
        assert_eq!(spi_rx, [0x9F, 0x01, 0x02, 0x03]);

        // Verify MMIO register layer (Rpi3bPlusMmioHal) across GPIO, Mailbox, UART0, Mini-UART1, and LAN7515.
        assert_eq!(
            board.mmio_hal.mmio_gpio_get_function(14).unwrap(),
            GpioFunction::Alt0
        );
        assert_eq!(
            board.mmio_hal.mmio_gpio_get_function(48).unwrap(),
            GpioFunction::Alt3
        );
        assert!(
            board
                .mmio_hal
                .mmio_gpio_read_pin(RPI3B_PLUS_ACT_LED_PIN)
                .unwrap()
        );
        board.mmio_hal.mmio_uart0_putc(cap, b'Q').unwrap();
        assert_eq!(board.mmio_hal.bus.last_uart0_tx(), b'Q');
        board.mmio_hal.bus.inject_uart0_rx(b'R');
        assert_eq!(
            board.mmio_hal.mmio_uart0_getc(ro_cap()).unwrap(),
            Some(b'R')
        );
    }
}
