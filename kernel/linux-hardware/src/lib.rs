// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Step 42 — Practical Debian 13 Server Hardware Expansion:
//! - NVMe & AHCI storage controllers mediated via PCIe/IOMMU/capability grants,
//! - Wired PCIe Ethernet NIC hardware state machine + MDIO/ring validation,
//! - USB host controller, descriptor parser, HID keyboard/mouse, and USB MSC BOT,
//! - PL031 RTC, SP805/SBSA Watchdog, CPU topology/thermal sysfs telemetry, and
//!   cryptographic hardware entropy accumulator.

pub mod nic;
pub mod platform;
pub mod storage;
pub mod usb;

pub use nic::{NicConfig, NicError, WiredEthernetNic};
pub use platform::{
    HardwareEntropyPool, PlatformTelemetry, RTC_AIE_OFF, RTC_AIE_ON, RTC_ALM_READ, RTC_ALM_SET,
    RTC_RD_TIME, RTC_SET_TIME, RtcPl031, RtcTime, WDIOC_GETSUPPORT, WDIOC_GETTIMELEFT,
    WDIOC_GETTIMEOUT, WDIOC_KEEPALIVE, WDIOC_SETTIMEOUT, WatchdogDevice,
};
pub use storage::{AhciController, NvmeController, NvmeNamespace, SataCommand, StorageError};
pub use usb::{
    HidBootKeyboardReport, HidBootMouseReport, UsbDeviceDescriptor, UsbHostController, UsbMscCbw,
    UsbMscCsw, UsbSpeed, parse_config_descriptors,
};

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_capability::{CapRights, Capability, ObjectId};
    use kernal_iommu::{DmaMapping, DmaPerms};
    use kernal_linux_abi::Errno;
    use kernal_linux_systemd::RebootAction;
    use kernal_pci::{Address as PciAddress, EcamWindow};

    fn ecam() -> EcamWindow {
        EcamWindow {
            base: 0x40_1000_0000,
            segment: 0,
            start_bus: 0,
            end_bus: 15,
        }
    }

    #[test]
    fn nvme_and_ahci_enforce_capability_dma_bounds_and_reset_generation() {
        let ctrl_rw = Capability {
            object: ObjectId(42),
            rights: CapRights::CONTROL
                .union(CapRights::READ)
                .union(CapRights::WRITE),
        };
        let ro_cap = Capability {
            object: ObjectId(42),
            rights: CapRights::READ,
        };
        let dma_rw =
            DmaMapping::new(0x1000_0000, 0x8000_0000, 0x4000, DmaPerms::READ_WRITE).unwrap();
        let dma_ro = DmaMapping::new(0x2000_0000, 0x8000_4000, 0x4000, DmaPerms::READ).unwrap();

        let pci = PciAddress {
            segment: 0,
            bus: 0,
            device: 1,
            function: 0,
        };
        let mut nvme = NvmeController::<8>::new(ecam(), pci, false).unwrap();
        nvme.enable(ctrl_rw, 64, 64).unwrap();
        let data_in = [0x3cu8; 512];
        nvme.write_blocks(ctrl_rw, &dma_rw, 1, 0x1000_0000, 3, &data_in)
            .unwrap();
        nvme.flush(ctrl_rw).unwrap();

        let mut data_out = [0u8; 512];
        nvme.read_blocks(ro_cap, &dma_rw, 1, 0x1000_0000, 3, &mut data_out)
            .unwrap();
        assert_eq!(data_out, data_in);

        // Read DMA mapping cannot accept controller-written read_blocks destination.
        assert_eq!(
            nvme.read_blocks(ro_cap, &dma_ro, 1, 0x2000_0000, 3, &mut data_out),
            Err(StorageError::DmaViolation)
        );
        // Reset revokes old queue generation.
        nvme.controller_reset(ctrl_rw).unwrap();
        assert_eq!(
            nvme.read_blocks(ro_cap, &dma_rw, 1, 0x1000_0000, 3, &mut data_out),
            Err(StorageError::NotReady)
        );

        let mut ahci = AhciController::<2, 8>::new();
        let gen0 = ahci.enable_port(ctrl_rw, 0, false).unwrap();
        let mut sbuf = [0x7du8; 512];
        ahci.sata_rw(
            ctrl_rw,
            &dma_rw,
            SataCommand {
                port: 0,
                command_slot: 0,
                expected_generation: gen0,
                prdt_iova: 0x1000_0000,
                lba: 1,
                write: true,
            },
            &mut sbuf,
        )
        .unwrap();
        let mut rbuf = [0u8; 512];
        ahci.sata_rw(
            ro_cap,
            &dma_rw,
            SataCommand {
                port: 0,
                command_slot: 1,
                expected_generation: gen0,
                prdt_iova: 0x1000_0000,
                lba: 1,
                write: false,
            },
            &mut rbuf,
        )
        .unwrap();
        assert_eq!(rbuf, sbuf);

        let gen1 = ahci.comreset_port(ctrl_rw, 0).unwrap();
        assert!(gen1 > gen0);
        assert_eq!(
            ahci.sata_rw(
                ro_cap,
                &dma_rw,
                SataCommand {
                    port: 0,
                    command_slot: 1,
                    expected_generation: gen0,
                    prdt_iova: 0x1000_0000,
                    lba: 1,
                    write: false,
                },
                &mut rbuf
            ),
            Err(StorageError::StaleGeneration)
        );
    }

    #[test]
    fn wired_nic_usb_hid_msc_rtc_watchdog_and_entropy_work() {
        let cap_rw = Capability {
            object: ObjectId(43),
            rights: CapRights::CONTROL
                .union(CapRights::READ)
                .union(CapRights::WRITE),
        };
        let dma = DmaMapping::new(0x1000_0000, 0x8000_0000, 0x4000, DmaPerms::READ_WRITE).unwrap();
        let mut nic = WiredEthernetNic::<4>::new(
            ecam(),
            NicConfig {
                pci: PciAddress {
                    segment: 0,
                    bus: 0,
                    device: 2,
                    function: 0,
                },
                mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x42],
                mtu: 1500,
                speed_mbps: 1000,
                full_duplex: true,
                tx_csum_offload: true,
                rx_csum_offload: true,
            },
        )
        .unwrap();
        nic.tx_submit(cap_rw, &dma, 1, 0x1000_0000, &[0x99u8; 64])
            .unwrap();
        let mut out = [0u8; 128];
        assert_eq!(nic.pop_wire_tx(&mut out).unwrap(), 64);

        // USB config descriptor & MSC CBW/CSW validation.
        let cfg = [
            9, 2, 25, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 3, 1, 1, 0, 7, 5, 0x81, 3, 8, 0, 10,
        ];
        let parsed = parse_config_descriptors(&cfg).unwrap();
        assert_eq!(parsed.num_interfaces, 1);
        assert_eq!(parsed.num_endpoints, 1);
        assert_eq!(parsed.interface_class, 3);

        let kbd = HidBootKeyboardReport::decode(&[0x02, 0, 0x04, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(kbd.modifiers, 0x02);
        assert_eq!(kbd.keys[0], 0x04);

        let cbw = UsbMscCbw {
            tag: 0xdead_beef,
            transfer_len: 512,
            flags: 0x80,
            lun: 0,
            cdb_len: 10,
            cdb: [0x28; 16],
        }
        .encode()
        .unwrap();
        assert_eq!(&cbw[0..4], b"USBC");
        let mut csw = [0u8; 13];
        csw[0..4].copy_from_slice(b"USBS");
        csw[4..8].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        assert!(UsbMscCsw::decode_and_verify(&csw, 0xdead_beef).is_ok());
        assert_eq!(
            UsbMscCsw::decode_and_verify(&csw, 0x1111_2222),
            Err(Errno::EIO)
        );

        // PL031 RTC roundtrip including leap day 2024-02-29.
        let mut rtc = RtcPl031::new(0);
        let leap = RtcTime {
            sec: 5,
            min: 4,
            hour: 3,
            mday: 29,
            mon: 1,    // Feb
            year: 124, // 2024
            wday: 0,
            yday: 0,
            isdst: 0,
        };
        rtc.set_time(cap_rw, leap).unwrap();
        let read_back = rtc.read_time();
        assert_eq!(read_back.year, 124);
        assert_eq!(read_back.mon, 1);
        assert_eq!(read_back.mday, 29);

        // Watchdog timeout expiry triggers RebootAction::Restart.
        let mut wdt = WatchdogDevice::new(10, false);
        wdt.start(cap_rw).unwrap();
        assert_eq!(wdt.tick_seconds(4), None);
        assert_eq!(wdt.tick_seconds(6), Some(RebootAction::Restart));

        // Hardware entropy fails closed until >= 256 bits are mixed.
        let mut pool = HardwareEntropyPool::new();
        let mut rnd = [0u8; 32];
        assert_eq!(pool.fill_bytes(&mut rnd), Err(Errno::EAGAIN));
        assert_eq!(pool.mix_seed(&[0u8; 32]), Err(Errno::EINVAL));
        pool.mix_seed(&[0x5a; 32]).unwrap();
        assert!(pool.is_seeded());
        pool.fill_bytes(&mut rnd).unwrap();
        assert_ne!(rnd, [0u8; 32]);
    }
}
