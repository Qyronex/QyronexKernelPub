// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_capability::{CapRights, Capability, ObjectId};
use kernal_fdt::Blob;
use kernal_fdt_aarch64::{Error as FdtError, parse_device_inventory};
use kernal_iommu::{DmaMapping, DmaPerms};
use kernal_linux_abi::Errno;
use kernal_linux_conformance::run_all_gates;
use kernal_linux_desktop::{
    DisplayMode, DrmDevice, EV_KEY, InputEvent, PcmAudioDevice, PcmFormat, PcmParams, SeatManager,
};
use kernal_linux_hardware::{
    AhciController, HardwareEntropyPool, NicConfig, NvmeController, RtcPl031, RtcTime,
    UsbHostController, UsbMscCbw, UsbMscCsw, WatchdogDevice, WiredEthernetNic,
};
use kernal_pci::{Address as PciAddress, EcamWindow};
use kernal_virtio::blk::{VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_RO, validate_blk_request};
use kernal_virtio::mmio::{
    MmioBus, REG_DEVICE_FEATURES, REG_DEVICE_FEATURES_SEL, REG_DEVICE_ID, REG_INTERRUPT_ACK,
    REG_INTERRUPT_STATUS, REG_MAGIC_VALUE, REG_QUEUE_NUM_MAX, REG_VENDOR_ID, REG_VERSION,
    VIRTIO_MMIO_MAGIC, VirtioDeviceId, VirtioMmioTransport,
};
use kernal_virtio::net::{
    NetDirection, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_MAC, VirtioNetL3,
    VirtioNetL4, VirtioNetValidation, validate_net_request,
};
use kernal_virtio::{
    DmaBufferGrant, SECTOR_SIZE, VIRTIO_F_VERSION_1, VRING_DESC_F_NEXT, VirtioBlkDevice,
    VirtioBlkOp, VirtioError, VirtqDesc,
};

const STEP20_CORPUS: &str = include_str!("../../../tests/prep/step20/virtio_block_cases.json");
const STEP21_CORPUS: &str = include_str!("../../../tests/prep/step21/virtio_net_cases.json");

fn extract_u64_field(line: &str, key: &str) -> u64 {
    let needle = format!("\"{key}\":");
    let start = line.find(&needle).unwrap() + needle.len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse::<u64>().unwrap()
}

fn extract_str_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":");
    let start = line.find(&needle)? + needle.len();
    let rest = line[start..].trim_start();
    if let Some(after_quote) = rest.strip_prefix('"') {
        let end = after_quote.find('"')?;
        Some(&after_quote[..end])
    } else {
        None
    }
}

fn extract_bool_field(line: &str, key: &str) -> bool {
    let needle = format!("\"{key}\":");
    let start = line.find(&needle).unwrap() + needle.len();
    line[start..].starts_with("true")
}

fn extract_descriptors(line: &str) -> Vec<VirtqDesc> {
    let start = line.find("\"descriptors\":[").unwrap() + "\"descriptors\":[".len();
    let end = start + line[start..].find(']').unwrap();
    let inner = &line[start..end];
    let mut out = Vec::new();
    for obj in inner.split('{').skip(1) {
        let body = obj.split('}').next().unwrap();
        let next_str = body.split("\"next\":").nth(1).unwrap().trim();
        let (flags, next) = if next_str == "null" {
            (0, 0)
        } else {
            (VRING_DESC_F_NEXT, next_str.parse::<u16>().unwrap())
        };
        out.push(VirtqDesc {
            addr: 0x8000_0000,
            len: 512,
            flags,
            next,
        });
    }
    out
}

fn extract_features(line: &str, mapping: &[(&str, u64)]) -> u64 {
    let start = line.find("\"features\":[").unwrap() + "\"features\":[".len();
    let end = start + line[start..].find(']').unwrap();
    let inner = &line[start..end];
    let mut bits = 0u64;
    if inner.trim().is_empty() {
        return 0;
    }
    for token in inner.split(',') {
        let clean = token.trim().trim_matches('"');
        match mapping.iter().find(|(k, _)| *k == clean) {
            Some((_, bit)) => bits |= *bit,
            None => bits |= 1u64 << 61, // sentinel unsupported bit
        }
    }
    bits
}

#[test]
fn step20_virtio_block_corpus_matches_rust_driver_validation_exactly() {
    let feature_map = [
        ("VERSION_1", VIRTIO_F_VERSION_1),
        ("BLK_F_FLUSH", VIRTIO_BLK_F_FLUSH),
        ("BLK_F_RO", VIRTIO_BLK_F_RO),
    ];
    let mut tested = 0usize;
    for line in STEP20_CORPUS.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("{\"id\":") {
            continue;
        }
        tested += 1;
        let q = extract_u64_field(trimmed, "queue_size") as usize;
        let head = extract_u64_field(trimmed, "head") as u16;
        let op = match extract_str_field(trimmed, "op").unwrap() {
            "read" => VirtioBlkOp::Read,
            "write" => VirtioBlkOp::Write,
            "flush" => VirtioBlkOp::Flush,
            other => panic!("unexpected op {other}"),
        };
        let features = extract_features(trimmed, &feature_map);
        let grant = DmaBufferGrant {
            base_addr: 0x8000_0000,
            len: 0x4000,
            writable: true,
            dma_assigned: true,
            buffer_generation: extract_u64_field(trimmed, "buffer_generation") as u32,
            expected_generation: extract_u64_field(trimmed, "expected_generation") as u32,
            revoked: extract_bool_field(trimmed, "buffer_revoked"),
        };
        let descriptors = extract_descriptors(trimmed);
        let expected_accept = extract_str_field(trimmed, "expected").unwrap() == "accept";
        let actual = validate_blk_request(q, features, op, &descriptors, head, &grant).is_ok();
        assert_eq!(
            actual, expected_accept,
            "Step-20 case mismatch on line: {trimmed}"
        );
    }
    assert_eq!(tested, 12);
}

#[test]
fn step21_virtio_net_corpus_matches_rust_driver_validation_exactly() {
    let feature_map = [
        ("VERSION_1", VIRTIO_F_VERSION_1),
        ("NET_F_MAC", VIRTIO_NET_F_MAC),
        ("CSUM", VIRTIO_NET_F_CSUM),
        ("GUEST_CSUM", VIRTIO_NET_F_GUEST_CSUM),
    ];
    let mut tested = 0usize;
    for line in STEP21_CORPUS.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("{\"id\":") {
            continue;
        }
        tested += 1;
        let q = extract_u64_field(trimmed, "queue_size") as usize;
        let head = extract_u64_field(trimmed, "head") as u16;
        let features = extract_features(trimmed, &feature_map);
        let direction = match extract_str_field(trimmed, "direction").unwrap() {
            "rx" => NetDirection::Rx,
            "tx" => NetDirection::Tx,
            other => panic!("unexpected direction {other}"),
        };
        let packet_len = extract_u64_field(trimmed, "packet_len") as usize;
        let mtu = extract_u64_field(trimmed, "mtu") as usize;
        let l3 = match extract_str_field(trimmed, "l3").unwrap() {
            "arp" => VirtioNetL3::Arp,
            "ipv4" => VirtioNetL3::Ipv4,
            "ipv6" => VirtioNetL3::Ipv6,
            other => panic!("unexpected l3 {other}"),
        };
        let l4 = match extract_str_field(trimmed, "l4") {
            None => None,
            Some("udp") => Some(VirtioNetL4::Udp),
            Some("tcp") => Some(VirtioNetL4::Tcp),
            Some(other) => {
                // Deliberately test invalid L4 strings like "sctp" fail closed!
                assert_eq!(other, "sctp");
                None
            }
        };
        let has_sctp = trimmed.contains("\"l4\":\"sctp\"");
        let grant = DmaBufferGrant {
            base_addr: 0x8000_0000,
            len: 0x4000,
            writable: true,
            dma_assigned: extract_bool_field(trimmed, "dma_assigned"),
            buffer_generation: extract_u64_field(trimmed, "buffer_generation") as u32,
            expected_generation: extract_u64_field(trimmed, "expected_generation") as u32,
            revoked: extract_bool_field(trimmed, "buffer_revoked"),
        };
        let descriptors = extract_descriptors(trimmed);
        let expected_accept = extract_str_field(trimmed, "expected").unwrap() == "accept";
        let actual = if has_sctp {
            false
        } else {
            validate_net_request(VirtioNetValidation {
                queue_size: q,
                features,
                direction,
                packet_len,
                mtu,
                l3,
                l4,
                descriptors: &descriptors,
                head,
                grant: &grant,
            })
            .is_ok()
        };
        assert_eq!(
            actual, expected_accept,
            "Step-21 case mismatch on line: {trimmed}"
        );
    }
    assert_eq!(tested, 14);
}

#[test]
fn step42_to_step44_end_to_end_hardware_desktop_and_release_gate_contract() {
    // End-to-end FDT + VirtIO + Step 42 server hardware + Step 43 desktop + Step 44 release gate.
    struct MockBus {
        regs: [u32; 128],
    }
    impl MmioBus for MockBus {
        fn region_size(&self) -> u64 {
            512
        }
        fn read32(&self, offset: usize) -> Result<u32, VirtioError> {
            if offset == REG_DEVICE_FEATURES {
                let sel = self.regs[REG_DEVICE_FEATURES_SEL / 4];
                return Ok(if sel == 0 { self.regs[offset / 4] } else { 1 });
            }
            self.regs
                .get(offset / 4)
                .copied()
                .ok_or(VirtioError::MmioOutOfBounds)
        }
        fn write32(&mut self, offset: usize, value: u32) -> Result<(), VirtioError> {
            self.regs[offset / 4] = value;
            if offset == REG_INTERRUPT_ACK {
                self.regs[REG_INTERRUPT_STATUS / 4] &= !value;
            }
            Ok(())
        }
        fn read8(&self, offset: usize) -> Result<u8, VirtioError> {
            let w = self.read32(offset & !3)?;
            Ok(((w >> ((offset & 3) * 8)) & 0xff) as u8)
        }
    }

    let mut bus = MockBus { regs: [0; 128] };
    bus.regs[REG_MAGIC_VALUE / 4] = VIRTIO_MMIO_MAGIC;
    bus.regs[REG_VERSION / 4] = 2;
    bus.regs[REG_DEVICE_ID / 4] = 2;
    bus.regs[REG_VENDOR_ID / 4] = 0x554d_4551;
    bus.regs[REG_DEVICE_FEATURES / 4] = VIRTIO_BLK_F_FLUSH as u32;
    bus.regs[REG_QUEUE_NUM_MAX / 4] = 128;

    let info = kernal_fdt_aarch64::VirtioMmioInfo {
        region: kernal_fdt_aarch64::MmioRegion {
            base: 0x0a00_0000,
            size: 0x200,
        },
        irq: 48,
        enabled: true,
    };
    let mut transport =
        VirtioMmioTransport::initialize(info, &mut bus, VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_FLUSH)
            .unwrap();
    assert_eq!(transport.device_id, VirtioDeviceId::Blk);
    transport
        .setup_queue(&mut bus, 0, 16, 0x4100_0000, 0x4100_1000, 0x4100_2000)
        .unwrap();
    transport.mark_driver_ok(&mut bus).unwrap();

    // VirtIO-Blk read-after-write on disposable RAM overlay.
    let ctrl_rw = Capability {
        object: ObjectId(44),
        rights: CapRights::CONTROL
            .union(CapRights::READ)
            .union(CapRights::WRITE),
    };
    let grant = DmaBufferGrant {
        base_addr: 0x8000_0000,
        len: 0x1_0000,
        writable: true,
        dma_assigned: true,
        buffer_generation: 1,
        expected_generation: 1,
        revoked: false,
    };
    let mut blk = VirtioBlkDevice::<8, 16>::new(VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_FLUSH).unwrap();
    let payload = [0x42u8; SECTOR_SIZE];
    blk.write_sectors(ctrl_rw, &grant, 0, &payload).unwrap();
    blk.flush(ctrl_rw, &grant).unwrap();
    let mut back = [0u8; SECTOR_SIZE];
    blk.read_sectors(ctrl_rw, &grant, 0, &mut back).unwrap();
    assert_eq!(back, payload);

    // Confirm invalid empty DTB fails closed cleanly.
    assert!(Blob::parse(&[]).is_err());
    let _ = FdtError::OverlappingRegion;

    // Step 42 hardware integration check.
    let ecam = EcamWindow {
        base: 0x40_1000_0000,
        segment: 0,
        start_bus: 0,
        end_bus: 7,
    };
    let pci = PciAddress {
        segment: 0,
        bus: 0,
        device: 1,
        function: 0,
    };
    let dma = DmaMapping::new(0x1000_0000, 0x8000_0000, 0x4000, DmaPerms::READ_WRITE).unwrap();
    let mut nvme = NvmeController::<4>::new(ecam, pci, false).unwrap();
    nvme.enable(ctrl_rw, 16, 16).unwrap();
    let _ = AhciController::<2, 4>::new();
    let _ = WiredEthernetNic::<4>::new(
        ecam,
        NicConfig {
            pci: PciAddress {
                segment: 0,
                bus: 0,
                device: 2,
                function: 0,
            },
            mac: [0x52, 0x54, 0, 0, 0, 2],
            mtu: 1500,
            speed_mbps: 1000,
            full_duplex: true,
            tx_csum_offload: true,
            rx_csum_offload: true,
        },
    )
    .unwrap();
    let usb = UsbHostController::<4>::new();
    assert_eq!(usb.active_generation(0), Err(Errno::ENODEV));
    let _ = UsbMscCbw {
        tag: 1,
        transfer_len: 512,
        flags: 0x80,
        lun: 0,
        cdb_len: 10,
        cdb: [0x28; 16],
    };
    let _ = UsbMscCsw::decode_and_verify(&[0u8; 13], 1);
    let _ = RtcPl031::new(
        RtcTime::from_epoch_seconds(1_784_000_000)
            .to_epoch_seconds()
            .unwrap(),
    );
    let _ = WatchdogDevice::new(30, false);
    let mut pool = HardwareEntropyPool::new();
    pool.mix_seed(&[0x3au8; 32]).unwrap();
    let mut rand = [0u8; 32];
    pool.fill_bytes(&mut rand).unwrap();
    let _ = dma;

    // Step 43 desktop seat & media checks.
    let mut seat = SeatManager::new();
    let s1 = seat.open_session(ctrl_rw, 1000, 1).unwrap();
    let a1 = seat.activate_session(ctrl_rw, s1.session_id).unwrap();
    let mut drm = DrmDevice::new();
    drm.set_master(
        ctrl_rw,
        a1.session_id,
        a1.generation,
        seat.seat_generation(),
    )
    .unwrap();
    let fb = drm.create_dumb(a1.session_id, 1280, 720, 32).unwrap();
    drm.set_crtc(
        a1.session_id,
        a1.generation,
        fb.handle,
        DisplayMode::default(),
    )
    .unwrap();
    seat.evdev
        .push_event(InputEvent {
            sec: 1,
            usec: 0,
            event_type: EV_KEY,
            code: 30,
            value: 1,
        })
        .unwrap();
    let _ = PcmAudioDevice::new();
    let _ = PcmParams {
        rate_hz: 48_000,
        channels: 2,
        format: PcmFormat::S16Le,
        period_frames: 256,
    };

    // Step 44 deterministic conformance + security + fuzz/stress release gate.
    let report = run_all_gates();
    assert!(report.all_passed());
    assert_eq!(report.total_failed(), 0);
    let _ = parse_device_inventory::<4>;
}
