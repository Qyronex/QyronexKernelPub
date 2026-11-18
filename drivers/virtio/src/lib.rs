// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! VirtIO MMIO v1/v2 transport, Split Virtqueue descriptor validation, and
//! capability/IOMMU-mediated `virtio-blk`, `virtio-net`, `virtio-gpu`, `virtio-input`, and
//! `virtio-rng` drivers.

pub mod blk;
pub mod blk_mmio;
pub mod gpu;
pub mod gpu_mmio;
pub mod input;
pub mod input_mmio;
pub mod mmio;
pub mod net;
pub mod net_mmio;
pub mod queue;
pub mod rng;

pub use blk::{
    SECTOR_SIZE, VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_RO, VIRTIO_BLK_F_SIZE_MAX,
    VirtioBlkDevice, VirtioBlkOp, VirtioBlkReqHeader,
};
pub use blk_mmio::{
    DEFAULT_BLK_MMIO_DMA_BYTES, DEFAULT_BLK_MMIO_QUEUE_SIZE, VirtioBlkDmaBlock, VirtioBlkMmio,
};
pub use gpu::{
    VIRTIO_GPU_F_EDID, VIRTIO_GPU_F_VIRGL, VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM,
    VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM, VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
    VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM, VIRTIO_GPU_MAX_SCANOUTS, VirtioGpuConfig, VirtioGpuCtrlHdr,
    VirtioGpuDisplayOne, VirtioGpuMemEntry, VirtioGpuRect, VirtioGpuRespDisplayInfo,
};
pub use gpu_mmio::{
    DEFAULT_GPU_MMIO_QUEUE_SIZE, DEFAULT_GPU_MMIO_REQ_BYTES, VirtioGpuDmaBlock, VirtioGpuMmio,
};
pub use input::{
    VirtioInputAbsInfo, VirtioInputCaps, VirtioInputDevids, VirtioInputEvent, VirtioInputKind,
};
pub use input_mmio::{DEFAULT_INPUT_MMIO_QUEUE_SIZE, VirtioInputDmaBlock, VirtioInputMmio};
pub use mmio::{
    MmioBus, VIRTIO_F_VERSION_1, VIRTIO_MMIO_MAGIC, VirtioDeviceId, VirtioMmioTransport,
    VolatileMmioBus,
};
pub use net::{
    NET_DEFAULT_MTU, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_MAC,
    VIRTIO_NET_F_MTU, VIRTIO_NET_F_STATUS, VirtioNetDevice, VirtioNetHdr, VirtioNetL3, VirtioNetL4,
    VirtioNetValidation,
};
pub use net_mmio::{
    DEFAULT_NET_MMIO_BUF_BYTES, DEFAULT_NET_MMIO_QUEUE_SIZE, HARDWARE_NET_FEATURES,
    VirtioNetDmaBlock, VirtioNetMmio,
};
pub use queue::{
    DmaBufferGrant, MAX_VIRTQ_SIZE, SplitVirtqueue, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE,
    VirtqDesc, VirtqUsedElem, validate_descriptor_chain,
};
pub use rng::VirtioRngDevice;

use kernal_linux_abi::Errno;

/// Unified fail-closed error surface across VirtIO MMIO transport, queues, and device drivers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtioError {
    BadMagic,
    UnsupportedVersion,
    UnsupportedDeviceId,
    DeviceDisabled,
    FeaturesRejected,
    MissingVersion1Feature,
    UnsupportedFeature,
    InvalidQueueSize,
    QueueOutOfRange,
    QueueAlreadyReady,
    DescriptorOutOfBounds,
    DescriptorCycle,
    DescriptorLengthOverflow,
    DescriptorOrderingInvalid,
    DmaUnassigned,
    StaleGeneration,
    RevokedAuthority,
    BufferTooSmall,
    ReadOnlyDevice,
    UnsupportedOp,
    OutOfRange,
    InvalidPacket,
    QueueFull,
    QueueEmpty,
    MmioOutOfBounds,
    DeviceFault,
}

impl VirtioError {
    pub const fn to_errno(self) -> Errno {
        match self {
            Self::ReadOnlyDevice => Errno::EROFS,
            Self::RevokedAuthority | Self::StaleGeneration | Self::DmaUnassigned => Errno::EACCES,
            Self::QueueFull | Self::QueueEmpty => Errno::EAGAIN,
            Self::UnsupportedOp
            | Self::UnsupportedVersion
            | Self::UnsupportedDeviceId
            | Self::UnsupportedFeature => Errno::EOPNOTSUPP,
            Self::DeviceFault | Self::DeviceDisabled | Self::BadMagic => Errno::EIO,
            Self::OutOfRange
            | Self::BufferTooSmall
            | Self::InvalidPacket
            | Self::InvalidQueueSize
            | Self::QueueOutOfRange
            | Self::QueueAlreadyReady
            | Self::DescriptorOutOfBounds
            | Self::DescriptorCycle
            | Self::DescriptorLengthOverflow
            | Self::DescriptorOrderingInvalid
            | Self::FeaturesRejected
            | Self::MissingVersion1Feature
            | Self::MmioOutOfBounds => Errno::EINVAL,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmio::*;
    use kernal_capability::{CapRights, Capability, ObjectId};
    use kernal_fdt_aarch64::{MmioRegion, VirtioMmioInfo};

    struct MockMmioBus {
        regs: [u32; 128],
    }

    impl MockMmioBus {
        fn new(device_id: u32, features: u64, max_q: u32) -> Self {
            let mut regs = [0u32; 128];
            regs[REG_MAGIC_VALUE / 4] = VIRTIO_MMIO_MAGIC;
            regs[REG_VERSION / 4] = 2;
            regs[REG_DEVICE_ID / 4] = device_id;
            regs[REG_VENDOR_ID / 4] = 0x554d_4551; // "QEMU"
            regs[REG_DEVICE_FEATURES / 4] = features as u32;
            regs[REG_QUEUE_NUM_MAX / 4] = max_q;
            regs[REG_INTERRUPT_STATUS / 4] = 1;
            Self { regs }
        }
    }

    impl MmioBus for MockMmioBus {
        fn region_size(&self) -> u64 {
            512
        }

        fn read32(&self, offset: usize) -> Result<u32, VirtioError> {
            if offset == REG_DEVICE_FEATURES {
                let sel = self.regs[REG_DEVICE_FEATURES_SEL / 4];
                return Ok(if sel == 0 {
                    self.regs[REG_DEVICE_FEATURES / 4]
                } else {
                    1 // VIRTIO_F_VERSION_1 (bit 32 -> bit 0 of high word)
                });
            }
            self.regs
                .get(offset / 4)
                .copied()
                .ok_or(VirtioError::MmioOutOfBounds)
        }

        fn write32(&mut self, offset: usize, value: u32) -> Result<(), VirtioError> {
            let slot = self
                .regs
                .get_mut(offset / 4)
                .ok_or(VirtioError::MmioOutOfBounds)?;
            *slot = value;
            if offset == REG_INTERRUPT_ACK {
                self.regs[REG_INTERRUPT_STATUS / 4] &= !value;
            }
            Ok(())
        }

        fn read8(&self, offset: usize) -> Result<u8, VirtioError> {
            let word = self.read32(offset & !3)?;
            Ok(((word >> ((offset & 3) * 8)) & 0xff) as u8)
        }
    }

    fn dma_ok() -> DmaBufferGrant {
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

    #[test]
    fn virtio_mmio_transport_handshake_queue_setup_and_teardown() {
        let info = VirtioMmioInfo {
            region: MmioRegion {
                base: 0x0a00_0000,
                size: 0x200,
            },
            irq: 48,
            enabled: true,
        };
        let mut bus = MockMmioBus::new(2, VIRTIO_BLK_F_FLUSH, 128);
        let mut transport = VirtioMmioTransport::initialize(
            info,
            &mut bus,
            VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_FLUSH,
        )
        .unwrap();
        assert_eq!(transport.device_id, VirtioDeviceId::Blk);
        assert_ne!(transport.negotiated_features & VIRTIO_F_VERSION_1, 0);
        transport
            .setup_queue(&mut bus, 0, 16, 0x4100_0000, 0x4100_1000, 0x4100_2000)
            .unwrap();
        transport.mark_driver_ok(&mut bus).unwrap();
        transport.notify_queue(&mut bus, 0).unwrap();
        assert_eq!(transport.ack_interrupt(&mut bus).unwrap(), 1);
        assert_eq!(transport.ack_interrupt(&mut bus).unwrap(), 0);

        let prev_gen = transport.generation;
        transport.reset_and_revoke(&mut bus).unwrap();
        assert!(!transport.driver_ok);
        assert!(transport.generation > prev_gen);
        assert_eq!(
            transport.notify_queue(&mut bus, 0),
            Err(VirtioError::DeviceFault)
        );
    }

    #[test]
    fn virtio_blk_read_write_flush_and_fail_closed_guards() {
        let cap_rw = Capability {
            object: ObjectId(20),
            rights: CapRights::READ.union(CapRights::WRITE),
        };
        let cap_ro = Capability {
            object: ObjectId(20),
            rights: CapRights::READ,
        };
        let grant = dma_ok();
        let mut blk =
            VirtioBlkDevice::<8, 16>::new(VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_FLUSH).unwrap();

        let mut sector_in = [0xA5u8; SECTOR_SIZE];
        sector_in[..4].copy_from_slice(b"EXT4");
        blk.write_sectors(cap_rw, &grant, 2, &sector_in).unwrap();
        blk.flush(cap_rw, &grant).unwrap();
        assert_eq!(blk.flush_generation(), 1);

        let mut sector_out = [0u8; SECTOR_SIZE];
        blk.read_sectors(cap_ro, &grant, 2, &mut sector_out)
            .unwrap();
        assert_eq!(sector_out, sector_in);

        assert_eq!(
            blk.write_sectors(cap_ro, &grant, 2, &sector_in),
            Err(VirtioError::RevokedAuthority)
        );
        let mut stale = grant;
        stale.buffer_generation = 99;
        assert_eq!(
            blk.read_sectors(cap_ro, &stale, 2, &mut sector_out),
            Err(VirtioError::StaleGeneration)
        );
    }

    #[test]
    fn virtio_net_and_rng_enforce_mtu_l3_l4_and_dma_grants() {
        let cap_rw = Capability {
            object: ObjectId(21),
            rights: CapRights::READ.union(CapRights::WRITE),
        };
        let grant = dma_ok();
        let mut net = VirtioNetDevice::<16, 4>::new(
            VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC,
            [0x52, 0x54, 0, 0, 0, 1],
            1500,
        )
        .unwrap();

        let pkt = [0x11u8; 64];
        net.transmit(
            cap_rw,
            &grant,
            VirtioNetL3::Ipv4,
            Some(VirtioNetL4::Udp),
            &pkt,
        )
        .unwrap();
        let mut popped = [0u8; 128];
        let popped_len = net.pop_transmitted(&mut popped).unwrap();
        assert_eq!(&popped[..popped_len], &pkt[..]);

        // ARP with L4 must fail closed.
        assert_eq!(
            net.transmit(
                cap_rw,
                &grant,
                VirtioNetL3::Arp,
                Some(VirtioNetL4::Tcp),
                &pkt
            ),
            Err(VirtioError::InvalidPacket)
        );

        net.inject_rx_frame(&pkt).unwrap();
        let mut rx_out = [0u8; 128];
        assert_eq!(net.receive(cap_rw, &grant, &mut rx_out).unwrap(), 64);

        let mut rng = VirtioRngDevice::<8>::new(VIRTIO_F_VERSION_1, 0x1234_5678_9abc_def0).unwrap();
        let mut entropy = [0u8; 32];
        rng.harvest_entropy(cap_rw, &grant, &mut entropy).unwrap();
        assert_ne!(entropy, [0u8; 32]);
    }
}
