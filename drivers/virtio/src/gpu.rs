// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![forbid(unsafe_code)]

//! VirtIO 1.2 GPU (`virtio-gpu`, device ID 16) 2D control structures and fail-closed validation.

use crate::VirtioError;

/// VirtIO-GPU maximum scanouts defined by the specification (§5.7.6.8).
pub const VIRTIO_GPU_MAX_SCANOUTS: usize = 16;

/// VirtIO-GPU command codes (§5.7.6.7).
pub const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x0100;
pub const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
pub const VIRTIO_GPU_CMD_RESOURCE_UNREF: u32 = 0x0102;
pub const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x0103;
pub const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32 = 0x0104;
pub const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
pub const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
pub const VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
pub const VIRTIO_GPU_CMD_GET_EDID: u32 = 0x010a;

/// VirtIO-GPU response codes (§5.7.6.7).
pub const VIRTIO_GPU_RESP_OK_NODATA: u32 = 0x1100;
pub const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;
pub const VIRTIO_GPU_RESP_OK_EDID: u32 = 0x1104;
pub const VIRTIO_GPU_RESP_ERR_UNSPEC: u32 = 0x1200;
pub const VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY: u32 = 0x1201;
pub const VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
pub const VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
pub const VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID: u32 = 0x1204;
pub const VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER: u32 = 0x1205;

/// Optional VirtIO-GPU feature bits (§5.7.3).
pub const VIRTIO_GPU_F_VIRGL: u64 = 1 << 0;
pub const VIRTIO_GPU_F_EDID: u64 = 1 << 1;

/// Supported 32-bpp 2D pixel formats (`enum virtio_gpu_formats`).
pub const VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM: u32 = 1;
pub const VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: u32 = 2;
pub const VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM: u32 = 3;
pub const VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM: u32 = 4;
pub const VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM: u32 = 67;
pub const VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM: u32 = 68;
pub const VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM: u32 = 121;
pub const VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM: u32 = 134;

/// Common VirtIO-GPU control request/response header (24 bytes LE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioGpuCtrlHdr {
    pub cmd_type: u32,
    pub flags: u32,
    pub fence_id: u64,
    pub ctx_id: u32,
    pub ring_idx: u8,
    pub padding: [u8; 3],
}

impl VirtioGpuCtrlHdr {
    pub const fn new(cmd_type: u32) -> Self {
        Self {
            cmd_type,
            flags: 0,
            fence_id: 0,
            ctx_id: 0,
            ring_idx: 0,
            padding: [0; 3],
        }
    }
}

/// Rectangle coordinate descriptor (`struct virtio_gpu_rect`, 16 bytes LE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioGpuRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl VirtioGpuRect {
    pub const fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub const fn validate_within(self, max_w: u32, max_h: u32) -> Result<(), VirtioError> {
        if self.width == 0 || self.height == 0 {
            return Err(VirtioError::OutOfRange);
        }
        let Some(end_x) = self.x.checked_add(self.width) else {
            return Err(VirtioError::OutOfRange);
        };
        let Some(end_y) = self.y.checked_add(self.height) else {
            return Err(VirtioError::OutOfRange);
        };
        if end_x > max_w || end_y > max_h {
            return Err(VirtioError::OutOfRange);
        }
        Ok(())
    }
}

/// One scanout slot returned inside `VIRTIO_GPU_RESP_OK_DISPLAY_INFO` (24 bytes LE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioGpuDisplayOne {
    pub r: VirtioGpuRect,
    pub enabled: u32,
    pub flags: u32,
}

/// Response payload for `VIRTIO_GPU_CMD_GET_DISPLAY_INFO` (408 bytes LE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtioGpuRespDisplayInfo {
    pub hdr: VirtioGpuCtrlHdr,
    pub pmodes: [VirtioGpuDisplayOne; VIRTIO_GPU_MAX_SCANOUTS],
}

/// Request payload for `VIRTIO_GPU_CMD_RESOURCE_CREATE_2D` (40 bytes LE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioGpuResourceCreate2d {
    pub hdr: VirtioGpuCtrlHdr,
    pub resource_id: u32,
    pub format: u32,
    pub width: u32,
    pub height: u32,
}

/// Request payload for `VIRTIO_GPU_CMD_RESOURCE_UNREF` (32 bytes LE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioGpuResourceUnref {
    pub hdr: VirtioGpuCtrlHdr,
    pub resource_id: u32,
    pub padding: u32,
}

/// Request header for `VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING` (32 bytes LE), followed by
/// `nr_entries` instances of [`VirtioGpuMemEntry`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioGpuResourceAttachBacking {
    pub hdr: VirtioGpuCtrlHdr,
    pub resource_id: u32,
    pub nr_entries: u32,
}

/// One scatter-gather physical backing extent (`struct virtio_gpu_mem_entry`, 16 bytes LE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioGpuMemEntry {
    pub addr: u64,
    pub length: u32,
    pub padding: u32,
}

/// Request payload for `VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING` (32 bytes LE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioGpuResourceDetachBacking {
    pub hdr: VirtioGpuCtrlHdr,
    pub resource_id: u32,
    pub padding: u32,
}

/// Request payload for `VIRTIO_GPU_CMD_SET_SCANOUT` (48 bytes LE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioGpuSetScanout {
    pub hdr: VirtioGpuCtrlHdr,
    pub r: VirtioGpuRect,
    pub scanout_id: u32,
    pub resource_id: u32,
}

/// Request payload for `VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D` (56 bytes LE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioGpuTransferToHost2d {
    pub hdr: VirtioGpuCtrlHdr,
    pub r: VirtioGpuRect,
    pub offset: u64,
    pub resource_id: u32,
    pub padding: u32,
}

/// Request payload for `VIRTIO_GPU_CMD_RESOURCE_FLUSH` (48 bytes LE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioGpuResourceFlush {
    pub hdr: VirtioGpuCtrlHdr,
    pub r: VirtioGpuRect,
    pub resource_id: u32,
    pub padding: u32,
}

/// Device configuration registers at MMIO `REG_CONFIG_BASE + 0x00..0x10` (§5.7.4).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioGpuConfig {
    pub events_read: u32,
    pub events_clear: u32,
    pub num_scanouts: u32,
    pub num_capsets: u32,
}

pub const fn is_supported_gpu_format(format: u32) -> bool {
    matches!(
        format,
        VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM
            | VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM
            | VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM
            | VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM
            | VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM
            | VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM
            | VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM
            | VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM
    )
}

pub fn validate_create_2d(
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
) -> Result<u64, VirtioError> {
    if resource_id == 0 || !is_supported_gpu_format(format) || width == 0 || height == 0 {
        return Err(VirtioError::OutOfRange);
    }
    let pitch = u64::from(width)
        .checked_mul(4)
        .ok_or(VirtioError::DescriptorLengthOverflow)?;
    pitch
        .checked_mul(u64::from(height))
        .ok_or(VirtioError::DescriptorLengthOverflow)
}

pub fn validate_mem_entries(entries: &[VirtioGpuMemEntry]) -> Result<u64, VirtioError> {
    if entries.is_empty() {
        return Err(VirtioError::OutOfRange);
    }
    let mut total = 0u64;
    for entry in entries {
        if entry.length == 0 || entry.padding != 0 {
            return Err(VirtioError::OutOfRange);
        }
        entry
            .addr
            .checked_add(u64::from(entry.length))
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
        total = total
            .checked_add(u64::from(entry.length))
            .ok_or(VirtioError::DescriptorLengthOverflow)?;
    }
    Ok(total)
}

pub const fn gpu_response_to_error(resp_type: u32, expected: u32) -> Result<(), VirtioError> {
    if resp_type == expected {
        return Ok(());
    }
    match resp_type {
        VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID
        | VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID
        | VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID
        | VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER => Err(VirtioError::OutOfRange),
        VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY => Err(VirtioError::BufferTooSmall),
        _ => Err(VirtioError::DeviceFault),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn gpu_abi_struct_sizes_match_virtio_1_2_spec() {
        assert_eq!(size_of::<VirtioGpuCtrlHdr>(), 24);
        assert_eq!(size_of::<VirtioGpuRect>(), 16);
        assert_eq!(size_of::<VirtioGpuDisplayOne>(), 24);
        assert_eq!(size_of::<VirtioGpuRespDisplayInfo>(), 408);
        assert_eq!(size_of::<VirtioGpuResourceCreate2d>(), 40);
        assert_eq!(size_of::<VirtioGpuResourceUnref>(), 32);
        assert_eq!(size_of::<VirtioGpuResourceAttachBacking>(), 32);
        assert_eq!(size_of::<VirtioGpuMemEntry>(), 16);
        assert_eq!(size_of::<VirtioGpuResourceDetachBacking>(), 32);
        assert_eq!(size_of::<VirtioGpuSetScanout>(), 48);
        assert_eq!(size_of::<VirtioGpuTransferToHost2d>(), 56);
        assert_eq!(size_of::<VirtioGpuResourceFlush>(), 48);
    }

    #[test]
    fn gpu_validation_rejects_invalid_rect_resource_and_mem_entries() {
        assert_eq!(
            validate_create_2d(0, VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM, 1280, 800),
            Err(VirtioError::OutOfRange)
        );
        assert_eq!(
            validate_create_2d(1, VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM, 1280, 800),
            Ok(4_096_000)
        );
        assert!(
            VirtioGpuRect::new(100, 100, 200, 200)
                .validate_within(1280, 800)
                .is_ok()
        );
        assert_eq!(
            VirtioGpuRect::new(1200, 0, 100, 100).validate_within(1280, 800),
            Err(VirtioError::OutOfRange)
        );
        assert_eq!(validate_mem_entries(&[]), Err(VirtioError::OutOfRange));
        assert_eq!(
            validate_mem_entries(&[VirtioGpuMemEntry {
                addr: 0x4000_0000,
                length: 4096,
                padding: 0,
            }]),
            Ok(4096)
        );
    }
}
