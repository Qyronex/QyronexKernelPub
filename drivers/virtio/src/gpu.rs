// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![forbid(unsafe_code)]

//! Bounded VirtIO-GPU control protocol codecs for the Step-43 AArch64 desktop path.
//! Queue submission and DMA mapping remain the responsibility of the MMIO device owner.

use crate::VirtioError;

pub const GPU_CMD_GET_DISPLAY_INFO: u32 = 0x0100;
pub const GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
pub const GPU_CMD_RESOURCE_UNREF: u32 = 0x0102;
pub const GPU_CMD_SET_SCANOUT: u32 = 0x0103;
pub const GPU_CMD_RESOURCE_FLUSH: u32 = 0x0104;
pub const GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
pub const GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
pub const GPU_CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;

pub const GPU_RESP_OK_NODATA: u32 = 0x1100;
pub const GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;
pub const GPU_FORMAT_B8G8R8A8_UNORM: u32 = 1;
pub const GPU_MAX_SCANOUTS: usize = 16;
pub const GPU_HEADER_BYTES: usize = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GpuRect { pub x: u32, pub y: u32, pub width: u32, pub height: u32 }

impl GpuRect {
    pub fn validate(self) -> Result<Self, VirtioError> {
        if self.width == 0 || self.height == 0 || self.x.checked_add(self.width).is_none()
            || self.y.checked_add(self.height).is_none() { return Err(VirtioError::OutOfRange); }
        Ok(self)
    }
    fn encode_into(self, out: &mut [u8], offset: usize) {
        put_u32(out, offset, self.x); put_u32(out, offset + 4, self.y);
        put_u32(out, offset + 8, self.width); put_u32(out, offset + 12, self.height);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GpuDisplay { pub rect: GpuRect, pub enabled: bool }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GpuDisplayInfo { pub displays: [Option<GpuDisplay>; GPU_MAX_SCANOUTS] }

impl GpuDisplayInfo {
    /// Parses the fixed-size 408-byte RESP_OK_DISPLAY_INFO response.
    pub fn decode(bytes: &[u8]) -> Result<Self, VirtioError> {
        const RESPONSE_BYTES: usize = GPU_HEADER_BYTES + GPU_MAX_SCANOUTS * 24;
        if bytes.len() < RESPONSE_BYTES || get_u32(bytes, 0)? != GPU_RESP_OK_DISPLAY_INFO {
            return Err(VirtioError::DeviceFault);
        }
        let mut displays = [None; GPU_MAX_SCANOUTS];
        for (index, slot) in displays.iter_mut().enumerate() {
            let off = GPU_HEADER_BYTES + index * 24;
            let rect = GpuRect { x: get_u32(bytes, off)?, y: get_u32(bytes, off + 4)?,
                width: get_u32(bytes, off + 8)?, height: get_u32(bytes, off + 12)? };
            let enabled = get_u32(bytes, off + 16)? != 0;
            if enabled { rect.validate()?; *slot = Some(GpuDisplay { rect, enabled }); }
        }
        Ok(Self { displays })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GpuBackingEntry { pub address: u64, pub length: u32 }

pub fn encode_get_display_info(out: &mut [u8]) -> Result<usize, VirtioError> {
    encode_header(out, GPU_HEADER_BYTES, GPU_CMD_GET_DISPLAY_INFO)?; Ok(GPU_HEADER_BYTES)
}

pub fn encode_resource_create_2d(out: &mut [u8], resource_id: u32, format: u32,
    width: u32, height: u32) -> Result<usize, VirtioError> {
    if resource_id == 0 || width == 0 || height == 0 || width.checked_mul(4).is_none()
        || width.checked_mul(height).and_then(|v| v.checked_mul(4)).is_none() {
        return Err(VirtioError::OutOfRange);
    }
    encode_header(out, 40, GPU_CMD_RESOURCE_CREATE_2D)?;
    put_u32(out, 24, resource_id); put_u32(out, 28, format);
    put_u32(out, 32, width); put_u32(out, 36, height); Ok(40)
}

pub fn encode_resource_attach_backing(out: &mut [u8], resource_id: u32,
    entries: &[GpuBackingEntry]) -> Result<usize, VirtioError> {
    if resource_id == 0 || entries.is_empty() || entries.len() > u32::MAX as usize {
        return Err(VirtioError::OutOfRange);
    }
    let payload = entries.len().checked_mul(16).ok_or(VirtioError::OutOfRange)?;
    let total = 32usize.checked_add(payload).ok_or(VirtioError::OutOfRange)?;
    encode_header(out, total, GPU_CMD_RESOURCE_ATTACH_BACKING)?;
    put_u32(out, 24, resource_id); put_u32(out, 28, entries.len() as u32);
    for (i, entry) in entries.iter().enumerate() {
        if entry.length == 0 || entry.address.checked_add(u64::from(entry.length)).is_none() {
            return Err(VirtioError::OutOfRange);
        }
        let off = 32 + i * 16; put_u64(out, off, entry.address);
        put_u32(out, off + 8, entry.length); put_u32(out, off + 12, 0);
    }
    Ok(total)
}

pub fn encode_set_scanout(out: &mut [u8], rect: GpuRect, scanout_id: u32,
    resource_id: u32) -> Result<usize, VirtioError> {
    rect.validate()?; encode_header(out, 48, GPU_CMD_SET_SCANOUT)?;
    rect.encode_into(out, 24); put_u32(out, 40, scanout_id); put_u32(out, 44, resource_id); Ok(48)
}

pub fn encode_transfer_to_host_2d(out: &mut [u8], rect: GpuRect, offset: u64,
    resource_id: u32) -> Result<usize, VirtioError> {
    rect.validate()?;
    offset.checked_add(u64::from(rect.width) * u64::from(rect.height) * 4)
        .ok_or(VirtioError::OutOfRange)?;
    encode_header(out, 56, GPU_CMD_TRANSFER_TO_HOST_2D)?;
    rect.encode_into(out, 24); put_u64(out, 40, offset); put_u32(out, 48, resource_id); Ok(56)
}

pub fn encode_resource_flush(out: &mut [u8], rect: GpuRect,
    resource_id: u32) -> Result<usize, VirtioError> {
    rect.validate()?; encode_header(out, 48, GPU_CMD_RESOURCE_FLUSH)?;
    rect.encode_into(out, 24); put_u32(out, 40, resource_id); Ok(48)
}

pub fn encode_resource_unref(out: &mut [u8], resource_id: u32) -> Result<usize, VirtioError> {
    if resource_id == 0 { return Err(VirtioError::OutOfRange); }
    encode_header(out, 32, GPU_CMD_RESOURCE_UNREF)?; put_u32(out, 24, resource_id); Ok(32)
}

fn encode_header(out: &mut [u8], len: usize, command: u32) -> Result<(), VirtioError> {
    if out.len() < len { return Err(VirtioError::BufferTooSmall); }
    out[..len].fill(0); put_u32(out, 0, command); Ok(())
}
fn get_u32(bytes: &[u8], offset: usize) -> Result<u32, VirtioError> {
    let end = offset.checked_add(4).ok_or(VirtioError::OutOfRange)?;
    let s = bytes.get(offset..end).ok_or(VirtioError::BufferTooSmall)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encodes_resource_and_scanout_commands() {
        let mut out = [0u8; 128];
        assert_eq!(encode_resource_create_2d(&mut out, 7, GPU_FORMAT_B8G8R8A8_UNORM, 800, 600), Ok(40));
        assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), GPU_CMD_RESOURCE_CREATE_2D);
        assert_eq!(u32::from_le_bytes(out[32..36].try_into().unwrap()), 800);
        assert_eq!(encode_set_scanout(&mut out, GpuRect { x: 0, y: 0, width: 800, height: 600 }, 0, 7), Ok(48));
        assert_eq!(u32::from_le_bytes(out[44..48].try_into().unwrap()), 7);
    }
    #[test]
    fn rejects_overflow_and_short_buffers() {
        let mut out = [0u8; 32];
        assert_eq!(encode_resource_create_2d(&mut out, 1, 1, u32::MAX, 2), Err(VirtioError::OutOfRange));
        assert_eq!(encode_get_display_info(&mut out), Err(VirtioError::BufferTooSmall));
        assert_eq!(GpuRect { x: u32::MAX, y: 0, width: 2, height: 1 }.validate(), Err(VirtioError::OutOfRange));
    }
    #[test]
    fn decodes_enabled_scanout_and_ignores_disabled_entries() {
        let mut response = [0u8; GPU_HEADER_BYTES + GPU_MAX_SCANOUTS * 24];
        put_u32(&mut response, 0, GPU_RESP_OK_DISPLAY_INFO);
        put_u32(&mut response, 24 + 8, 1024); put_u32(&mut response, 24 + 12, 768);
        put_u32(&mut response, 24 + 16, 1);
        let info = GpuDisplayInfo::decode(&response).unwrap();
        assert_eq!(info.displays[0].unwrap().rect.width, 1024);
        assert!(info.displays[1].is_none());
    }
}
