// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_capability::{CapRights, Capability};
use kernal_linux_abi::Errno;

pub const DRM_IOCTL_VERSION: u64 = 0xc040_6400;
pub const DRM_IOCTL_GET_CAP: u64 = 0xc010_640c;
pub const DRM_IOCTL_SET_MASTER: u64 = 0x0000_641e;
pub const DRM_IOCTL_DROP_MASTER: u64 = 0x0000_641f;
pub const DRM_IOCTL_MODE_GETRESOURCES: u64 = 0xc040_64a0;
pub const DRM_IOCTL_MODE_SETCRTC: u64 = 0xc068_64a2;
pub const DRM_IOCTL_MODE_CREATE_DUMB: u64 = 0xc020_64b2;
pub const DRM_IOCTL_MODE_MAP_DUMB: u64 = 0xc010_64b3;
pub const DRM_IOCTL_MODE_DESTROY_DUMB: u64 = 0xc004_64b4;

pub const FBIOGET_VSCREENINFO: u64 = 0x4600;
pub const FBIOGET_FSCREENINFO: u64 = 0x4602;
pub const DRM_CAP_DUMB_BUFFER: u64 = 0x1;

pub const MAX_DUMB_BUFFERS: usize = 8;
pub const MAX_DUMB_SIZE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayMode {
    pub width: u32,
    pub height: u32,
    pub bpp: u32,
    pub refresh_hz: u32,
}

impl Default for DisplayMode {
    fn default() -> Self {
        Self {
            width: 1280,
            height: 720,
            bpp: 32,
            refresh_hz: 60,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DumbBufferMeta {
    pub handle: u32,
    pub width: u32,
    pub height: u32,
    pub bpp: u32,
    pub pitch: u32,
    pub size: u64,
    pub mmap_offset: u64,
    pub owner_session: u32,
    pub active: bool,
}

impl DumbBufferMeta {
    const EMPTY: Self = Self {
        handle: 0,
        width: 0,
        height: 0,
        bpp: 0,
        pitch: 0,
        size: 0,
        mmap_offset: 0,
        owner_session: 0,
        active: false,
    };
}

/// Optional DRM/KMS + simplefb device (`/dev/dri/card0`, `/dev/fb0`) requiring explicit seat
/// master authority for modesetting and buffer ownership.
#[derive(Clone, Debug)]
pub struct DrmDevice {
    pub mode: DisplayMode,
    pub active_master_session: Option<u32>,
    pub active_master_generation: u32,
    pub active_fb_handle: Option<u32>,
    pub active_crtc_id: u32,
    next_handle: u32,
    buffers: [DumbBufferMeta; MAX_DUMB_BUFFERS],
}

impl Default for DrmDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl DrmDevice {
    pub const fn new() -> Self {
        Self {
            mode: DisplayMode {
                width: 1280,
                height: 720,
                bpp: 32,
                refresh_hz: 60,
            },
            active_master_session: None,
            active_master_generation: 1,
            active_fb_handle: None,
            active_crtc_id: 1,
            next_handle: 1,
            buffers: [DumbBufferMeta::EMPTY; MAX_DUMB_BUFFERS],
        }
    }

    pub fn set_master(
        &mut self,
        cap: Capability,
        session_id: u32,
        seat_generation: u32,
        active_seat_gen: u32,
    ) -> Result<(), Errno> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(Errno::EACCES);
        }
        if seat_generation != active_seat_gen {
            return Err(Errno::EACCES);
        }
        self.active_master_session = Some(session_id);
        self.active_master_generation = seat_generation;
        Ok(())
    }

    pub fn drop_master(&mut self, session_id: u32) -> Result<(), Errno> {
        if self.active_master_session != Some(session_id) {
            return Err(Errno::EACCES);
        }
        self.active_master_session = None;
        Ok(())
    }

    /// Revokes DRM master when `logind` switches away from the session.
    pub fn revoke_master_for_seat_switch(&mut self, new_generation: u32) {
        self.active_master_session = None;
        self.active_master_generation = new_generation;
    }

    pub fn create_dumb(
        &mut self,
        session_id: u32,
        width: u32,
        height: u32,
        bpp: u32,
    ) -> Result<DumbBufferMeta, Errno> {
        if width == 0 || height == 0 || !matches!(bpp, 16 | 24 | 32) {
            return Err(Errno::EINVAL);
        }
        let bytes_per_pixel = bpp / 8;
        let pitch = width.checked_mul(bytes_per_pixel).ok_or(Errno::ENOMEM)?;
        let size = u64::from(pitch)
            .checked_mul(u64::from(height))
            .ok_or(Errno::ENOMEM)?;
        if size > MAX_DUMB_SIZE_BYTES {
            return Err(Errno::ENOMEM);
        }
        let slot_idx = self
            .buffers
            .iter()
            .position(|b| !b.active)
            .ok_or(Errno::ENOSPC)?;
        let handle = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1).max(1);
        let meta = DumbBufferMeta {
            handle,
            width,
            height,
            bpp,
            pitch,
            size,
            mmap_offset: 0x1000_0000u64 + (u64::from(handle) << 24),
            owner_session: session_id,
            active: true,
        };
        self.buffers[slot_idx] = meta;
        Ok(meta)
    }

    pub fn map_dumb(&self, session_id: u32, handle: u32) -> Result<u64, Errno> {
        let buf = self
            .buffers
            .iter()
            .find(|b| b.active && b.handle == handle)
            .ok_or(Errno::ENOENT)?;
        if buf.owner_session != session_id {
            return Err(Errno::EACCES);
        }
        Ok(buf.mmap_offset)
    }

    pub fn destroy_dumb(&mut self, session_id: u32, handle: u32) -> Result<(), Errno> {
        let buf = self
            .buffers
            .iter_mut()
            .find(|b| b.active && b.handle == handle)
            .ok_or(Errno::ENOENT)?;
        if buf.owner_session != session_id {
            return Err(Errno::EACCES);
        }
        buf.active = false;
        if self.active_fb_handle == Some(handle) {
            self.active_fb_handle = None;
        }
        Ok(())
    }

    pub fn set_crtc(
        &mut self,
        session_id: u32,
        seat_generation: u32,
        fb_handle: u32,
        mode: DisplayMode,
    ) -> Result<(), Errno> {
        if self.active_master_session != Some(session_id)
            || self.active_master_generation != seat_generation
        {
            return Err(Errno::EACCES);
        }
        let fb = self
            .buffers
            .iter()
            .find(|b| b.active && b.handle == fb_handle)
            .ok_or(Errno::ENOENT)?;
        if fb.owner_session != session_id || mode.width > fb.width || mode.height > fb.height {
            return Err(Errno::EINVAL);
        }
        self.active_fb_handle = Some(fb_handle);
        self.mode = mode;
        Ok(())
    }
}
