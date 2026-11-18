// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::mem::size_of;
use kernal_capability::{CapRights, Capability};
use kernal_linux_abi::Errno;

pub const DRM_IOCTL_VERSION: u64 = 0xc040_6400;
pub const DRM_IOCTL_GET_UNIQUE: u64 = 0xc010_6401;
pub const DRM_IOCTL_GET_MAGIC: u64 = 0x8004_6402;
pub const DRM_IOCTL_GEM_CLOSE: u64 = 0x4008_6409;
pub const DRM_IOCTL_GET_CAP: u64 = 0xc010_640c;
pub const DRM_IOCTL_SET_CLIENT_CAP: u64 = 0x4010_640d;
pub const DRM_IOCTL_SET_MASTER: u64 = 0x0000_641e;
pub const DRM_IOCTL_DROP_MASTER: u64 = 0x0000_641f;
pub const DRM_IOCTL_PRIME_HANDLE_TO_FD: u64 = 0xc00c_642d;
pub const DRM_IOCTL_WAIT_VBLANK: u64 = 0xc018_643a;
pub const DRM_IOCTL_MODE_GETRESOURCES: u64 = 0xc040_64a0;
pub const DRM_IOCTL_MODE_GETCRTC: u64 = 0xc068_64a1;
pub const DRM_IOCTL_MODE_SETCRTC: u64 = 0xc068_64a2;
pub const DRM_IOCTL_MODE_CURSOR: u64 = 0xc01c_64a3;
pub const DRM_IOCTL_MODE_GETENCODER: u64 = 0xc014_64a6;
pub const DRM_IOCTL_MODE_GETCONNECTOR: u64 = 0xc050_64a7;
pub const DRM_IOCTL_MODE_GETPROPERTY: u64 = 0xc040_64aa;
pub const DRM_IOCTL_MODE_SETPROPERTY: u64 = 0xc010_64ab;
pub const DRM_IOCTL_MODE_GETPROPBLOB: u64 = 0xc010_64ac;
pub const DRM_IOCTL_MODE_GETFB: u64 = 0xc01c_64ad;
pub const DRM_IOCTL_MODE_ADDFB: u64 = 0xc01c_64ae;
pub const DRM_IOCTL_MODE_RMFB: u64 = 0xc004_64af;
pub const DRM_IOCTL_MODE_PAGE_FLIP: u64 = 0xc018_64b0;
pub const DRM_IOCTL_MODE_DIRTYFB: u64 = 0xc018_64b1;
pub const DRM_IOCTL_MODE_CREATE_DUMB: u64 = 0xc020_64b2;
pub const DRM_IOCTL_MODE_MAP_DUMB: u64 = 0xc010_64b3;
pub const DRM_IOCTL_MODE_DESTROY_DUMB: u64 = 0xc004_64b4;
pub const DRM_IOCTL_MODE_GETPLANERESOURCES: u64 = 0xc010_64b5;
pub const DRM_IOCTL_MODE_GETPLANE: u64 = 0xc020_64b6;
pub const DRM_IOCTL_MODE_ADDFB2: u64 = 0xc068_64b8;
pub const DRM_IOCTL_MODE_OBJ_GETPROPERTIES: u64 = 0xc020_64b9;
pub const DRM_IOCTL_MODE_ATOMIC: u64 = 0xc038_64bc;
pub const DRM_IOCTL_MODE_CURSOR2: u64 = 0xc024_64bb;

pub const FBIOGET_VSCREENINFO: u64 = 0x4600;
pub const FBIOGET_FSCREENINFO: u64 = 0x4602;
pub const FBIOPAN_DISPLAY: u64 = 0x4606;

pub const DRM_CAP_DUMB_BUFFER: u64 = 0x1;
pub const DRM_CAP_VBLANK_HIGH_CRTC: u64 = 0x2;
pub const DRM_CAP_DUMB_PREFERRED_DEPTH: u64 = 0x3;
pub const DRM_CAP_DUMB_PREFER_SHADOW: u64 = 0x4;
pub const DRM_CAP_PRIME: u64 = 0x5;
pub const DRM_CAP_TIMESTAMP_MONOTONIC: u64 = 0x6;
pub const DRM_CAP_ASYNC_PAGE_FLIP: u64 = 0x7;
pub const DRM_CAP_CURSOR_WIDTH: u64 = 0x8;
pub const DRM_CAP_CURSOR_HEIGHT: u64 = 0x9;
pub const DRM_CAP_ADDFB2_MODIFIERS: u64 = 0x10;
pub const DRM_CAP_CRTC_IN_VBLANK_EVENT: u64 = 0x12;

pub const DRM_CLIENT_CAP_STEREO_3D: u64 = 1;
pub const DRM_CLIENT_CAP_UNIVERSAL_PLANES: u64 = 2;
pub const DRM_CLIENT_CAP_ATOMIC: u64 = 3;

pub const DRM_MODE_TYPE_PREFERRED: u32 = 1 << 3;
pub const DRM_MODE_TYPE_DRIVER: u32 = 1 << 6;
pub const DRM_MODE_CONNECTOR_VIRTUAL: u32 = 15;
pub const DRM_MODE_ENCODER_VIRTUAL: u32 = 7;
pub const DRM_MODE_CONNECTED: u32 = 1;
pub const DRM_MODE_PAGE_FLIP_EVENT: u32 = 0x01;

pub const DRM_EVENT_VBLANK: u32 = 0x01;
pub const DRM_EVENT_FLIP_COMPLETE: u32 = 0x02;

/// `fourcc_code('X','R','2','4')` and `'A','R','2','4'`.
pub const DRM_FORMAT_XRGB8888: u32 = 0x3432_5258;
pub const DRM_FORMAT_ARGB8888: u32 = 0x3432_5241;

pub const DRM_CONNECTOR_ID: u32 = 10;
pub const DRM_ENCODER_ID: u32 = 20;
pub const DRM_CRTC_ID: u32 = 30;
pub const DRM_PRIMARY_PLANE_ID: u32 = 40;

pub const MAX_DUMB_BUFFERS: usize = 16;
pub const MAX_DRM_FBS: usize = 16;
pub const MAX_DRM_EVENTS: usize = 16;
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
            height: 800,
            bpp: 32,
            refresh_hz: 60,
        }
    }
}

/// Linux `struct drm_mode_modeinfo` (68 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrmModeInfo {
    pub clock: u32,
    pub hdisplay: u16,
    pub hsync_start: u16,
    pub hsync_end: u16,
    pub htotal: u16,
    pub hskew: u16,
    pub vdisplay: u16,
    pub vsync_start: u16,
    pub vsync_end: u16,
    pub vtotal: u16,
    pub vscan: u16,
    pub vrefresh: u32,
    pub flags: u32,
    pub mode_type: u32,
    pub name: [u8; 32],
}

impl DrmModeInfo {
    pub fn from_display_mode(mode: DisplayMode) -> Self {
        let w = u16::try_from(mode.width).unwrap_or(1280);
        let h = u16::try_from(mode.height).unwrap_or(800);
        let hsync_start = w.saturating_add(48);
        let hsync_end = hsync_start.saturating_add(32);
        let htotal = hsync_end.saturating_add(80);
        let vsync_start = h.saturating_add(3);
        let vsync_end = vsync_start.saturating_add(6);
        let vtotal = vsync_end.saturating_add(20);
        let vrefresh = mode.refresh_hz.max(60);
        let clock = u32::from(htotal)
            .saturating_mul(u32::from(vtotal))
            .saturating_mul(vrefresh)
            / 1000;
        let mut name = [0u8; 32];
        let mut pos = write_dec(mode.width, &mut name);
        if pos < name.len() {
            name[pos] = b'x';
            pos += 1;
        }
        let _ = write_dec(mode.height, &mut name[pos..]);
        Self {
            clock,
            hdisplay: w,
            hsync_start,
            hsync_end,
            htotal,
            hskew: 0,
            vdisplay: h,
            vsync_start,
            vsync_end,
            vtotal,
            vscan: 0,
            vrefresh,
            flags: 0x05, // PHSYNC | PVSYNC
            mode_type: DRM_MODE_TYPE_PREFERRED | DRM_MODE_TYPE_DRIVER,
            name,
        }
    }

    pub fn to_bytes(self) -> [u8; 68] {
        let mut out = [0u8; 68];
        out[0..4].copy_from_slice(&self.clock.to_le_bytes());
        out[4..6].copy_from_slice(&self.hdisplay.to_le_bytes());
        out[6..8].copy_from_slice(&self.hsync_start.to_le_bytes());
        out[8..10].copy_from_slice(&self.hsync_end.to_le_bytes());
        out[10..12].copy_from_slice(&self.htotal.to_le_bytes());
        out[12..14].copy_from_slice(&self.hskew.to_le_bytes());
        out[14..16].copy_from_slice(&self.vdisplay.to_le_bytes());
        out[16..18].copy_from_slice(&self.vsync_start.to_le_bytes());
        out[18..20].copy_from_slice(&self.vsync_end.to_le_bytes());
        out[20..22].copy_from_slice(&self.vtotal.to_le_bytes());
        out[22..24].copy_from_slice(&self.vscan.to_le_bytes());
        out[24..28].copy_from_slice(&self.vrefresh.to_le_bytes());
        out[28..32].copy_from_slice(&self.flags.to_le_bytes());
        out[32..36].copy_from_slice(&self.mode_type.to_le_bytes());
        out[36..68].copy_from_slice(&self.name);
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, Errno> {
        if raw.len() < size_of::<Self>() {
            return Err(Errno::EINVAL);
        }
        let mut name = [0u8; 32];
        name.copy_from_slice(&raw[36..68]);
        Ok(Self {
            clock: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
            hdisplay: u16::from_le_bytes([raw[4], raw[5]]),
            hsync_start: u16::from_le_bytes([raw[6], raw[7]]),
            hsync_end: u16::from_le_bytes([raw[8], raw[9]]),
            htotal: u16::from_le_bytes([raw[10], raw[11]]),
            hskew: u16::from_le_bytes([raw[12], raw[13]]),
            vdisplay: u16::from_le_bytes([raw[14], raw[15]]),
            vsync_start: u16::from_le_bytes([raw[16], raw[17]]),
            vsync_end: u16::from_le_bytes([raw[18], raw[19]]),
            vtotal: u16::from_le_bytes([raw[20], raw[21]]),
            vscan: u16::from_le_bytes([raw[22], raw[23]]),
            vrefresh: u32::from_le_bytes([raw[24], raw[25], raw[26], raw[27]]),
            flags: u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]),
            mode_type: u32::from_le_bytes([raw[32], raw[33], raw[34], raw[35]]),
            name,
        })
    }
}

/// Linux `struct drm_event_vblank` (32 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DrmEventVblank {
    pub event_type: u32,
    pub length: u32,
    pub user_data: u64,
    pub tv_sec: u32,
    pub tv_usec: u32,
    pub sequence: u32,
    pub crtc_id: u32,
}

impl DrmEventVblank {
    pub fn encode(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..4].copy_from_slice(&self.event_type.to_le_bytes());
        out[4..8].copy_from_slice(&self.length.to_le_bytes());
        out[8..16].copy_from_slice(&self.user_data.to_le_bytes());
        out[16..20].copy_from_slice(&self.tv_sec.to_le_bytes());
        out[20..24].copy_from_slice(&self.tv_usec.to_le_bytes());
        out[24..28].copy_from_slice(&self.sequence.to_le_bytes());
        out[28..32].copy_from_slice(&self.crtc_id.to_le_bytes());
        out
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddFbRequest {
    pub session_id: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u32,
    pub depth: u32,
    pub pixel_format: u32,
    pub handle: u32,
    pub offset: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetCrtcRequest {
    pub session_id: u32,
    pub seat_generation: u32,
    pub crtc_id: u32,
    pub fb_id: u32,
    pub x: u32,
    pub y: u32,
    pub mode_override: Option<DisplayMode>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageFlipRequest {
    pub session_id: u32,
    pub seat_generation: u32,
    pub crtc_id: u32,
    pub fb_id: u32,
    pub flags: u32,
    pub user_data: u64,
    pub tv_sec: u32,
    pub tv_usec: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrmFramebufferMeta {
    pub fb_id: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u32,
    pub depth: u32,
    pub pixel_format: u32,
    pub handle: u32,
    pub offset: u32,
    pub active: bool,
}

impl DrmFramebufferMeta {
    const EMPTY: Self = Self {
        fb_id: 0,
        width: 0,
        height: 0,
        pitch: 0,
        bpp: 0,
        depth: 0,
        pixel_format: 0,
        handle: 0,
        offset: 0,
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
    pub active_fb_id: Option<u32>,
    pub active_fb_handle: Option<u32>,
    pub active_crtc_id: u32,
    pub crtc_x: u32,
    pub crtc_y: u32,
    pub mode_valid: bool,
    pub vblank_sequence: u32,
    next_handle: u32,
    next_fb_id: u32,
    buffers: [DumbBufferMeta; MAX_DUMB_BUFFERS],
    fbs: [DrmFramebufferMeta; MAX_DRM_FBS],
    events: [DrmEventVblank; MAX_DRM_EVENTS],
    ev_head: usize,
    ev_tail: usize,
    ev_count: usize,
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
                height: 800,
                bpp: 32,
                refresh_hz: 60,
            },
            active_master_session: None,
            active_master_generation: 1,
            active_fb_id: None,
            active_fb_handle: None,
            active_crtc_id: DRM_CRTC_ID,
            crtc_x: 0,
            crtc_y: 0,
            mode_valid: true,
            vblank_sequence: 1,
            next_handle: 1,
            next_fb_id: 100,
            buffers: [DumbBufferMeta::EMPTY; MAX_DUMB_BUFFERS],
            fbs: [DrmFramebufferMeta::EMPTY; MAX_DRM_FBS],
            events: [DrmEventVblank {
                event_type: 0,
                length: 0,
                user_data: 0,
                tv_sec: 0,
                tv_usec: 0,
                sequence: 0,
                crtc_id: 0,
            }; MAX_DRM_EVENTS],
            ev_head: 0,
            ev_tail: 0,
            ev_count: 0,
        }
    }

    pub fn set_preferred_dimensions(&mut self, width: u32, height: u32) {
        if width > 0 && height > 0 {
            self.mode.width = width;
            self.mode.height = height;
        }
    }

    pub fn has_pending_event(&self) -> bool {
        self.ev_count > 0
    }

    pub fn pop_event(&mut self) -> Option<DrmEventVblank> {
        if self.ev_count == 0 {
            return None;
        }
        let ev = self.events[self.ev_head];
        self.ev_head = (self.ev_head + 1) % MAX_DRM_EVENTS;
        self.ev_count -= 1;
        Some(ev)
    }

    fn push_event(&mut self, ev: DrmEventVblank) {
        if self.ev_count == MAX_DRM_EVENTS {
            self.ev_head = (self.ev_head + 1) % MAX_DRM_EVENTS;
            self.ev_count -= 1;
        }
        self.events[self.ev_tail] = ev;
        self.ev_tail = (self.ev_tail + 1) % MAX_DRM_EVENTS;
        self.ev_count += 1;
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

    pub fn lookup_dumb(&self, handle: u32) -> Option<DumbBufferMeta> {
        self.buffers
            .iter()
            .copied()
            .find(|b| b.active && b.handle == handle)
    }

    pub fn lookup_dumb_by_mmap_offset(&self, offset: u64) -> Option<DumbBufferMeta> {
        self.buffers
            .iter()
            .copied()
            .find(|b| b.active && b.mmap_offset == offset)
    }

    pub fn map_dumb(&self, session_id: u32, handle: u32) -> Result<u64, Errno> {
        let buf = self.lookup_dumb(handle).ok_or(Errno::ENOENT)?;
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
            self.active_fb_id = None;
        }
        Ok(())
    }

    pub fn add_fb(&mut self, req: AddFbRequest) -> Result<DrmFramebufferMeta, Errno> {
        let dumb = self.lookup_dumb(req.handle).ok_or(Errno::ENOENT)?;
        if dumb.owner_session != req.session_id {
            return Err(Errno::EACCES);
        }
        if req.width == 0 || req.height == 0 || req.pitch < req.width.saturating_mul(req.bpp / 8) {
            return Err(Errno::EINVAL);
        }
        let needed = u64::from(req.offset)
            .saturating_add(u64::from(req.pitch).saturating_mul(u64::from(req.height)));
        if needed > dumb.size {
            return Err(Errno::EINVAL);
        }
        let slot = self
            .fbs
            .iter_mut()
            .find(|f| !f.active)
            .ok_or(Errno::ENOSPC)?;
        let fb_id = self.next_fb_id;
        self.next_fb_id = self.next_fb_id.wrapping_add(1).max(100);
        let fb = DrmFramebufferMeta {
            fb_id,
            width: req.width,
            height: req.height,
            pitch: req.pitch,
            bpp: req.bpp,
            depth: req.depth,
            pixel_format: req.pixel_format,
            handle: req.handle,
            offset: req.offset,
            active: true,
        };
        *slot = fb;
        Ok(fb)
    }

    pub fn lookup_fb(&self, fb_id: u32) -> Option<DrmFramebufferMeta> {
        self.fbs
            .iter()
            .copied()
            .find(|f| f.active && f.fb_id == fb_id)
    }

    pub fn active_fb_ids(&self, out: &mut [u32]) -> usize {
        let mut count = 0usize;
        for fb in &self.fbs {
            if fb.active {
                if count < out.len() {
                    out[count] = fb.fb_id;
                }
                count += 1;
            }
        }
        count
    }

    pub fn remove_fb(&mut self, fb_id: u32) -> Result<(), Errno> {
        let fb = self
            .fbs
            .iter_mut()
            .find(|f| f.active && f.fb_id == fb_id)
            .ok_or(Errno::ENOENT)?;
        fb.active = false;
        if self.active_fb_id == Some(fb_id) {
            self.active_fb_id = None;
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
        self.mode_valid = true;
        Ok(())
    }

    /// KMS `SETCRTC` targeting a registered framebuffer ID (or `0` to disable scanout).
    pub fn set_crtc_by_fb_id(
        &mut self,
        req: SetCrtcRequest,
    ) -> Result<Option<DrmFramebufferMeta>, Errno> {
        if req.crtc_id != DRM_CRTC_ID {
            return Err(Errno::ENOENT);
        }
        if self.active_master_session != Some(req.session_id)
            || self.active_master_generation != req.seat_generation
        {
            return Err(Errno::EACCES);
        }
        if req.fb_id == 0 {
            self.active_fb_id = None;
            self.active_fb_handle = None;
            self.crtc_x = req.x;
            self.crtc_y = req.y;
            return Ok(None);
        }
        let fb = self.lookup_fb(req.fb_id).ok_or(Errno::ENOENT)?;
        let mode = req.mode_override.unwrap_or(self.mode);
        self.set_crtc(req.session_id, req.seat_generation, fb.handle, mode)?;
        self.active_fb_id = Some(req.fb_id);
        self.crtc_x = req.x;
        self.crtc_y = req.y;
        Ok(Some(fb))
    }

    pub fn page_flip(&mut self, req: PageFlipRequest) -> Result<DrmFramebufferMeta, Errno> {
        if req.crtc_id != DRM_CRTC_ID {
            return Err(Errno::ENOENT);
        }
        let fb = self
            .set_crtc_by_fb_id(SetCrtcRequest {
                session_id: req.session_id,
                seat_generation: req.seat_generation,
                crtc_id: req.crtc_id,
                fb_id: req.fb_id,
                x: 0,
                y: 0,
                mode_override: None,
            })?
            .ok_or(Errno::EINVAL)?;
        self.vblank_sequence = self.vblank_sequence.wrapping_add(1).max(1);
        if (req.flags & DRM_MODE_PAGE_FLIP_EVENT) != 0 {
            self.push_event(DrmEventVblank {
                event_type: DRM_EVENT_FLIP_COMPLETE,
                length: 32,
                user_data: req.user_data,
                tv_sec: req.tv_sec,
                tv_usec: req.tv_usec,
                sequence: self.vblank_sequence,
                crtc_id: DRM_CRTC_ID,
            });
        }
        Ok(fb)
    }

    pub fn queue_vblank_event(&mut self, user_data: u64, tv_sec: u32, tv_usec: u32) -> u32 {
        self.vblank_sequence = self.vblank_sequence.wrapping_add(1).max(1);
        self.push_event(DrmEventVblank {
            event_type: DRM_EVENT_VBLANK,
            length: 32,
            user_data,
            tv_sec,
            tv_usec,
            sequence: self.vblank_sequence,
            crtc_id: DRM_CRTC_ID,
        });
        self.vblank_sequence
    }
}

fn write_dec(mut val: u32, out: &mut [u8]) -> usize {
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    loop {
        tmp[len] = b'0' + (val % 10) as u8;
        len += 1;
        val /= 10;
        if val == 0 {
            break;
        }
    }
    let take = len.min(out.len());
    for (i, dst) in out[..take].iter_mut().enumerate() {
        *dst = tmp[len - 1 - i];
    }
    take
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_capability::ObjectId;

    #[test]
    fn drm_abi_structs_match_linux_aarch64_sizes() {
        assert_eq!(size_of::<DrmModeInfo>(), 68);
        assert_eq!(size_of::<DrmEventVblank>(), 32);
        let mode = DrmModeInfo::from_display_mode(DisplayMode {
            width: 1280,
            height: 800,
            bpp: 32,
            refresh_hz: 60,
        });
        let raw = mode.to_bytes();
        let parsed = DrmModeInfo::from_bytes(&raw).unwrap();
        assert_eq!(parsed.hdisplay, 1280);
        assert_eq!(parsed.vdisplay, 800);
        assert_eq!(&parsed.name[..9], b"1280x800\0");
    }

    #[test]
    fn drm_kms_fb_setcrtc_and_page_flip_emit_vblank_events() {
        let cap = Capability {
            object: ObjectId(43),
            rights: CapRights::CONTROL,
        };
        let mut drm = DrmDevice::new();
        drm.set_master(cap, 1, 1, 1).unwrap();
        let dumb = drm.create_dumb(1, 1280, 800, 32).unwrap();
        assert_eq!(
            drm.lookup_dumb_by_mmap_offset(dumb.mmap_offset)
                .unwrap()
                .handle,
            dumb.handle
        );
        let fb = drm
            .add_fb(AddFbRequest {
                session_id: 1,
                width: 1280,
                height: 800,
                pitch: dumb.pitch,
                bpp: 32,
                depth: 24,
                pixel_format: DRM_FORMAT_XRGB8888,
                handle: dumb.handle,
                offset: 0,
            })
            .unwrap();
        let mut ids = [0u32; 4];
        assert_eq!(drm.active_fb_ids(&mut ids), 1);
        assert_eq!(ids[0], fb.fb_id);

        drm.set_crtc_by_fb_id(SetCrtcRequest {
            session_id: 1,
            seat_generation: 1,
            crtc_id: DRM_CRTC_ID,
            fb_id: fb.fb_id,
            x: 0,
            y: 0,
            mode_override: None,
        })
        .unwrap();
        assert_eq!(drm.active_fb_id, Some(fb.fb_id));

        assert!(!drm.has_pending_event());
        drm.page_flip(PageFlipRequest {
            session_id: 1,
            seat_generation: 1,
            crtc_id: DRM_CRTC_ID,
            fb_id: fb.fb_id,
            flags: DRM_MODE_PAGE_FLIP_EVENT,
            user_data: 0xdead_beef,
            tv_sec: 12,
            tv_usec: 345,
        })
        .unwrap();
        assert!(drm.has_pending_event());
        let ev = drm.pop_event().unwrap();
        assert_eq!(ev.event_type, DRM_EVENT_FLIP_COMPLETE);
        assert_eq!(ev.user_data, 0xdead_beef);
        assert_eq!(ev.crtc_id, DRM_CRTC_ID);
        assert!(!drm.has_pending_event());

        drm.remove_fb(fb.fb_id).unwrap();
        assert_eq!(drm.active_fb_ids(&mut ids), 0);
    }
}
