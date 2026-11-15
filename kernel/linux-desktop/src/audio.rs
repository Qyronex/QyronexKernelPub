// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_capability::{CapRights, Capability};
use kernal_linux_abi::Errno;

pub const SNDRV_PCM_IOCTL_HW_PARAMS: u64 = 0xc260_4111;
pub const SNDRV_PCM_IOCTL_PREPARE: u64 = 0x0000_4140;
pub const SNDRV_PCM_IOCTL_START: u64 = 0x0000_4142;
pub const SNDRV_PCM_IOCTL_DROP: u64 = 0x0000_4143;

pub const MAX_PCM_BUFFER_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcmFormat {
    S16Le,
    S32Le,
}

impl PcmFormat {
    pub const fn bytes_per_sample(self) -> usize {
        match self {
            Self::S16Le => 2,
            Self::S32Le => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcmParams {
    pub rate_hz: u32,
    pub channels: u8,
    pub format: PcmFormat,
    pub period_frames: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcmState {
    Open,
    Setup,
    Prepared,
    Running,
}

/// Bounded PCM audio playback stream (`/dev/snd/pcmC0D0p`).
#[derive(Clone, Debug)]
pub struct PcmAudioDevice {
    pub state: PcmState,
    pub params: Option<PcmParams>,
    pub frames_written: u64,
    ring_used: usize,
}

impl Default for PcmAudioDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl PcmAudioDevice {
    pub const fn new() -> Self {
        Self {
            state: PcmState::Open,
            params: None,
            frames_written: 0,
            ring_used: 0,
        }
    }

    pub fn set_hw_params(&mut self, cap: Capability, params: PcmParams) -> Result<(), Errno> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(Errno::EACCES);
        }
        if !matches!(params.rate_hz, 44_100 | 48_000 | 96_000)
            || !(1..=8).contains(&params.channels)
            || params.period_frames == 0
        {
            return Err(Errno::EINVAL);
        }
        let frame_bytes = usize::from(params.channels) * params.format.bytes_per_sample();
        let period_bytes = usize::try_from(params.period_frames)
            .ok()
            .and_then(|f| f.checked_mul(frame_bytes))
            .ok_or(Errno::EINVAL)?;
        if period_bytes > MAX_PCM_BUFFER_BYTES {
            return Err(Errno::EINVAL);
        }
        self.params = Some(params);
        self.state = PcmState::Setup;
        Ok(())
    }

    pub fn prepare(&mut self) -> Result<(), Errno> {
        if self.params.is_none() {
            return Err(Errno::EBADF);
        }
        self.ring_used = 0;
        self.state = PcmState::Prepared;
        Ok(())
    }

    pub fn start(&mut self) -> Result<(), Errno> {
        if self.state != PcmState::Prepared {
            return Err(Errno::EBADF);
        }
        self.state = PcmState::Running;
        Ok(())
    }

    pub fn drop_stream(&mut self) {
        self.ring_used = 0;
        if self.params.is_some() {
            self.state = PcmState::Setup;
        }
    }

    pub fn write_frames(&mut self, cap: Capability, data: &[u8]) -> Result<usize, Errno> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(Errno::EACCES);
        }
        let params = self.params.ok_or(Errno::EBADF)?;
        if !matches!(self.state, PcmState::Prepared | PcmState::Running) {
            return Err(Errno::EBADF);
        }
        let frame_bytes = usize::from(params.channels) * params.format.bytes_per_sample();
        if data.is_empty() || !data.len().is_multiple_of(frame_bytes) {
            return Err(Errno::EINVAL);
        }
        let frames = data.len() / frame_bytes;
        self.state = PcmState::Running;
        self.ring_used = (self.ring_used + data.len()).min(MAX_PCM_BUFFER_BYTES);
        self.frames_written = self.frames_written.saturating_add(frames as u64);
        Ok(frames)
    }
}
