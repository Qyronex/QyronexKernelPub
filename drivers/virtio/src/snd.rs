// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![forbid(unsafe_code)]

//! Minimal bounded VirtIO-snd control/PCM protocol codecs for the Step-43 audio path.
//! This module does not claim a live device backend; MMIO queues and DMA lifecycle are separate.

use crate::VirtioError;

pub const SND_R_PCM_INFO: u32 = 0x0100;
pub const SND_R_PCM_SET_PARAMS: u32 = 0x0101;
pub const SND_R_PCM_PREPARE: u32 = 0x0102;
pub const SND_R_PCM_RELEASE: u32 = 0x0103;
pub const SND_R_PCM_START: u32 = 0x0104;
pub const SND_R_PCM_STOP: u32 = 0x0105;
pub const SND_PCM_FMT_S16: u8 = 3;
pub const SND_PCM_FMT_S32: u8 = 15;
pub const SND_PCM_RATE_44100: u8 = 6;
pub const SND_PCM_RATE_48000: u8 = 7;
pub const SND_PCM_RATE_96000: u8 = 10;
pub const SND_PCM_MAX_CHANNELS: u8 = 8;
pub const SND_PCM_MAX_BUFFER_BYTES: u32 = 1 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SndPcmParams { pub buffer_bytes: u32, pub period_bytes: u32,
    pub channels: u8, pub format: u8, pub rate: u8 }

impl SndPcmParams {
    pub fn validate(self) -> Result<Self, VirtioError> {
        if self.buffer_bytes == 0 || self.buffer_bytes > SND_PCM_MAX_BUFFER_BYTES
            || self.period_bytes == 0 || self.period_bytes > self.buffer_bytes
            || !self.buffer_bytes.is_multiple_of(self.period_bytes)
            || !(1..=SND_PCM_MAX_CHANNELS).contains(&self.channels)
            || !matches!(self.format, SND_PCM_FMT_S16 | SND_PCM_FMT_S32)
            || !matches!(self.rate, SND_PCM_RATE_44100 | SND_PCM_RATE_48000 | SND_PCM_RATE_96000) {
            return Err(VirtioError::OutOfRange);
        }
        Ok(self)
    }
    pub fn encode_request(self, stream_id: u32, out: &mut [u8]) -> Result<usize, VirtioError> {
        self.validate()?;
        if out.len() < 24 { return Err(VirtioError::BufferTooSmall); }
        out[..24].fill(0); put_u32(out, 0, SND_R_PCM_SET_PARAMS);
        put_u32(out, 4, stream_id); put_u32(out, 8, self.buffer_bytes);
        put_u32(out, 12, self.period_bytes); out[20] = self.channels;
        out[21] = self.format; out[22] = self.rate; Ok(24)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SndPcmCommand { pub code: u32, pub stream_id: u32 }

impl SndPcmCommand {
    pub fn encode(self, out: &mut [u8]) -> Result<usize, VirtioError> {
        if !matches!(self.code, SND_R_PCM_INFO | SND_R_PCM_PREPARE | SND_R_PCM_RELEASE
            | SND_R_PCM_START | SND_R_PCM_STOP) { return Err(VirtioError::UnsupportedOp); }
        if out.len() < 8 { return Err(VirtioError::BufferTooSmall); }
        out[..8].fill(0); put_u32(out, 0, self.code); put_u32(out, 4, self.stream_id); Ok(8)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SndPcmStatus { pub status: i32, pub latency_bytes: u32 }

impl SndPcmStatus {
    pub fn decode(bytes: &[u8]) -> Result<Self, VirtioError> {
        if bytes.len() < 8 { return Err(VirtioError::BufferTooSmall); }
        Ok(Self { status: i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            latency_bytes: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SndPcmXfer { pub stream_id: u32 }

impl SndPcmXfer {
    pub fn encode(self, out: &mut [u8]) -> Result<usize, VirtioError> {
        if out.len() < 4 { return Err(VirtioError::BufferTooSmall); }
        put_u32(out, 0, self.stream_id); Ok(4)
    }
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encodes_supported_pcm_parameters_and_commands() {
        let params = SndPcmParams { buffer_bytes: 16_384, period_bytes: 4_096,
            channels: 2, format: SND_PCM_FMT_S16, rate: SND_PCM_RATE_48000 };
        let mut out = [0u8; 32];
        assert_eq!(params.encode_request(3, &mut out), Ok(24));
        assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), SND_R_PCM_SET_PARAMS);
        assert_eq!(out[20], 2);
        assert_eq!(SndPcmCommand { code: SND_R_PCM_START, stream_id: 3 }.encode(&mut out), Ok(8));
    }
    #[test]
    fn rejects_invalid_periods_formats_and_commands() {
        let invalid = SndPcmParams { buffer_bytes: 4096, period_bytes: 3000,
            channels: 2, format: SND_PCM_FMT_S16, rate: SND_PCM_RATE_48000 };
        assert_eq!(invalid.validate(), Err(VirtioError::OutOfRange));
        let mut out = [0u8; 32];
        assert_eq!(SndPcmCommand { code: 0xffff, stream_id: 0 }.encode(&mut out),
            Err(VirtioError::UnsupportedOp));
    }
    #[test]
    fn decodes_pcm_status() {
        let bytes = [0, 0, 0, 0, 0x00, 0x10, 0, 0];
        assert_eq!(SndPcmStatus::decode(&bytes),
            Ok(SndPcmStatus { status: 0, latency_bytes: 4096 }));
    }
}
