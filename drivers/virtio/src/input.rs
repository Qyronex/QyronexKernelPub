// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![forbid(unsafe_code)]

//! VirtIO input configuration and event codecs. Events are normalized to Linux evdev values;
//! queue ownership, DMA grants, and seat-focus authorization stay with the device/runtime layer.

use crate::VirtioError;

pub const INPUT_CFG_UNSET: u8 = 0x00;
pub const INPUT_CFG_ID_NAME: u8 = 0x01;
pub const INPUT_CFG_ID_SERIAL: u8 = 0x02;
pub const INPUT_CFG_ID_DEVIDS: u8 = 0x03;
pub const INPUT_CFG_PROP_BITS: u8 = 0x10;
pub const INPUT_CFG_EV_BITS: u8 = 0x11;
pub const INPUT_CFG_ABS_INFO: u8 = 0x12;
pub const INPUT_CFG_DATA_BYTES: usize = 128;
pub const INPUT_EVENT_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputConfig { pub select: u8, pub subselect: u8, pub size: u8,
    pub data: [u8; INPUT_CFG_DATA_BYTES] }

impl InputConfig {
    /// Decodes the 136-byte VirtIO input configuration space.
    pub fn decode(bytes: &[u8]) -> Result<Self, VirtioError> {
        if bytes.len() < 136 || usize::from(bytes[2]) > INPUT_CFG_DATA_BYTES {
            return Err(VirtioError::BufferTooSmall);
        }
        let mut data = [0u8; INPUT_CFG_DATA_BYTES]; data.copy_from_slice(&bytes[8..136]);
        Ok(Self { select: bytes[0], subselect: bytes[1], size: bytes[2], data })
    }
    pub fn name(&self) -> Result<&[u8], VirtioError> {
        if self.select != INPUT_CFG_ID_NAME { return Err(VirtioError::DeviceFault); }
        Ok(&self.data[..usize::from(self.size)])
    }
    pub fn supports_event(&self, event_type: u16, code: u16) -> bool {
        if self.select != INPUT_CFG_EV_BITS || self.subselect != event_type as u8 { return false; }
        let byte = usize::from(code / 8);
        byte < usize::from(self.size) && (self.data[byte] & (1u8 << (code % 8))) != 0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioInputEvent { pub event_type: u16, pub code: u16, pub value: u32 }

impl VirtioInputEvent {
    pub fn decode(bytes: &[u8]) -> Result<Self, VirtioError> {
        if bytes.len() < INPUT_EVENT_BYTES { return Err(VirtioError::BufferTooSmall); }
        Ok(Self { event_type: u16::from_le_bytes([bytes[0], bytes[1]]),
            code: u16::from_le_bytes([bytes[2], bytes[3]]),
            value: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) })
    }
    pub fn encode(self) -> [u8; INPUT_EVENT_BYTES] {
        let mut out = [0u8; INPUT_EVENT_BYTES];
        out[0..2].copy_from_slice(&self.event_type.to_le_bytes());
        out[2..4].copy_from_slice(&self.code.to_le_bytes());
        out[4..8].copy_from_slice(&self.value.to_le_bytes()); out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn input_event_round_trips() {
        let event = VirtioInputEvent { event_type: 1, code: 30, value: 1 };
        assert_eq!(VirtioInputEvent::decode(&event.encode()).unwrap(), event);
    }
    #[test]
    fn config_bits_are_bounded_and_queryable() {
        let mut bytes = [0u8; 136]; bytes[0] = INPUT_CFG_EV_BITS; bytes[1] = 1; bytes[2] = 8;
        bytes[8 + 30 / 8] = 1 << (30 % 8);
        let cfg = InputConfig::decode(&bytes).unwrap();
        assert!(cfg.supports_event(1, 30)); assert!(!cfg.supports_event(1, 31));
        assert!(!cfg.supports_event(2, 30));
    }
    #[test]
    fn rejects_short_or_oversized_config() {
        assert_eq!(InputConfig::decode(&[0u8; 135]), Err(VirtioError::BufferTooSmall));
        let mut bytes = [0u8; 136]; bytes[2] = 129;
        assert_eq!(InputConfig::decode(&bytes), Err(VirtioError::BufferTooSmall));
    }
}
