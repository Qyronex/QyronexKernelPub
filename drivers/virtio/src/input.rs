// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![forbid(unsafe_code)]

//! VirtIO 1.2 Input (`virtio-input`, device ID 18) ABI types and capability metadata.

use crate::VirtioError;

/// VirtIO-Input configuration selectors (§5.8.4).
pub const VIRTIO_INPUT_CFG_UNSET: u8 = 0x00;
pub const VIRTIO_INPUT_CFG_ID_NAME: u8 = 0x01;
pub const VIRTIO_INPUT_CFG_ID_SERIAL: u8 = 0x02;
pub const VIRTIO_INPUT_CFG_ID_DEVIDS: u8 = 0x03;
pub const VIRTIO_INPUT_CFG_PROP_BITS: u8 = 0x10;
pub const VIRTIO_INPUT_CFG_EV_BITS: u8 = 0x11;
pub const VIRTIO_INPUT_CFG_ABS_INFO: u8 = 0x12;

/// Linux input event type constants carried inside `VirtioInputEvent`.
pub const VIRTIO_INPUT_EV_SYN: u16 = 0x00;
pub const VIRTIO_INPUT_EV_KEY: u16 = 0x01;
pub const VIRTIO_INPUT_EV_REL: u16 = 0x02;
pub const VIRTIO_INPUT_EV_ABS: u16 = 0x03;
pub const VIRTIO_INPUT_EV_REP: u16 = 0x14;

/// Common key/button codes for device kind detection.
pub const KEY_ENTER: u16 = 28;
pub const BTN_LEFT: u16 = 0x110;
pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;

/// Maximum config payload size inside `struct virtio_input_config`.
pub const VIRTIO_INPUT_MAX_CFG_DATA: usize = 128;

/// Wire-format event placed into `eventq` (`struct virtio_input_event`, 8 bytes LE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioInputEvent {
    pub event_type: u16,
    pub code: u16,
    pub value: u32,
}

/// Device identification descriptor (`struct virtio_input_devids`, 8 bytes LE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioInputDevids {
    pub bustype: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}

/// Absolute axis range metadata (`struct virtio_input_absinfo`, 20 bytes LE).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioInputAbsInfo {
    pub min: u32,
    pub max: u32,
    pub fuzz: u32,
    pub flat: u32,
    pub res: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtioInputKind {
    Keyboard,
    Mouse,
    Tablet,
    Generic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtioInputCaps {
    pub name: [u8; 64],
    pub name_len: usize,
    pub devids: VirtioInputDevids,
    pub prop_bits: [u8; 8],
    pub ev_bits: u32,
    pub key_bits: [u8; 96],
    pub rel_bits: [u8; 4],
    pub abs_bits: [u8; 8],
    pub abs_x: VirtioInputAbsInfo,
    pub abs_y: VirtioInputAbsInfo,
}

impl Default for VirtioInputCaps {
    fn default() -> Self {
        Self::empty()
    }
}

impl VirtioInputCaps {
    pub const fn empty() -> Self {
        Self {
            name: [0; 64],
            name_len: 0,
            devids: VirtioInputDevids {
                bustype: 0x06, // BUS_VIRTUAL
                vendor: 0x0001,
                product: 0x0001,
                version: 0x0100,
            },
            prop_bits: [0; 8],
            ev_bits: 0,
            key_bits: [0; 96],
            rel_bits: [0; 4],
            abs_bits: [0; 8],
            abs_x: VirtioInputAbsInfo {
                min: 0,
                max: 0x7fff,
                fuzz: 0,
                flat: 0,
                res: 0,
            },
            abs_y: VirtioInputAbsInfo {
                min: 0,
                max: 0x7fff,
                fuzz: 0,
                flat: 0,
                res: 0,
            },
        }
    }

    pub fn has_bit(mask: &[u8], bit: usize) -> bool {
        let byte_idx = bit / 8;
        let bit_idx = bit % 8;
        byte_idx < mask.len() && (mask[byte_idx] & (1u8 << bit_idx)) != 0
    }

    pub fn classify(&self) -> VirtioInputKind {
        let has_abs = (self.ev_bits & (1 << VIRTIO_INPUT_EV_ABS)) != 0
            || Self::has_bit(&self.abs_bits, ABS_X as usize)
            || Self::has_bit(&self.abs_bits, ABS_Y as usize);
        let has_rel = (self.ev_bits & (1 << VIRTIO_INPUT_EV_REL)) != 0
            || self.rel_bits.iter().any(|&b| b != 0);
        let has_btn_left = Self::has_bit(&self.key_bits, BTN_LEFT as usize);
        let has_key_enter = Self::has_bit(&self.key_bits, KEY_ENTER as usize);

        if has_abs && (has_btn_left || Self::has_bit(&self.abs_bits, ABS_X as usize)) {
            VirtioInputKind::Tablet
        } else if has_rel || has_btn_left {
            VirtioInputKind::Mouse
        } else if has_key_enter || (self.ev_bits & (1 << VIRTIO_INPUT_EV_KEY)) != 0 {
            VirtioInputKind::Keyboard
        } else {
            VirtioInputKind::Generic
        }
    }
}

pub fn decode_devids(bytes: &[u8]) -> Result<VirtioInputDevids, VirtioError> {
    if bytes.len() < core::mem::size_of::<VirtioInputDevids>() {
        return Err(VirtioError::InvalidPacket);
    }
    Ok(VirtioInputDevids {
        bustype: u16::from_le_bytes([bytes[0], bytes[1]]),
        vendor: u16::from_le_bytes([bytes[2], bytes[3]]),
        product: u16::from_le_bytes([bytes[4], bytes[5]]),
        version: u16::from_le_bytes([bytes[6], bytes[7]]),
    })
}

pub fn decode_abs_info(bytes: &[u8]) -> Result<VirtioInputAbsInfo, VirtioError> {
    if bytes.len() < core::mem::size_of::<VirtioInputAbsInfo>() {
        return Err(VirtioError::InvalidPacket);
    }
    Ok(VirtioInputAbsInfo {
        min: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        max: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        fuzz: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        flat: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        res: u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn input_abi_sizes_and_classification_match_virtio_1_2() {
        assert_eq!(size_of::<VirtioInputEvent>(), 8);
        assert_eq!(size_of::<VirtioInputDevids>(), 8);
        assert_eq!(size_of::<VirtioInputAbsInfo>(), 20);

        let mut kb = VirtioInputCaps::empty();
        kb.ev_bits = (1 << VIRTIO_INPUT_EV_SYN) | (1 << VIRTIO_INPUT_EV_KEY);
        kb.key_bits[(KEY_ENTER as usize) / 8] |= 1 << ((KEY_ENTER as usize) % 8);
        assert_eq!(kb.classify(), VirtioInputKind::Keyboard);

        let mut tablet = VirtioInputCaps::empty();
        tablet.ev_bits =
            (1 << VIRTIO_INPUT_EV_SYN) | (1 << VIRTIO_INPUT_EV_KEY) | (1 << VIRTIO_INPUT_EV_ABS);
        tablet.key_bits[(BTN_LEFT as usize) / 8] |= 1 << ((BTN_LEFT as usize) % 8);
        tablet.abs_bits[0] = 0b11;
        assert_eq!(tablet.classify(), VirtioInputKind::Tablet);

        let mut mouse = VirtioInputCaps::empty();
        mouse.ev_bits =
            (1 << VIRTIO_INPUT_EV_SYN) | (1 << VIRTIO_INPUT_EV_KEY) | (1 << VIRTIO_INPUT_EV_REL);
        mouse.rel_bits[0] = 0b11;
        assert_eq!(mouse.classify(), VirtioInputKind::Mouse);
    }
}
