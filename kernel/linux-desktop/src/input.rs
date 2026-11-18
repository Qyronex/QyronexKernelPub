// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_abi::Errno;

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;
pub const EV_REP: u16 = 0x14;

pub const EVIOCGVERSION: u64 = 0x8004_4501;
pub const EVIOCGID: u64 = 0x8008_4502;
pub const EVIOCGNAME: u64 = 0x8040_4506;
pub const EVIOCGBIT_KEY: u64 = 0x8008_4521;
pub const EVIOCGRAB: u64 = 0x4004_4590;
pub const EVIOCSCLOCKID: u64 = 0x4004_45a0;

/// Linux `struct input_event` (24 bytes on 64-bit AArch64).
pub const INPUT_EVENT_BYTES: usize = 24;
pub const MAX_INPUT_RING: usize = 128;
pub const MAX_INPUT_DEVICES: usize = 4;

/// Decoded variable-length `EV_*` evdev ioctl command (`_IOC_TYPE == 'E'`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvdevIoctl {
    GetVersion,
    GetId,
    GetRep,
    GetName(usize),
    GetPhys(usize),
    GetUniq(usize),
    GetProp(usize),
    GetMtSlots(usize),
    GetStateBits { nr: u8, len: usize },
    GetBit { ev_type: u16, len: usize },
    GetAbs { axis: u16 },
    GetEffects,
    Grab,
    RevokeOrMask,
    SetClockId,
}

impl EvdevIoctl {
    pub const fn decode(raw: u64) -> Option<Self> {
        let ioc_type = ((raw >> 8) & 0xff) as u8;
        if ioc_type != b'E' {
            return None;
        }
        let nr = (raw & 0xff) as u8;
        let len = ((raw >> 16) & 0x3fff) as usize;
        match nr {
            0x01 => Some(Self::GetVersion),
            0x02 => Some(Self::GetId),
            0x03 => Some(Self::GetRep),
            0x06 => Some(Self::GetName(len)),
            0x07 => Some(Self::GetPhys(len)),
            0x08 => Some(Self::GetUniq(len)),
            0x09 => Some(Self::GetProp(len)),
            0x0a => Some(Self::GetMtSlots(len)),
            0x18..=0x1f => Some(Self::GetStateBits { nr, len }),
            0x20..=0x3f => Some(Self::GetBit {
                ev_type: (nr - 0x20) as u16,
                len,
            }),
            0x40..=0x7f => Some(Self::GetAbs {
                axis: (nr - 0x40) as u16,
            }),
            0x84 => Some(Self::GetEffects),
            0x90 => Some(Self::Grab),
            0x91..=0x93 => Some(Self::RevokeOrMask),
            0xa0 => Some(Self::SetClockId),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InputAbsAxisInfo {
    pub value: i32,
    pub minimum: i32,
    pub maximum: i32,
    pub fuzz: i32,
    pub flat: i32,
    pub resolution: i32,
}

impl InputAbsAxisInfo {
    pub fn encode(self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[0..4].copy_from_slice(&self.value.to_le_bytes());
        out[4..8].copy_from_slice(&self.minimum.to_le_bytes());
        out[8..12].copy_from_slice(&self.maximum.to_le_bytes());
        out[12..16].copy_from_slice(&self.fuzz.to_le_bytes());
        out[16..20].copy_from_slice(&self.flat.to_le_bytes());
        out[20..24].copy_from_slice(&self.resolution.to_le_bytes());
        out
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputDeviceProfile {
    Keyboard,
    Mouse,
    Tablet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputDeviceMeta {
    pub present: bool,
    pub profile: InputDeviceProfile,
    pub bustype: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
    pub name: [u8; 64],
    pub name_len: usize,
    pub prop_bits: [u8; 8],
    pub ev_bits: u32,
    pub key_bits: [u8; 96],
    pub rel_bits: [u8; 4],
    pub abs_bits: [u8; 8],
    pub abs_x: InputAbsAxisInfo,
    pub abs_y: InputAbsAxisInfo,
}

impl InputDeviceMeta {
    pub const fn empty() -> Self {
        Self {
            present: false,
            profile: InputDeviceProfile::Keyboard,
            bustype: 0x06, // BUS_VIRTUAL
            vendor: 0x0627,
            product: 0x0001,
            version: 0x0100,
            name: [0; 64],
            name_len: 0,
            prop_bits: [0; 8],
            ev_bits: 0,
            key_bits: [0; 96],
            rel_bits: [0; 4],
            abs_bits: [0; 8],
            abs_x: InputAbsAxisInfo {
                value: 0,
                minimum: 0,
                maximum: 0x7fff,
                fuzz: 0,
                flat: 0,
                resolution: 0,
            },
            abs_y: InputAbsAxisInfo {
                value: 0,
                minimum: 0,
                maximum: 0x7fff,
                fuzz: 0,
                flat: 0,
                resolution: 0,
            },
        }
    }

    pub fn default_keyboard() -> Self {
        let mut meta = Self::empty();
        meta.present = true;
        meta.profile = InputDeviceProfile::Keyboard;
        let name = b"QEMU Virtio Keyboard\0";
        meta.name[..name.len() - 1].copy_from_slice(&name[..name.len() - 1]);
        meta.name_len = name.len() - 1;
        meta.ev_bits = (1 << EV_SYN) | (1 << EV_KEY) | (1 << EV_REP);
        // Mark common keyboard keys 1..=127.
        for code in 1usize..=127 {
            meta.key_bits[code / 8] |= 1u8 << (code % 8);
        }
        meta
    }

    pub fn encode_id(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..2].copy_from_slice(&self.bustype.to_le_bytes());
        out[2..4].copy_from_slice(&self.vendor.to_le_bytes());
        out[4..6].copy_from_slice(&self.product.to_le_bytes());
        out[6..8].copy_from_slice(&self.version.to_le_bytes());
        out
    }

    pub fn copy_ev_bitmask(&self, ev_type: u16, out: &mut [u8]) -> usize {
        out.fill(0);
        match ev_type {
            0 => {
                let bytes = self.ev_bits.to_le_bytes();
                let n = bytes.len().min(out.len());
                out[..n].copy_from_slice(&bytes[..n]);
                n
            }
            EV_KEY => {
                let n = self.key_bits.len().min(out.len());
                out[..n].copy_from_slice(&self.key_bits[..n]);
                n
            }
            EV_REL => {
                let n = self.rel_bits.len().min(out.len());
                out[..n].copy_from_slice(&self.rel_bits[..n]);
                n
            }
            EV_ABS => {
                let n = self.abs_bits.len().min(out.len());
                out[..n].copy_from_slice(&self.abs_bits[..n]);
                n
            }
            _ => out.len(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InputEvent {
    pub sec: i64,
    pub usec: i64,
    pub event_type: u16,
    pub code: u16,
    pub value: i32,
}

impl InputEvent {
    pub fn encode(self) -> [u8; INPUT_EVENT_BYTES] {
        let mut out = [0u8; INPUT_EVENT_BYTES];
        out[0..8].copy_from_slice(&self.sec.to_le_bytes());
        out[8..16].copy_from_slice(&self.usec.to_le_bytes());
        out[16..18].copy_from_slice(&self.event_type.to_le_bytes());
        out[18..20].copy_from_slice(&self.code.to_le_bytes());
        out[20..24].copy_from_slice(&self.value.to_le_bytes());
        out
    }
}

/// `evdev` input event device (`/dev/input/event0..N`) enforcing seat-focus isolation and grab
/// revocation when a session becomes inactive.
#[derive(Clone, Debug)]
pub struct EvdevDevice {
    pub meta: InputDeviceMeta,
    ring: [InputEvent; MAX_INPUT_RING],
    head: usize,
    tail: usize,
    count: usize,
    grab_session: Option<u32>,
    grab_generation: u32,
}

impl Default for EvdevDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl EvdevDevice {
    pub const fn new() -> Self {
        Self {
            meta: InputDeviceMeta::empty(),
            ring: [InputEvent {
                sec: 0,
                usec: 0,
                event_type: 0,
                code: 0,
                value: 0,
            }; MAX_INPUT_RING],
            head: 0,
            tail: 0,
            count: 0,
            grab_session: None,
            grab_generation: 1,
        }
    }

    pub const fn has_pending_events(&self) -> bool {
        self.count > 0
    }

    pub fn push_event(&mut self, event: InputEvent) -> Result<(), Errno> {
        if self.count == MAX_INPUT_RING {
            // Drop oldest unread event cleanly on ring saturation.
            self.head = (self.head + 1) % MAX_INPUT_RING;
            self.count -= 1;
        }
        self.ring[self.tail] = event;
        self.tail = (self.tail + 1) % MAX_INPUT_RING;
        self.count += 1;
        Ok(())
    }

    pub fn grab(
        &mut self,
        session_id: u32,
        session_gen: u32,
        active_session: Option<(u32, u32)>,
        enable: bool,
    ) -> Result<(), Errno> {
        if active_session != Some((session_id, session_gen)) {
            return Err(Errno::EACCES);
        }
        if enable {
            if let Some(holder) = self.grab_session
                && holder != session_id
            {
                return Err(Errno::EBUSY);
            }
            self.grab_session = Some(session_id);
            self.grab_generation = session_gen;
        } else if self.grab_session == Some(session_id) {
            self.grab_session = None;
        }
        Ok(())
    }

    pub fn revoke_on_seat_switch(&mut self, new_generation: u32) {
        self.grab_session = None;
        self.grab_generation = new_generation;
    }

    pub fn read_event(
        &mut self,
        session_id: u32,
        session_gen: u32,
        active_session: Option<(u32, u32)>,
    ) -> Result<InputEvent, Errno> {
        if active_session != Some((session_id, session_gen)) {
            return Err(Errno::EACCES);
        }
        if let Some(grabber) = self.grab_session
            && grabber != session_id
        {
            return Err(Errno::EBUSY);
        }
        if self.count == 0 {
            return Err(Errno::EAGAIN);
        }
        let ev = self.ring[self.head];
        self.head = (self.head + 1) % MAX_INPUT_RING;
        self.count -= 1;
        Ok(ev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evdev_ioctl_decoder_handles_variable_lengths_and_bitmasks() {
        assert_eq!(
            EvdevIoctl::decode(0x8040_4506),
            Some(EvdevIoctl::GetName(64))
        );
        assert_eq!(
            EvdevIoctl::decode(0x8080_4506),
            Some(EvdevIoctl::GetName(128))
        );
        assert_eq!(
            EvdevIoctl::decode(0x8060_4521),
            Some(EvdevIoctl::GetBit {
                ev_type: EV_KEY,
                len: 96
            })
        );
        assert_eq!(
            EvdevIoctl::decode(0x8018_4541),
            Some(EvdevIoctl::GetAbs { axis: 1 })
        );

        let kb = InputDeviceMeta::default_keyboard();
        let mut buf = [0u8; 96];
        kb.copy_ev_bitmask(0, &mut buf[..8]);
        assert_ne!(buf[0] & (1 << EV_KEY), 0);
        kb.copy_ev_bitmask(EV_KEY, &mut buf);
        assert_ne!(buf[28 / 8] & (1 << (28 % 8)), 0);
    }
}
