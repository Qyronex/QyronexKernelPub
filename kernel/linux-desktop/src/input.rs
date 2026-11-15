// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_abi::Errno;

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;

pub const EVIOCGVERSION: u64 = 0x8004_4501;
pub const EVIOCGID: u64 = 0x8008_4502;
pub const EVIOCGNAME: u64 = 0x8040_4506;
pub const EVIOCGBIT_KEY: u64 = 0x8008_4521;
pub const EVIOCGRAB: u64 = 0x4004_4590;

/// Linux `struct input_event` (24 bytes on 64-bit AArch64).
pub const INPUT_EVENT_BYTES: usize = 24;
pub const MAX_INPUT_RING: usize = 32;

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

/// `evdev` input event device (`/dev/input/event0`) enforcing seat-focus isolation and grab
/// revocation when a session becomes inactive.
#[derive(Clone, Debug)]
pub struct EvdevDevice {
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
