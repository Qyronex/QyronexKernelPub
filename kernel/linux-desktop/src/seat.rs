// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use crate::drm::DrmDevice;
use crate::input::EvdevDevice;
use kernal_capability::{CapRights, Capability};
use kernal_linux_abi::Errno;

pub const MAX_SEAT_SESSIONS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionGrant {
    pub session_id: u32,
    pub uid: u32,
    pub vt: u8,
    pub generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    pub id: u32,
    pub uid: u32,
    pub vt: u8,
    pub active: bool,
    pub allocated: bool,
    pub generation: u32,
}

impl SessionRecord {
    const EMPTY: Self = Self {
        id: 0,
        uid: 0,
        vt: 0,
        active: false,
        allocated: false,
        generation: 1,
    };
}

/// `logind`-compatible seat & session coordinator enforcing atomic focus/master transfer.
#[derive(Clone, Debug)]
pub struct SeatManager {
    pub drm: DrmDevice,
    pub evdev: EvdevDevice,
    sessions: [SessionRecord; MAX_SEAT_SESSIONS],
    active_session: Option<(u32, u32)>,
    next_session_id: u32,
    seat_generation: u32,
}

impl Default for SeatManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SeatManager {
    pub const fn new() -> Self {
        Self {
            drm: DrmDevice::new(),
            evdev: EvdevDevice::new(),
            sessions: [SessionRecord::EMPTY; MAX_SEAT_SESSIONS],
            active_session: None,
            next_session_id: 1,
            seat_generation: 1,
        }
    }

    pub const fn active_session(&self) -> Option<(u32, u32)> {
        self.active_session
    }

    pub const fn seat_generation(&self) -> u32 {
        self.seat_generation
    }

    pub fn open_session(
        &mut self,
        cap: Capability,
        uid: u32,
        vt: u8,
    ) -> Result<SessionGrant, Errno> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(Errno::EACCES);
        }
        let slot = self
            .sessions
            .iter_mut()
            .find(|s| !s.allocated)
            .ok_or(Errno::ENOSPC)?;
        let id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1).max(1);
        *slot = SessionRecord {
            id,
            uid,
            vt,
            active: false,
            allocated: true,
            generation: self.seat_generation,
        };
        Ok(SessionGrant {
            session_id: id,
            uid,
            vt,
            generation: self.seat_generation,
        })
    }

    /// Switches seat focus to `session_id`, revoking previous DRM master and `evdev` grabs first.
    pub fn activate_session(
        &mut self,
        cap: Capability,
        session_id: u32,
    ) -> Result<SessionGrant, Errno> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(Errno::EACCES);
        }
        if !self
            .sessions
            .iter()
            .any(|s| s.allocated && s.id == session_id)
        {
            return Err(Errno::ENOENT);
        }

        self.seat_generation = self.seat_generation.wrapping_add(1).max(1);
        let new_gen = self.seat_generation;
        self.drm.revoke_master_for_seat_switch(new_gen);
        self.evdev.revoke_on_seat_switch(new_gen);

        let mut activated = None;
        for slot in &mut self.sessions {
            if slot.allocated {
                if slot.id == session_id {
                    slot.active = true;
                    slot.generation = new_gen;
                    activated = Some(SessionGrant {
                        session_id: slot.id,
                        uid: slot.uid,
                        vt: slot.vt,
                        generation: new_gen,
                    });
                } else {
                    slot.active = false;
                }
            }
        }
        let grant = activated.ok_or(Errno::ENOENT)?;
        self.active_session = Some((grant.session_id, grant.generation));
        Ok(grant)
    }

    pub fn format_seat0_status(&self, out: &mut [u8]) -> Result<usize, Errno> {
        let active_id = self.active_session.map(|(id, _)| id).unwrap_or(0);
        let mut cursor = 0usize;
        let parts: [&[u8]; 3] = [
            b"ID=seat0\nCAN_MULTI_SESSION=1\nCAN_TTY=1\nCAN_GRAPHICAL=1\nACTIVE=",
            if active_id == 0 { b"none" } else { b"session-" },
            b"\n",
        ];
        for p in parts {
            if cursor + p.len() > out.len() {
                return Err(Errno::ENOBUFS);
            }
            out[cursor..cursor + p.len()].copy_from_slice(p);
            cursor += p.len();
            if p == b"session-" {
                cursor += write_u32_ascii(active_id, &mut out[cursor..])?;
            }
        }
        Ok(cursor)
    }
}

fn write_u32_ascii(mut value: u32, out: &mut [u8]) -> Result<usize, Errno> {
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    loop {
        tmp[len] = b'0' + (value % 10) as u8;
        len += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    if out.len() < len {
        return Err(Errno::ENOBUFS);
    }
    for i in 0..len {
        out[i] = tmp[len - 1 - i];
    }
    Ok(len)
}
