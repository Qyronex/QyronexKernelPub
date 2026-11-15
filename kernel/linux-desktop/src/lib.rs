// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Step 43 — Optional & Cleanly Isolated Debian Desktop Enablement:
//! - DRM/KMS dumb buffer / CRTC / master lock & framebuffer geometry (`/dev/dri/card0`, `/dev/fb0`),
//! - `evdev` input event rings & `EVIOCGRAB` focus isolation (`/dev/input/event0`),
//! - PCM audio DMA period queue (`/dev/snd/pcmC0D0p`),
//! - `logind` seat & session revocation (`/run/systemd/seats/seat0`, `/run/systemd/sessions/*`).

pub mod audio;
pub mod drm;
pub mod input;
pub mod seat;

pub use audio::{
    PcmAudioDevice, PcmFormat, PcmParams, PcmState, SNDRV_PCM_IOCTL_DROP,
    SNDRV_PCM_IOCTL_HW_PARAMS, SNDRV_PCM_IOCTL_PREPARE, SNDRV_PCM_IOCTL_START,
};
pub use drm::{
    DRM_CAP_DUMB_BUFFER, DRM_IOCTL_DROP_MASTER, DRM_IOCTL_GET_CAP, DRM_IOCTL_MODE_CREATE_DUMB,
    DRM_IOCTL_MODE_DESTROY_DUMB, DRM_IOCTL_MODE_GETRESOURCES, DRM_IOCTL_MODE_MAP_DUMB,
    DRM_IOCTL_MODE_SETCRTC, DRM_IOCTL_SET_MASTER, DRM_IOCTL_VERSION, DisplayMode, DrmDevice,
    DumbBufferMeta, FBIOGET_FSCREENINFO, FBIOGET_VSCREENINFO,
};
pub use input::{
    EV_ABS, EV_KEY, EV_REL, EV_SYN, EVIOCGBIT_KEY, EVIOCGID, EVIOCGNAME, EVIOCGRAB, EVIOCGVERSION,
    EvdevDevice, INPUT_EVENT_BYTES, InputEvent,
};
pub use seat::{SeatManager, SessionGrant, SessionRecord};

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_capability::{CapRights, Capability, ObjectId};
    use kernal_linux_abi::Errno;

    #[test]
    fn seat_switch_revokes_previous_drm_master_and_evdev_grab() {
        let ctrl = Capability {
            object: ObjectId(43),
            rights: CapRights::CONTROL
                .union(CapRights::READ)
                .union(CapRights::WRITE),
        };
        let mut seat = SeatManager::new();
        let s1_open = seat.open_session(ctrl, 1000, 1).unwrap();
        let s2_open = seat.open_session(ctrl, 1001, 2).unwrap();

        let s1 = seat.activate_session(ctrl, s1_open.session_id).unwrap();
        let seat_gen1 = seat.seat_generation();
        seat.drm
            .set_master(ctrl, s1.session_id, s1.generation, seat_gen1)
            .unwrap();
        let fb1 = seat.drm.create_dumb(s1.session_id, 1280, 720, 32).unwrap();
        seat.drm
            .set_crtc(
                s1.session_id,
                s1.generation,
                fb1.handle,
                DisplayMode::default(),
            )
            .unwrap();

        seat.evdev
            .grab(s1.session_id, s1.generation, seat.active_session(), true)
            .unwrap();
        seat.evdev
            .push_event(InputEvent {
                sec: 1,
                usec: 0,
                event_type: EV_KEY,
                code: 30,
                value: 1,
            })
            .unwrap();

        // Switch seat to session 2 -> session 1 immediately loses DRM master & evdev read/grab rights.
        let s2 = seat.activate_session(ctrl, s2_open.session_id).unwrap();
        assert_eq!(
            seat.drm.set_crtc(
                s1.session_id,
                s1.generation,
                fb1.handle,
                DisplayMode::default()
            ),
            Err(Errno::EACCES)
        );
        assert_eq!(
            seat.evdev
                .read_event(s1.session_id, s1.generation, seat.active_session()),
            Err(Errno::EACCES)
        );
        // Active session 2 reads the key event cleanly and acquires DRM master.
        let ev = seat
            .evdev
            .read_event(s2.session_id, s2.generation, seat.active_session())
            .unwrap();
        assert_eq!(ev.code, 30);

        let mut status = [0u8; 128];
        let n = seat.format_seat0_status(&mut status).unwrap();
        assert!(
            core::str::from_utf8(&status[..n])
                .unwrap()
                .contains("ACTIVE=session-2")
        );

        // PCM audio enforces period/channel bounds and state transitions.
        let mut pcm = PcmAudioDevice::new();
        assert_eq!(pcm.write_frames(ctrl, &[0u8; 8]), Err(Errno::EBADF));
        pcm.set_hw_params(
            ctrl,
            PcmParams {
                rate_hz: 48_000,
                channels: 2,
                format: PcmFormat::S16Le,
                period_frames: 256,
            },
        )
        .unwrap();
        pcm.prepare().unwrap();
        assert_eq!(pcm.write_frames(ctrl, &[0x12u8; 64]).unwrap(), 16);
        assert_eq!(pcm.state, PcmState::Running);
        pcm.drop_stream();
        assert_eq!(pcm.state, PcmState::Setup);
    }

    #[test]
    fn drm_rejects_overflowing_dumb_buffer_allocations() {
        let mut drm = DrmDevice::new();
        assert_eq!(drm.create_dumb(1, u32::MAX / 2, 4, 32), Err(Errno::ENOMEM));
        assert_eq!(drm.create_dumb(1, 0, 720, 32), Err(Errno::EINVAL));
    }
}
