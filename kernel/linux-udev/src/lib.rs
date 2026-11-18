// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Step 38 — `udev`, hotplug, and Linux-visible device model:
//! - sysfs hierarchy and Linux-visible device identities for the supported VirtIO block (`vda`),
//!   VirtIO network (`eth0`), and console/TTY (`ttyAMA0`, `console`) subset,
//! - `NETLINK_KOBJECT_UEVENT` (`protocol = 15`) `add`/`remove` event synthesis,
//! - race-safe device lifecycle with capability-generation revocation so removed devices never
//!   leave stale authority behind.

use kernal_capability::{CapRights, Capability, ObjectId};
use kernal_linux_abi::Errno;

pub const NETLINK_KOBJECT_UEVENT: u32 = 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceSubsystem {
    Block,
    Net,
    Tty,
}

impl DeviceSubsystem {
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Block => b"block",
            Self::Net => b"net",
            Self::Tty => b"tty",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UeventAction {
    Add,
    Remove,
    Change,
}

impl UeventAction {
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Add => b"add",
            Self::Remove => b"remove",
            Self::Change => b"change",
        }
    }
}

/// One Linux-visible device node in the Step-38 device model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxVisibleDevice {
    live: bool,
    generation: u32,
    object_id: ObjectId,
    subsystem: DeviceSubsystem,
    name: [u8; 16],
    name_len: usize,
    devpath: [u8; 48],
    devpath_len: usize,
    major: u32,
    minor: u32,
    ifindex: u32,
    size_sectors: u64,
}

impl LinuxVisibleDevice {
    const EMPTY: Self = Self {
        live: false,
        generation: 0,
        object_id: ObjectId(0),
        subsystem: DeviceSubsystem::Block,
        name: [0u8; 16],
        name_len: 0,
        devpath: [0u8; 48],
        devpath_len: 0,
        major: 0,
        minor: 0,
        ifindex: 0,
        size_sectors: 0,
    };

    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    pub fn devpath(&self) -> &[u8] {
        &self.devpath[..self.devpath_len]
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }
}

/// Capability token bound to a specific hotplug generation of a [`LinuxVisibleDevice`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceHandleToken {
    pub cap: Capability,
    pub generation: u32,
}

/// Race-safe registry of Linux-visible devices (`vda`, `eth0`, `ttyAMA0`, `console`) with
/// monotonic `uevent` sequence numbers and capability-generation revocation on device removal.
pub struct UdevDeviceRegistry<const MAX_DEVS: usize> {
    devices: [LinuxVisibleDevice; MAX_DEVS],
    seqnum: u64,
    next_generation: u32,
}

impl<const MAX_DEVS: usize> Default for UdevDeviceRegistry<MAX_DEVS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_DEVS: usize> UdevDeviceRegistry<MAX_DEVS> {
    pub const fn new() -> Self {
        Self {
            devices: [LinuxVisibleDevice::EMPTY; MAX_DEVS],
            seqnum: 1,
            next_generation: 1,
        }
    }

    /// Seeds the baseline QEMU/hardware VirtIO block (`vda`), VirtIO net (`eth0`), and serial
    /// console (`ttyAMA0`) devices.
    pub fn seed_supported_devices(&mut self) -> Result<(), Errno> {
        let _ = self.register_device(
            DeviceSubsystem::Block,
            b"vda",
            b"/devices/virtio0/block/vda",
            254,
            0,
            0,
            2_097_152, // 1 GiB in 512-byte sectors
        )?;
        let _ = self.register_device(
            DeviceSubsystem::Net,
            b"eth0",
            b"/devices/virtio1/net/eth0",
            0,
            0,
            2,
            0,
        )?;
        let _ = self.register_device(
            DeviceSubsystem::Tty,
            b"ttyAMA0",
            b"/devices/platform/pl011/tty/ttyAMA0",
            204,
            64,
            0,
            0,
        )?;
        Ok(())
    }

    /// Registers (hotplugs) a device, returning its slot index and the `NETLINK_KOBJECT_UEVENT`
    /// sequence number assigned to the `add` event.
    #[allow(clippy::too_many_arguments)]
    pub fn register_device(
        &mut self,
        subsystem: DeviceSubsystem,
        name: &[u8],
        devpath: &[u8],
        major: u32,
        minor: u32,
        ifindex: u32,
        size_sectors: u64,
    ) -> Result<(usize, u64), Errno> {
        if name.is_empty() || name.len() > 16 || devpath.is_empty() || devpath.len() > 48 {
            return Err(Errno::EINVAL);
        }
        if self.devices.iter().any(|d| d.live && d.name() == name) {
            return Err(Errno::EEXIST);
        }
        let (idx, slot) = self
            .devices
            .iter_mut()
            .enumerate()
            .find(|(_, d)| !d.live)
            .ok_or(Errno::ENOSPC)?;

        let generation = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1);
        let seq = self.seqnum;
        self.seqnum = self.seqnum.saturating_add(1);

        let mut n = [0u8; 16];
        n[..name.len()].copy_from_slice(name);
        let mut dp = [0u8; 48];
        dp[..devpath.len()].copy_from_slice(devpath);

        *slot = LinuxVisibleDevice {
            live: true,
            generation,
            object_id: ObjectId(0x3800_0000_0000_0000 | ((idx as u64) + 1)),
            subsystem,
            name: n,
            name_len: name.len(),
            devpath: dp,
            devpath_len: devpath.len(),
            major,
            minor,
            ifindex,
            size_sectors,
        };
        Ok((idx, seq))
    }

    /// Grants a capability token bound to the current generation of `name`.
    pub fn issue_handle(&self, name: &[u8], rights: CapRights) -> Result<DeviceHandleToken, Errno> {
        let dev = self
            .devices
            .iter()
            .find(|d| d.live && d.name() == name)
            .ok_or(Errno::ENODEV)?;
        Ok(DeviceHandleToken {
            cap: Capability {
                object: dev.object_id,
                rights,
            },
            generation: dev.generation,
        })
    }

    /// Verifies that `token` still matches a live device and its exact hotplug generation.
    /// Once a device is removed (or hot-replaced), any previously issued token fails closed with `ENODEV`.
    pub fn authorize_handle(
        &self,
        token: DeviceHandleToken,
        required: CapRights,
    ) -> Result<(), Errno> {
        if !token.cap.rights.contains(required) {
            return Err(Errno::EACCES);
        }
        let dev = self
            .devices
            .iter()
            .find(|d| d.live && d.object_id == token.cap.object)
            .ok_or(Errno::ENODEV)?;
        if dev.generation != token.generation {
            return Err(Errno::ENODEV);
        }
        Ok(())
    }

    /// Removes (unplugs) a device by name, invalidating all outstanding capability tokens for it.
    pub fn remove_device(&mut self, name: &[u8]) -> Result<u64, Errno> {
        let slot = self
            .devices
            .iter_mut()
            .find(|d| d.live && d.name() == name)
            .ok_or(Errno::ENODEV)?;
        *slot = LinuxVisibleDevice::EMPTY;
        let seq = self.seqnum;
        self.seqnum = self.seqnum.saturating_add(1);
        Ok(seq)
    }

    /// Formats a `NETLINK_KOBJECT_UEVENT` datagram (`<action>@<devpath>\0ACTION=...\0...`) for `name`.
    pub fn format_uevent(
        &self,
        name: &[u8],
        action: UeventAction,
        out: &mut [u8],
    ) -> Result<usize, Errno> {
        self.format_uevent_with_uuid(name, action, None, self.seqnum, out)
    }

    /// Formats a `NETLINK_KOBJECT_UEVENT` datagram for `name` (with optional `SYNTH_UUID`) and
    /// advances `self.seqnum`.
    pub fn emit_uevent_with_uuid(
        &mut self,
        name: &[u8],
        action: UeventAction,
        synth_uuid: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<usize, Errno> {
        let len = self.format_uevent_with_uuid(name, action, synth_uuid, self.seqnum, out)?;
        self.seqnum = self.seqnum.saturating_add(1);
        Ok(len)
    }

    fn format_uevent_with_uuid(
        &self,
        name: &[u8],
        action: UeventAction,
        synth_uuid: Option<&[u8]>,
        seqnum: u64,
        out: &mut [u8],
    ) -> Result<usize, Errno> {
        let dev = self
            .devices
            .iter()
            .find(|d| d.live && d.name() == name)
            .ok_or(Errno::ENODEV)?;
        let mut cursor = 0usize;
        cursor += push_bytes(out, cursor, action.as_bytes());
        cursor += push_bytes(out, cursor, b"@");
        cursor += push_bytes(out, cursor, dev.devpath());
        cursor += push_bytes(out, cursor, b"\0ACTION=");
        cursor += push_bytes(out, cursor, action.as_bytes());
        cursor += push_bytes(out, cursor, b"\0DEVPATH=");
        cursor += push_bytes(out, cursor, dev.devpath());
        cursor += push_bytes(out, cursor, b"\0SUBSYSTEM=");
        cursor += push_bytes(out, cursor, dev.subsystem.as_bytes());
        if dev.subsystem != DeviceSubsystem::Net {
            cursor += push_bytes(out, cursor, b"\0DEVNAME=");
            cursor += push_bytes(out, cursor, dev.name());
            cursor += push_bytes(out, cursor, b"\0MAJOR=");
            cursor += push_u64(out, cursor, u64::from(dev.major));
            cursor += push_bytes(out, cursor, b"\0MINOR=");
            cursor += push_u64(out, cursor, u64::from(dev.minor));
        } else {
            cursor += push_bytes(out, cursor, b"\0INTERFACE=");
            cursor += push_bytes(out, cursor, dev.name());
            cursor += push_bytes(out, cursor, b"\0IFINDEX=");
            cursor += push_u64(out, cursor, u64::from(dev.ifindex));
        }
        if let Some(uuid) = synth_uuid
            && !uuid.is_empty()
        {
            cursor += push_bytes(out, cursor, b"\0SYNTH_UUID=");
            cursor += push_bytes(out, cursor, uuid);
        }
        cursor += push_bytes(out, cursor, b"\0SEQNUM=");
        cursor += push_u64(out, cursor, seqnum);
        cursor += push_bytes(out, cursor, b"\0");
        Ok(cursor)
    }

    /// Synthesizes `/sys/class/...` and `/sys/devices/...` attributes required by `systemd-udevd`.
    pub fn read_sysfs_device_attr(&self, rel_path: &[u8], out: &mut [u8]) -> Result<usize, Errno> {
        match rel_path {
            b"class/block/vda/dev" | b"devices/virtio0/block/vda/dev" => {
                self.require_live(b"vda")?;
                Ok(push_bytes(out, 0, b"254:0\n"))
            }
            b"class/block/vda/size" | b"devices/virtio0/block/vda/size" => {
                let d = self.require_live(b"vda")?;
                let mut pos = push_u64(out, 0, d.size_sectors);
                pos += push_bytes(out, pos, b"\n");
                Ok(pos)
            }
            b"class/block/vda/uevent" | b"devices/virtio0/block/vda/uevent" => {
                self.require_live(b"vda")?;
                Ok(push_bytes(
                    out,
                    0,
                    b"MAJOR=254\nMINOR=0\nDEVNAME=vda\nDEVTYPE=disk\n",
                ))
            }
            b"class/net/eth0/ifindex" | b"devices/virtio1/net/eth0/ifindex" => {
                self.require_live(b"eth0")?;
                Ok(push_bytes(out, 0, b"2\n"))
            }
            b"class/net/eth0/address" | b"devices/virtio1/net/eth0/address" => {
                self.require_live(b"eth0")?;
                Ok(push_bytes(out, 0, b"52:54:00:12:34:56\n"))
            }
            b"class/net/eth0/operstate" | b"devices/virtio1/net/eth0/operstate" => {
                self.require_live(b"eth0")?;
                Ok(push_bytes(out, 0, b"up\n"))
            }
            b"class/net/eth0/uevent" | b"devices/virtio1/net/eth0/uevent" => {
                self.require_live(b"eth0")?;
                Ok(push_bytes(out, 0, b"INTERFACE=eth0\nIFINDEX=2\n"))
            }
            b"class/tty/ttyAMA0/dev" | b"devices/platform/pl011/tty/ttyAMA0/dev" => {
                self.require_live(b"ttyAMA0")?;
                Ok(push_bytes(out, 0, b"204:64\n"))
            }
            b"class/tty/ttyAMA0/uevent" | b"devices/platform/pl011/tty/ttyAMA0/uevent" => {
                self.require_live(b"ttyAMA0")?;
                Ok(push_bytes(
                    out,
                    0,
                    b"MAJOR=204\nMINOR=64\nDEVNAME=ttyAMA0\n",
                ))
            }
            b"kernel/uevent_seqnum" => {
                let mut pos = push_u64(out, 0, self.seqnum);
                pos += push_bytes(out, pos, b"\n");
                Ok(pos)
            }
            _ => Err(Errno::ENOENT),
        }
    }

    fn require_live(&self, name: &[u8]) -> Result<&LinuxVisibleDevice, Errno> {
        self.devices
            .iter()
            .find(|d| d.live && d.name() == name)
            .ok_or(Errno::ENOENT)
    }
}

fn push_bytes(out: &mut [u8], offset: usize, src: &[u8]) -> usize {
    if offset >= out.len() {
        return 0;
    }
    let avail = out.len() - offset;
    let take = avail.min(src.len());
    out[offset..offset + take].copy_from_slice(&src[..take]);
    take
}

fn push_u64(out: &mut [u8], offset: usize, mut val: u64) -> usize {
    if val == 0 {
        return push_bytes(out, offset, b"0");
    }
    let mut rev = [0u8; 20];
    let mut len = 0usize;
    while val > 0 {
        rev[len] = b'0' + (val % 10) as u8;
        val /= 10;
        len += 1;
    }
    let mut digits = [0u8; 20];
    for i in 0..len {
        digits[i] = rev[len - 1 - i];
    }
    push_bytes(out, offset, &digits[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udev_registry_publishes_virtio_devices_uevents_and_revokes_stale_handles() {
        let mut reg = UdevDeviceRegistry::<8>::new();
        reg.seed_supported_devices().unwrap();

        let mut buf = [0u8; 256];
        let n = reg
            .format_uevent(b"vda", UeventAction::Add, &mut buf)
            .unwrap();
        assert!(buf[..n].starts_with(b"add@/devices/virtio0/block/vda\0"));

        let attr_len = reg
            .read_sysfs_device_attr(b"class/block/vda/dev", &mut buf)
            .unwrap();
        assert_eq!(&buf[..attr_len], b"254:0\n");

        // Issue a handle to vda, then hot-unplug and re-add vda; old handle must fail with ENODEV!
        let handle = reg
            .issue_handle(b"vda", CapRights::READ.union(CapRights::WRITE))
            .unwrap();
        reg.authorize_handle(handle, CapRights::READ).unwrap();

        reg.remove_device(b"vda").unwrap();
        assert_eq!(
            reg.authorize_handle(handle, CapRights::READ),
            Err(Errno::ENODEV)
        );

        reg.register_device(
            DeviceSubsystem::Block,
            b"vda",
            b"/devices/virtio0/block/vda",
            254,
            0,
            0,
            2_097_152,
        )
        .unwrap();
        // Even with the same name re-registered, the old generation token remains invalid!
        assert_eq!(
            reg.authorize_handle(handle, CapRights::READ),
            Err(Errno::ENODEV)
        );

        let s1 = reg.seqnum;
        let mut uevent_buf = [0u8; 512];
        let n1 = reg
            .emit_uevent_with_uuid(b"vda", UeventAction::Add, None, &mut uevent_buf)
            .unwrap();
        let msg1 = core::str::from_utf8(&uevent_buf[..n1]).unwrap();
        assert!(msg1.contains("ACTION=add\0") && msg1.contains(&format!("SEQNUM={s1}\0")));
        assert!(!msg1.contains("SYNTH_UUID="));
        assert_eq!(reg.seqnum, s1 + 1);

        let n2 = reg
            .emit_uevent_with_uuid(
                b"ttyAMA0",
                UeventAction::Add,
                Some(b"11223344-5566-7788-99aa-bbccddeeff00"),
                &mut uevent_buf,
            )
            .unwrap();
        let msg2 = core::str::from_utf8(&uevent_buf[..n2]).unwrap();
        let s2 = s1 + 1;
        assert!(msg2.contains(&format!("SEQNUM={s2}\0")));
        assert!(msg2.contains("SYNTH_UUID=11223344-5566-7788-99aa-bbccddeeff00\0"));
        assert_eq!(reg.seqnum, s2 + 1);
    }
}
