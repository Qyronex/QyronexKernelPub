// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_capability::{CapRights, Capability};
use kernal_linux_abi::Errno;

pub const USB_DESC_DEVICE: u8 = 1;
pub const USB_DESC_CONFIG: u8 = 2;
pub const USB_DESC_INTERFACE: u8 = 4;
pub const USB_DESC_ENDPOINT: u8 = 5;

pub const USB_CBW_SIGNATURE: u32 = 0x4342_5355; // "USBC"
pub const USB_CSW_SIGNATURE: u32 = 0x5342_5355; // "USBS"

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsbSpeed {
    Low,
    Full,
    High,
    Super,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsbDeviceDescriptor {
    pub usb_bcd: u16,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub max_packet_0: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub num_configs: u8,
}

impl UsbDeviceDescriptor {
    pub fn parse(raw: &[u8]) -> Result<Self, Errno> {
        if raw.len() < 18 || raw[0] != 18 || raw[1] != USB_DESC_DEVICE {
            return Err(Errno::EINVAL);
        }
        if raw[7] == 0 {
            return Err(Errno::EINVAL);
        }
        Ok(Self {
            usb_bcd: u16::from_le_bytes([raw[2], raw[3]]),
            class: raw[4],
            subclass: raw[5],
            protocol: raw[6],
            max_packet_0: raw[7],
            vendor_id: u16::from_le_bytes([raw[8], raw[9]]),
            product_id: u16::from_le_bytes([raw[10], raw[11]]),
            num_configs: raw[17],
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedConfigSummary {
    pub total_length: u16,
    pub num_interfaces: u8,
    pub num_endpoints: u8,
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
}

/// Bounds-checked parser over concatenated USB configuration/interface/endpoint descriptors.
pub fn parse_config_descriptors(raw: &[u8]) -> Result<ParsedConfigSummary, Errno> {
    if raw.len() < 9 || raw[0] < 9 || raw[1] != USB_DESC_CONFIG {
        return Err(Errno::EINVAL);
    }
    let total_length = u16::from_le_bytes([raw[2], raw[3]]);
    if usize::from(total_length) != raw.len() {
        return Err(Errno::EINVAL);
    }
    let mut offset = 0usize;
    let mut num_interfaces = 0u8;
    let mut num_endpoints = 0u8;
    let mut iface_class = 0u8;
    let mut iface_sub = 0u8;
    let mut iface_proto = 0u8;

    while offset < raw.len() {
        let len = usize::from(*raw.get(offset).ok_or(Errno::EINVAL)?);
        let dtype = *raw.get(offset + 1).ok_or(Errno::EINVAL)?;
        if len < 2 || offset + len > raw.len() {
            return Err(Errno::EINVAL);
        }
        match dtype {
            USB_DESC_INTERFACE if len >= 9 => {
                num_interfaces = num_interfaces.saturating_add(1);
                if num_interfaces == 1 {
                    iface_class = raw[offset + 5];
                    iface_sub = raw[offset + 6];
                    iface_proto = raw[offset + 7];
                }
            }
            USB_DESC_ENDPOINT if len >= 7 => {
                num_endpoints = num_endpoints.saturating_add(1);
            }
            USB_DESC_INTERFACE | USB_DESC_ENDPOINT => return Err(Errno::EINVAL),
            _ => {}
        }
        offset += len;
    }

    Ok(ParsedConfigSummary {
        total_length,
        num_interfaces,
        num_endpoints,
        interface_class: iface_class,
        interface_subclass: iface_sub,
        interface_protocol: iface_proto,
    })
}

/// 8-byte USB HID Boot Protocol Keyboard Report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HidBootKeyboardReport {
    pub modifiers: u8,
    pub keys: [u8; 6],
}

impl HidBootKeyboardReport {
    pub fn decode(raw: &[u8]) -> Result<Self, Errno> {
        if raw.len() != 8 {
            return Err(Errno::EINVAL);
        }
        let mut keys = [0u8; 6];
        keys.copy_from_slice(&raw[2..8]);
        Ok(Self {
            modifiers: raw[0],
            keys,
        })
    }
}

/// USB HID Boot Protocol Mouse Report (3 or 4 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HidBootMouseReport {
    pub buttons: u8,
    pub dx: i8,
    pub dy: i8,
    pub wheel: i8,
}

impl HidBootMouseReport {
    pub fn decode(raw: &[u8]) -> Result<Self, Errno> {
        if raw.len() < 3 || raw.len() > 8 {
            return Err(Errno::EINVAL);
        }
        Ok(Self {
            buttons: raw[0],
            dx: raw[1] as i8,
            dy: raw[2] as i8,
            wheel: raw.get(3).copied().unwrap_or(0) as i8,
        })
    }
}

/// USB Mass Storage Bulk-Only Transport Command Block Wrapper (31 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsbMscCbw {
    pub tag: u32,
    pub transfer_len: u32,
    pub flags: u8,
    pub lun: u8,
    pub cdb_len: u8,
    pub cdb: [u8; 16],
}

impl UsbMscCbw {
    pub fn encode(&self) -> Result<[u8; 31], Errno> {
        if self.lun >= 16 || self.cdb_len == 0 || self.cdb_len > 16 {
            return Err(Errno::EINVAL);
        }
        let mut out = [0u8; 31];
        out[0..4].copy_from_slice(&USB_CBW_SIGNATURE.to_le_bytes());
        out[4..8].copy_from_slice(&self.tag.to_le_bytes());
        out[8..12].copy_from_slice(&self.transfer_len.to_le_bytes());
        out[12] = self.flags;
        out[13] = self.lun;
        out[14] = self.cdb_len;
        out[15..31].copy_from_slice(&self.cdb);
        Ok(out)
    }
}

/// USB Mass Storage Command Status Wrapper (13 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsbMscCsw {
    pub tag: u32,
    pub data_residue: u32,
    pub status: u8,
}

impl UsbMscCsw {
    pub fn decode_and_verify(raw: &[u8], expected_tag: u32) -> Result<Self, Errno> {
        if raw.len() != 13 {
            return Err(Errno::EINVAL);
        }
        let sig = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        if sig != USB_CSW_SIGNATURE {
            return Err(Errno::EIO);
        }
        let tag = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
        if tag != expected_tag {
            return Err(Errno::EIO);
        }
        let data_residue = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let status = raw[12];
        if status > 2 {
            return Err(Errno::EIO);
        }
        Ok(Self {
            tag,
            data_residue,
            status,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct UsbPortSlot {
    connected: bool,
    enabled: bool,
    speed: UsbSpeed,
    address: u8,
    generation: u32,
    descriptor: Option<UsbDeviceDescriptor>,
}

impl UsbPortSlot {
    const EMPTY: Self = Self {
        connected: false,
        enabled: false,
        speed: UsbSpeed::High,
        address: 0,
        generation: 1,
        descriptor: None,
    };
}

/// Bounded xHCI/EHCI-style USB host controller root hub with port hotplug & revocation.
#[derive(Clone, Debug)]
pub struct UsbHostController<const PORTS: usize> {
    ports: [UsbPortSlot; PORTS],
    next_addr: u8,
}

impl<const PORTS: usize> Default for UsbHostController<PORTS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const PORTS: usize> UsbHostController<PORTS> {
    pub const fn new() -> Self {
        Self {
            ports: [UsbPortSlot::EMPTY; PORTS],
            next_addr: 1,
        }
    }

    pub fn hotplug_connect(
        &mut self,
        cap: Capability,
        port: usize,
        speed: UsbSpeed,
        descriptor: UsbDeviceDescriptor,
    ) -> Result<(u8, u32), Errno> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(Errno::EACCES);
        }
        let slot = self.ports.get_mut(port).ok_or(Errno::ENODEV)?;
        let addr = self.next_addr.max(1);
        self.next_addr = self.next_addr.wrapping_add(1).max(1);
        slot.generation = slot.generation.wrapping_add(1).max(1);
        slot.connected = true;
        slot.enabled = true;
        slot.speed = speed;
        slot.address = addr;
        slot.descriptor = Some(descriptor);
        Ok((addr, slot.generation))
    }

    pub fn disconnect(&mut self, cap: Capability, port: usize) -> Result<u32, Errno> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(Errno::EACCES);
        }
        let slot = self.ports.get_mut(port).ok_or(Errno::ENODEV)?;
        slot.connected = false;
        slot.enabled = false;
        slot.descriptor = None;
        slot.generation = slot.generation.wrapping_add(1).max(1);
        Ok(slot.generation)
    }

    pub fn active_generation(&self, port: usize) -> Result<u32, Errno> {
        let slot = self.ports.get(port).ok_or(Errno::ENODEV)?;
        if !slot.connected || !slot.enabled {
            return Err(Errno::ENODEV);
        }
        Ok(slot.generation)
    }
}
