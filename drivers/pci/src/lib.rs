// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub const CONFIG_SPACE_SIZE: usize = 4096;
pub const LEGACY_CONFIG_SIZE: usize = 256;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl Address {
    pub const fn is_valid(self) -> bool {
        self.device < 32 && self.function < 8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidAddress,
    BusOutsideWindow,
    Overflow,
    Truncated,
    NoDevice,
    MalformedCapability,
    CapabilityLoop,
    InvalidBar,
}

pub const VENDOR_INTEL: u16 = 0x8086;
pub const VENDOR_AMD: u16 = 0x1022;
pub const VENDOR_BROADCOM: u16 = 0x14E4;
pub const VENDOR_REALTEK: u16 = 0x10EC;
pub const VENDOR_REDHAT_VIRTIO: u16 = 0x1AF4;
pub const VENDOR_VIA: u16 = 0x1106;
pub const VENDOR_RASPBERRY_PI: u16 = 0x1DE4;

pub const DEVICE_INTEL_E1000: u16 = 0x100E;
pub const DEVICE_INTEL_E1000E: u16 = 0x10D3;
pub const DEVICE_INTEL_I210: u16 = 0x1533;
pub const DEVICE_INTEL_I225_V: u16 = 0x15F3;
pub const DEVICE_INTEL_Q35_HOST_BRIDGE: u16 = 0x29C0;
pub const DEVICE_INTEL_440FX_HOST_BRIDGE: u16 = 0x1237;

pub const DEVICE_AMD_PCNET_PCI: u16 = 0x2000;
pub const DEVICE_AMD_ZEN_ROOT_COMPLEX: u16 = 0x1480;

pub const DEVICE_REALTEK_RTL8168: u16 = 0x8168;
pub const DEVICE_VIRTIO_NET_LEGACY: u16 = 0x1000;
pub const DEVICE_VIRTIO_NET_MODERN: u16 = 0x1041;
pub const DEVICE_VIA_VL805_XHCI: u16 = 0x3483;
pub const DEVICE_RPI5_RP1_SOUTHBRIDGE: u16 = 0x0001;

pub const X86_PCI_CONFIG_ADDRESS_PORT: u16 = 0x0CF8;
pub const X86_PCI_CONFIG_DATA_PORT: u16 = 0x0CFC;

pub const COMMAND_IO_SPACE: u16 = 1 << 0;
pub const COMMAND_MEMORY_SPACE: u16 = 1 << 1;
pub const COMMAND_BUS_MASTER: u16 = 1 << 2;
pub const COMMAND_INTERRUPT_DISABLE: u16 = 1 << 10;

pub const CAP_ID_PM: u8 = 0x01;
pub const CAP_ID_MSI: u8 = 0x05;
pub const CAP_ID_VENDOR: u8 = 0x09;
pub const CAP_ID_PCIE: u8 = 0x10;
pub const CAP_ID_MSIX: u8 = 0x11;

pub const CLASS_NETWORK_CONTROLLER: u8 = 0x02;
pub const SUBCLASS_ETHERNET: u8 = 0x00;
pub const CLASS_SERIAL_BUS: u8 = 0x0C;
pub const SUBCLASS_USB: u8 = 0x03;
pub const PROG_IF_XHCI: u8 = 0x30;

/// Encodes an x86 Legacy PCI Configuration Mechanism #1 32-bit address value for I/O port `0xCF8`.
pub const fn legacy_io_config_address(
    bus: u8,
    device: u8,
    function: u8,
    register_offset: u8,
) -> Result<u32, Error> {
    if device >= 32 || function >= 8 || (register_offset & 0b11) != 0 {
        return Err(Error::InvalidAddress);
    }
    Ok(0x8000_0000
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | (register_offset as u32))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PcieGen {
    Gen1,
    Gen2,
    Gen3,
    Gen4,
    Gen5,
    Unknown(u8),
}

impl PcieGen {
    #[must_use]
    pub const fn from_speed_code(code: u8) -> Self {
        match code & 0x0F {
            1 => Self::Gen1,
            2 => Self::Gen2,
            3 => Self::Gen3,
            4 => Self::Gen4,
            5 => Self::Gen5,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn transfer_rate_mhz_per_lane(self) -> u32 {
        match self {
            Self::Gen1 => 2_500,
            Self::Gen2 => 5_000,
            Self::Gen3 => 8_000,
            Self::Gen4 => 16_000,
            Self::Gen5 => 32_000,
            Self::Unknown(_) => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcieLinkInfo {
    pub cap_offset: u8,
    pub generation: PcieGen,
    pub negotiated_width: u8,
    pub link_training: bool,
    pub dll_link_active: bool,
}

impl PcieLinkInfo {
    /// Parses the PCIe Capability structure (Capability ID `0x10`) from a 256-byte configuration space.
    pub fn parse_from_config(config: &[u8; 256], cap_offset: u8) -> Result<Self, Error> {
        let base = cap_offset as usize;
        if base < 0x40 || base + 0x14 > config.len() || config[base] != CAP_ID_PCIE {
            return Err(Error::MalformedCapability);
        }
        let link_status = u16::from_le_bytes([config[base + 0x12], config[base + 0x13]]);
        let speed_code = (link_status & 0x000F) as u8;
        let negotiated_width = ((link_status >> 4) & 0x003F) as u8;
        let link_training = (link_status & (1 << 11)) != 0;
        let dll_link_active = (link_status & (1 << 13)) != 0;

        Ok(Self {
            cap_offset,
            generation: PcieGen::from_speed_code(speed_code),
            negotiated_width,
            link_training,
            dll_link_active,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MsiCapability {
    pub cap_offset: u8,
    pub enabled: bool,
    pub is_64bit: bool,
    pub per_vector_masking: bool,
    pub multi_message_capable_log2: u8,
}

impl MsiCapability {
    pub fn parse_from_config(config: &[u8; 256], cap_offset: u8) -> Result<Self, Error> {
        let base = cap_offset as usize;
        if base < 0x40 || base + 4 > config.len() || config[base] != CAP_ID_MSI {
            return Err(Error::MalformedCapability);
        }
        let msg_ctrl = u16::from_le_bytes([config[base + 2], config[base + 3]]);
        Ok(Self {
            cap_offset,
            enabled: (msg_ctrl & (1 << 0)) != 0,
            multi_message_capable_log2: ((msg_ctrl >> 1) & 0b111) as u8,
            is_64bit: (msg_ctrl & (1 << 7)) != 0,
            per_vector_masking: (msg_ctrl & (1 << 8)) != 0,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MsixCapability {
    pub cap_offset: u8,
    pub enabled: bool,
    pub function_mask: bool,
    pub table_size: u16,
    pub table_bir: u8,
    pub table_offset: u32,
}

impl MsixCapability {
    pub fn parse_from_config(config: &[u8; 256], cap_offset: u8) -> Result<Self, Error> {
        let base = cap_offset as usize;
        if base < 0x40 || base + 12 > config.len() || config[base] != CAP_ID_MSIX {
            return Err(Error::MalformedCapability);
        }
        let msg_ctrl = u16::from_le_bytes([config[base + 2], config[base + 3]]);
        let table_raw = u32::from_le_bytes([
            config[base + 4],
            config[base + 5],
            config[base + 6],
            config[base + 7],
        ]);
        Ok(Self {
            cap_offset,
            enabled: (msg_ctrl & (1 << 15)) != 0,
            function_mask: (msg_ctrl & (1 << 14)) != 0,
            table_size: (msg_ctrl & 0x07FF) + 1,
            table_bir: (table_raw & 0b111) as u8,
            table_offset: table_raw & !0b111,
        })
    }
}

#[cfg(test)]
mod pcie_extension_tests {
    use super::*;

    #[test]
    fn encodes_x86_legacy_port_io_config_address() {
        let addr = legacy_io_config_address(0, 2, 0, 0x10).unwrap();
        assert_eq!(addr, 0x8000_1010);
        assert_eq!(
            legacy_io_config_address(1, 32, 0, 0),
            Err(Error::InvalidAddress)
        );
        assert_eq!(
            legacy_io_config_address(1, 0, 8, 0),
            Err(Error::InvalidAddress)
        );
        assert_eq!(
            legacy_io_config_address(1, 0, 0, 3),
            Err(Error::InvalidAddress)
        );
    }

    #[test]
    fn parses_pcie_link_status_and_msi_msix_capabilities() {
        let mut config = [0u8; 256];
        // PCIe capability at 0x60: Gen2 x4, DLL active
        config[0x60] = CAP_ID_PCIE;
        config[0x61] = 0x80;
        let link_status: u16 = 2 | (4 << 4) | (1 << 13);
        config[0x72..0x74].copy_from_slice(&link_status.to_le_bytes());

        // MSI-X capability at 0x80: enabled, 8 vectors (encoded 7), BIR 2, offset 0x2000
        config[0x80] = CAP_ID_MSIX;
        config[0x81] = 0x00;
        let msix_ctrl: u16 = (1 << 15) | 7;
        config[0x82..0x84].copy_from_slice(&msix_ctrl.to_le_bytes());
        let msix_table: u32 = 0x2000 | 2;
        config[0x84..0x88].copy_from_slice(&msix_table.to_le_bytes());

        let link = PcieLinkInfo::parse_from_config(&config, 0x60).unwrap();
        assert_eq!(link.generation, PcieGen::Gen2);
        assert_eq!(link.generation.transfer_rate_mhz_per_lane(), 5_000);
        assert_eq!(link.negotiated_width, 4);
        assert!(link.dll_link_active);

        let msix = MsixCapability::parse_from_config(&config, 0x80).unwrap();
        assert!(msix.enabled);
        assert_eq!(msix.table_size, 8);
        assert_eq!(msix.table_bir, 2);
        assert_eq!(msix.table_offset, 0x2000);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcamWindow {
    pub base: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

impl EcamWindow {
    pub fn config_address(self, address: Address) -> Result<u64, Error> {
        if !address.is_valid() {
            return Err(Error::InvalidAddress);
        }
        if address.segment != self.segment
            || !(self.start_bus..=self.end_bus).contains(&address.bus)
        {
            return Err(Error::BusOutsideWindow);
        }
        let bus = (address.bus - self.start_bus) as u64;
        self.base
            .checked_add(bus << 20)
            .ok_or(Error::Overflow)?
            .checked_add((address.device as u64) << 15)
            .ok_or(Error::Overflow)?
            .checked_add((address.function as u64) << 12)
            .ok_or(Error::Overflow)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub vendor_id: u16,
    pub device_id: u16,
    pub command: u16,
    pub status: u16,
    pub revision: u8,
    pub programming_interface: u8,
    pub subclass: u8,
    pub class: u8,
    pub header_type: u8,
    pub subsystem_vendor_id: Option<u16>,
    pub subsystem_id: Option<u16>,
}

impl Header {
    pub fn parse(config: &[u8]) -> Result<Self, Error> {
        if config.len() < 64 {
            return Err(Error::Truncated);
        }
        let vendor_id = read_u16(config, 0)?;
        if vendor_id == 0xffff {
            return Err(Error::NoDevice);
        }
        let header_type = config[0x0e];
        let type_number = header_type & 0x7f;
        let (subsystem_vendor_id, subsystem_id) = if type_number == 0 {
            (Some(read_u16(config, 0x2c)?), Some(read_u16(config, 0x2e)?))
        } else {
            (None, None)
        };
        Ok(Self {
            vendor_id,
            device_id: read_u16(config, 2)?,
            command: read_u16(config, 4)?,
            status: read_u16(config, 6)?,
            revision: config[8],
            programming_interface: config[9],
            subclass: config[10],
            class: config[11],
            header_type,
            subsystem_vendor_id,
            subsystem_id,
        })
    }

    pub const fn multifunction(self) -> bool {
        self.header_type & 0x80 != 0
    }
    pub const fn has_capabilities(self) -> bool {
        self.status & (1 << 4) != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bar {
    Io { base: u32 },
    Memory32 { base: u32, prefetchable: bool },
    Memory64 { base: u64, prefetchable: bool },
}

impl Bar {
    pub fn parse(low: u32, high: Option<u32>) -> Result<Self, Error> {
        if low & 1 != 0 {
            return Ok(Self::Io { base: low & !0x3 });
        }
        let prefetchable = low & (1 << 3) != 0;
        match (low >> 1) & 0x3 {
            0 => Ok(Self::Memory32 {
                base: low & !0xf,
                prefetchable,
            }),
            2 => {
                let high = high.ok_or(Error::InvalidBar)?;
                Ok(Self::Memory64 {
                    base: ((high as u64) << 32) | (low as u64 & !0xf),
                    prefetchable,
                })
            }
            _ => Err(Error::InvalidBar),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    pub id: u8,
    pub offset: u8,
}

pub struct Capabilities<'a> {
    config: &'a [u8],
    next: u8,
    visited: u64,
    finished: bool,
}

impl<'a> Capabilities<'a> {
    pub fn new(config: &'a [u8], header: Header) -> Result<Self, Error> {
        if config.len() < LEGACY_CONFIG_SIZE {
            return Err(Error::Truncated);
        }
        let next = if header.has_capabilities() {
            config[0x34] & 0xfc
        } else {
            0
        };
        Ok(Self {
            config,
            next,
            visited: 0,
            finished: false,
        })
    }
}

impl Iterator for Capabilities<'_> {
    type Item = Result<Capability, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished || self.next == 0 {
            return None;
        }
        let offset = self.next as usize;
        if !(0x40..=0xfc).contains(&offset) || offset + 2 > LEGACY_CONFIG_SIZE {
            self.finished = true;
            return Some(Err(Error::MalformedCapability));
        }
        let index = (offset - 0x40) / 4;
        let bit = 1u64 << index;
        if self.visited & bit != 0 {
            self.finished = true;
            return Some(Err(Error::CapabilityLoop));
        }
        self.visited |= bit;
        let capability = Capability {
            id: self.config[offset],
            offset: offset as u8,
        };
        let raw_next = self.config[offset + 1];
        if raw_next != 0 && raw_next & 0x3 != 0 {
            self.finished = true;
            return Some(Err(Error::MalformedCapability));
        }
        self.next = raw_next;
        Some(Ok(capability))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtendedCapability {
    pub id: u16,
    pub version: u8,
    pub offset: u16,
}

pub struct ExtendedCapabilities<'a> {
    config: &'a [u8],
    next: u16,
    remaining: u16,
}

impl<'a> ExtendedCapabilities<'a> {
    pub fn new(config: &'a [u8]) -> Result<Self, Error> {
        if config.len() < CONFIG_SPACE_SIZE {
            return Err(Error::Truncated);
        }
        Ok(Self {
            config,
            next: 0x100,
            remaining: 960,
        })
    }
}

impl Iterator for ExtendedCapabilities<'_> {
    type Item = Result<ExtendedCapability, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == 0 || self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let offset = self.next as usize;
        if !(0x100..=0xffc).contains(&offset) || offset & 0x3 != 0 {
            self.next = 0;
            return Some(Err(Error::MalformedCapability));
        }
        let header = match read_u32(self.config, offset) {
            Ok(value) => value,
            Err(error) => {
                self.next = 0;
                return Some(Err(error));
            }
        };
        let id = header as u16;
        if id == 0 || id == 0xffff {
            self.next = 0;
            return None;
        }
        let version = ((header >> 16) & 0xf) as u8;
        let next = ((header >> 20) & 0xfff) as u16;
        if next == self.next {
            self.next = 0;
            return Some(Err(Error::CapabilityLoop));
        }
        self.next = next;
        Some(Ok(ExtendedCapability {
            id,
            version,
            offset: offset as u16,
        }))
    }
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16, Error> {
    let raw: [u8; 2] = bytes
        .get(at..at + 2)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u16::from_le_bytes(raw))
}
fn read_u32(bytes: &[u8], at: usize) -> Result<u32, Error> {
    let raw: [u8; 4] = bytes
        .get(at..at + 4)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u32::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecam_address_matches_pcie_layout() {
        let window = EcamWindow {
            base: 0xe000_0000,
            segment: 0,
            start_bus: 0x20,
            end_bus: 0x2f,
        };
        let address = Address {
            segment: 0,
            bus: 0x21,
            device: 3,
            function: 2,
        };
        assert_eq!(
            window.config_address(address).unwrap(),
            0xe000_0000 + (1 << 20) + (3 << 15) + (2 << 12)
        );
    }

    #[test]
    fn absent_device_is_not_parsed_as_header() {
        let config = [0xffu8; 64];
        assert_eq!(Header::parse(&config), Err(Error::NoDevice));
    }

    #[test]
    fn capability_cycle_is_detected() {
        let mut config = [0u8; 256];
        config[0..2].copy_from_slice(&0x1234u16.to_le_bytes());
        config[6..8].copy_from_slice(&(1u16 << 4).to_le_bytes());
        config[0x34] = 0x40;
        config[0x40] = 5;
        config[0x41] = 0x44;
        config[0x44] = 0x11;
        config[0x45] = 0x40;
        let header = Header::parse(&config).unwrap();
        let mut caps = Capabilities::new(&config, header).unwrap();
        assert!(caps.next().unwrap().is_ok());
        assert!(caps.next().unwrap().is_ok());
        assert_eq!(caps.next().unwrap(), Err(Error::CapabilityLoop));
    }

    #[test]
    fn parses_64bit_bar_without_truncation() {
        let bar = Bar::parse(0x3456_700c, Some(0x0000_1234)).unwrap();
        assert_eq!(
            bar,
            Bar::Memory64 {
                base: 0x0000_1234_3456_7000,
                prefetchable: true
            }
        );
    }
}
