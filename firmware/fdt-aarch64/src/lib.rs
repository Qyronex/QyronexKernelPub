// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_fdt::{Blob, Event};

pub const MAX_NODE_DEPTH: usize = 32;
const MAX_PROPERTY_CELLS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Fdt(kernal_fdt::Error),
    NodeDepthExceeded,
    CpuCapacity,
    DeviceCapacity,
    MalformedProperty,
    UnsupportedCellCount,
    ZeroSizedRegion,
    AddressOverflow,
    OverlappingRegion,
    MissingProperty,
}

impl From<kernal_fdt::Error> for Error {
    fn from(value: kernal_fdt::Error) -> Self {
        Self::Fdt(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PsciConduit {
    Smc,
    Hvc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmioRegion {
    pub base: u64,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GicV3Info {
    pub distributor: MmioRegion,
    pub redistributor: MmioRegion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerInterrupts {
    pub secure_physical: u32,
    pub nonsecure_physical: u32,
    pub virtual_timer: u32,
    pub hypervisor: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuInfo {
    pub mpidr: u64,
    pub enabled: bool,
}

impl CpuInfo {
    const EMPTY: Self = Self {
        mpidr: 0,
        enabled: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformInfo<const N: usize> {
    cpus: [CpuInfo; N],
    cpu_count: usize,
    pub psci: Option<PsciConduit>,
    pub gic: Option<GicV3Info>,
    pub timer_interrupts: Option<TimerInterrupts>,
    pub pl011: Option<MmioRegion>,
}

impl<const N: usize> PlatformInfo<N> {
    pub const fn new() -> Self {
        Self {
            cpus: [CpuInfo::EMPTY; N],
            cpu_count: 0,
            psci: None,
            gic: None,
            timer_interrupts: None,
            pl011: None,
        }
    }

    pub fn cpus(&self) -> &[CpuInfo] {
        &self.cpus[..self.cpu_count]
    }

    fn push_cpu(&mut self, cpu: CpuInfo) -> Result<(), Error> {
        if self.cpu_count == N {
            return Err(Error::CpuCapacity);
        }
        self.cpus[self.cpu_count] = cpu;
        self.cpu_count += 1;
        Ok(())
    }
}

impl<const N: usize> Default for PlatformInfo<N> {
    fn default() -> Self {
        Self::new()
    }
}

pub const MAX_CHOSEN_BOOTARGS_BYTES: usize = 256;

/// One `virtio,mmio` platform transport node discovered from an AArch64 FDT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtioMmioInfo {
    pub region: MmioRegion,
    pub irq: u32,
    pub enabled: bool,
}

impl VirtioMmioInfo {
    const EMPTY: Self = Self {
        region: MmioRegion { base: 0, size: 0 },
        irq: 0,
        enabled: false,
    };
}

/// ARM PrimeCell PL031 real-time clock MMIO node discovered from an AArch64 FDT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtcMmioInfo {
    pub region: MmioRegion,
    pub irq: Option<u32>,
    pub enabled: bool,
}

/// Generic PCIe ECAM host controller window (`pci-host-ecam-generic`) from an AArch64 FDT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciHostEcamInfo {
    pub region: MmioRegion,
    pub bus_start: u8,
    pub bus_end: u8,
    pub enabled: bool,
}

/// Kernel boot parameters and seed presence metadata captured from FDT `/chosen`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChosenBootInfo {
    bootargs: [u8; MAX_CHOSEN_BOOTARGS_BYTES],
    bootargs_len: usize,
    pub rng_seed_len: usize,
}

impl ChosenBootInfo {
    pub const fn empty() -> Self {
        Self {
            bootargs: [0u8; MAX_CHOSEN_BOOTARGS_BYTES],
            bootargs_len: 0,
            rng_seed_len: 0,
        }
    }

    pub fn bootargs(&self) -> &[u8] {
        &self.bootargs[..self.bootargs_len]
    }
}

/// Hardware device inventory parsed from an AArch64 FDT without fixed board addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceInventory<const M: usize> {
    virtio_mmio: [VirtioMmioInfo; M],
    virtio_mmio_count: usize,
    pub pl011: Option<MmioRegion>,
    pub pl031_rtc: Option<RtcMmioInfo>,
    pub pcie_ecam: Option<PciHostEcamInfo>,
    pub chosen: ChosenBootInfo,
}

impl<const M: usize> DeviceInventory<M> {
    pub const fn new() -> Self {
        Self {
            virtio_mmio: [VirtioMmioInfo::EMPTY; M],
            virtio_mmio_count: 0,
            pl011: None,
            pl031_rtc: None,
            pcie_ecam: None,
            chosen: ChosenBootInfo::empty(),
        }
    }

    pub fn virtio_mmio_devices(&self) -> &[VirtioMmioInfo] {
        &self.virtio_mmio[..self.virtio_mmio_count]
    }

    fn push_virtio_mmio(&mut self, device: VirtioMmioInfo) -> Result<(), Error> {
        self.check_non_overlapping(device.region)?;
        if self.virtio_mmio_count == M {
            return Err(Error::DeviceCapacity);
        }
        self.virtio_mmio[self.virtio_mmio_count] = device;
        self.virtio_mmio_count += 1;
        Ok(())
    }

    fn check_non_overlapping(&self, candidate: MmioRegion) -> Result<(), Error> {
        let candidate_end = validate_nonzero_region(candidate)?;
        let existing_regions = self
            .virtio_mmio_devices()
            .iter()
            .map(|dev| dev.region)
            .chain(self.pl011)
            .chain(self.pl031_rtc.map(|rtc| rtc.region))
            .chain(self.pcie_ecam.map(|ecam| ecam.region));
        for region in existing_regions {
            let end = validate_nonzero_region(region)?;
            if candidate.base < end && region.base < candidate_end {
                return Err(Error::OverlappingRegion);
            }
        }
        Ok(())
    }
}

impl<const M: usize> Default for DeviceInventory<M> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
struct NodeScratch {
    parent_address_cells: u8,
    parent_size_cells: u8,
    child_address_cells: u8,
    child_size_cells: u8,
    cpu_name: bool,
    device_type_cpu: bool,
    enabled: bool,
    psci_compatible: bool,
    gicv3_compatible: bool,
    timer_compatible: bool,
    pl011_compatible: bool,
    pl031_compatible: bool,
    virtio_mmio_compatible: bool,
    ecam_compatible: bool,
    chosen_node: bool,
    psci_method: Option<PsciConduit>,
    reg: [u32; MAX_PROPERTY_CELLS],
    reg_len: u8,
    interrupts: [u32; MAX_PROPERTY_CELLS],
    interrupts_len: u8,
    bus_range: [u32; 2],
    has_bus_range: bool,
}

impl NodeScratch {
    const EMPTY: Self = Self {
        parent_address_cells: 2,
        parent_size_cells: 1,
        child_address_cells: 2,
        child_size_cells: 1,
        cpu_name: false,
        device_type_cpu: false,
        enabled: true,
        psci_compatible: false,
        gicv3_compatible: false,
        timer_compatible: false,
        pl011_compatible: false,
        pl031_compatible: false,
        virtio_mmio_compatible: false,
        ecam_compatible: false,
        chosen_node: false,
        psci_method: None,
        reg: [0; MAX_PROPERTY_CELLS],
        reg_len: 0,
        interrupts: [0; MAX_PROPERTY_CELLS],
        interrupts_len: 0,
        bus_range: [0; 2],
        has_bus_range: false,
    };

    fn for_child(parent: Option<Self>, name: &str) -> Self {
        let (parent_address_cells, parent_size_cells) = parent
            .map(|node| (node.child_address_cells, node.child_size_cells))
            .unwrap_or((2, 1));
        Self {
            parent_address_cells,
            parent_size_cells,
            cpu_name: name == "cpu" || name.starts_with("cpu@"),
            chosen_node: name == "chosen",
            ..Self::EMPTY
        }
    }

    fn capture_cells(
        destination: &mut [u32; MAX_PROPERTY_CELLS],
        value: &[u8],
    ) -> Result<u8, Error> {
        if !value.len().is_multiple_of(4) {
            return Err(Error::MalformedProperty);
        }
        let (chunks, remainder) = value.as_chunks::<4>();
        debug_assert!(remainder.is_empty());
        let count = chunks.len();
        if count > destination.len() {
            return Err(Error::MalformedProperty);
        }
        for (slot, chunk) in destination.iter_mut().zip(chunks) {
            *slot = u32::from_be_bytes(*chunk);
        }
        Ok(count as u8)
    }
}

pub fn parse_platform<const N: usize>(blob: &Blob<'_>) -> Result<PlatformInfo<N>, Error> {
    let mut platform = PlatformInfo::new();
    walk_fdt(
        blob,
        |_name, _value| Ok(()),
        |node| finalize_node(node, &mut platform),
    )?;
    Ok(platform)
}

/// Discovers QEMU/hardware MMIO peripherals, PCIe ECAM, PL031 RTC, VirtIO-MMIO transports, and
/// `/chosen` metadata from an AArch64 DTB without relying on hard-coded platform addresses.
pub fn parse_device_inventory<const M: usize>(
    blob: &Blob<'_>,
) -> Result<DeviceInventory<M>, Error> {
    let mut inventory = DeviceInventory::new();
    let mut chosen = ChosenBootInfo::empty();
    walk_fdt(
        blob,
        |name, value| capture_chosen_property(name, value, &mut chosen),
        |node| finalize_device_node(node, &mut inventory),
    )?;
    inventory.chosen = chosen;
    Ok(inventory)
}

fn walk_fdt(
    blob: &Blob<'_>,
    mut on_chosen_prop: impl FnMut(&str, &[u8]) -> Result<(), Error>,
    mut on_end_node: impl FnMut(NodeScratch) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut stack = [NodeScratch::EMPTY; MAX_NODE_DEPTH];
    let mut depth = 0usize;

    for event in blob.events() {
        match event? {
            Event::BeginNode(name) => {
                if depth == stack.len() {
                    return Err(Error::NodeDepthExceeded);
                }
                let parent = depth.checked_sub(1).map(|index| stack[index]);
                stack[depth] = NodeScratch::for_child(parent, name);
                depth += 1;
            }
            Event::Property { name, value } => {
                if depth == 0 {
                    return Err(Error::MalformedProperty);
                }
                let node = &mut stack[depth - 1];
                if node.chosen_node {
                    on_chosen_prop(name, value)?;
                }
                match name {
                    "#address-cells" => node.child_address_cells = one_cell(value)?,
                    "#size-cells" => node.child_size_cells = one_cell(value)?,
                    "device_type" => node.device_type_cpu = property_string(value) == Some("cpu"),
                    "status" => {
                        node.enabled = matches!(property_string(value), Some("okay") | Some("ok"));
                    }
                    "compatible" => {
                        node.psci_compatible = compatible_contains(value, "arm,psci")
                            || compatible_contains(value, "arm,psci-0.2")
                            || compatible_contains(value, "arm,psci-1.0");
                        node.gicv3_compatible = compatible_contains(value, "arm,gic-v3");
                        node.timer_compatible = compatible_contains(value, "arm,armv8-timer");
                        node.pl011_compatible = compatible_contains(value, "arm,pl011");
                        node.pl031_compatible = compatible_contains(value, "arm,pl031");
                        node.virtio_mmio_compatible = compatible_contains(value, "virtio,mmio");
                        node.ecam_compatible = compatible_contains(value, "pci-host-ecam-generic");
                    }
                    "method" => {
                        node.psci_method = match property_string(value) {
                            Some("smc") => Some(PsciConduit::Smc),
                            Some("hvc") => Some(PsciConduit::Hvc),
                            _ => None,
                        };
                    }
                    "reg" => node.reg_len = NodeScratch::capture_cells(&mut node.reg, value)?,
                    "interrupts" => {
                        node.interrupts_len =
                            NodeScratch::capture_cells(&mut node.interrupts, value)?;
                    }
                    "bus-range" => {
                        let mut cells = [0u32; MAX_PROPERTY_CELLS];
                        let len = NodeScratch::capture_cells(&mut cells, value)?;
                        if len != 2 || cells[0] > cells[1] || cells[1] > 255 {
                            return Err(Error::MalformedProperty);
                        }
                        node.bus_range = [cells[0], cells[1]];
                        node.has_bus_range = true;
                    }
                    _ => {}
                }
            }
            Event::EndNode => {
                if depth == 0 {
                    return Err(Error::MalformedProperty);
                }
                let node = stack[depth - 1];
                on_end_node(node)?;
                depth -= 1;
            }
        }
    }

    if depth != 0 {
        return Err(Error::MalformedProperty);
    }
    Ok(())
}

fn capture_chosen_property(
    name: &str,
    value: &[u8],
    chosen: &mut ChosenBootInfo,
) -> Result<(), Error> {
    match name {
        "bootargs" => {
            let trimmed = match value.iter().position(|b| *b == 0) {
                Some(idx) => &value[..idx],
                None => value,
            };
            if trimmed.len() > MAX_CHOSEN_BOOTARGS_BYTES {
                return Err(Error::MalformedProperty);
            }
            chosen.bootargs[..trimmed.len()].copy_from_slice(trimmed);
            chosen.bootargs_len = trimmed.len();
        }
        "rng-seed" => {
            chosen.rng_seed_len = value.len();
        }
        _ => {}
    }
    Ok(())
}

fn validate_nonzero_region(region: MmioRegion) -> Result<u64, Error> {
    if region.size == 0 {
        return Err(Error::ZeroSizedRegion);
    }
    region
        .base
        .checked_add(region.size)
        .ok_or(Error::AddressOverflow)
}

fn finalize_device_node<const M: usize>(
    node: NodeScratch,
    inventory: &mut DeviceInventory<M>,
) -> Result<(), Error> {
    if node.pl011_compatible && node.reg_len != 0 {
        let region = decode_reg_tuple(
            &node.reg,
            0,
            node.parent_address_cells,
            node.parent_size_cells,
        )?;
        inventory.check_non_overlapping(region)?;
        inventory.pl011 = Some(region);
    }

    if node.pl031_compatible {
        if node.reg_len == 0 {
            return Err(Error::MissingProperty);
        }
        let region = decode_reg_tuple(
            &node.reg,
            0,
            node.parent_address_cells,
            node.parent_size_cells,
        )?;
        inventory.check_non_overlapping(region)?;
        let irq = if node.interrupts_len != 0 {
            if node.interrupts_len < 3 {
                return Err(Error::MalformedProperty);
            }
            Some(decode_gic_interrupt(&node.interrupts[..3])?)
        } else {
            None
        };
        inventory.pl031_rtc = Some(RtcMmioInfo {
            region,
            irq,
            enabled: node.enabled,
        });
    }

    if node.virtio_mmio_compatible {
        if node.reg_len == 0 || node.interrupts_len == 0 {
            return Err(Error::MissingProperty);
        }
        if node.interrupts_len < 3 {
            return Err(Error::MalformedProperty);
        }
        let region = decode_reg_tuple(
            &node.reg,
            0,
            node.parent_address_cells,
            node.parent_size_cells,
        )?;
        let irq = decode_gic_interrupt(&node.interrupts[..3])?;
        inventory.push_virtio_mmio(VirtioMmioInfo {
            region,
            irq,
            enabled: node.enabled,
        })?;
    }

    if node.ecam_compatible {
        if node.reg_len == 0 {
            return Err(Error::MissingProperty);
        }
        let region = decode_reg_tuple(
            &node.reg,
            0,
            node.parent_address_cells,
            node.parent_size_cells,
        )?;
        inventory.check_non_overlapping(region)?;
        let (bus_start, bus_end) = if node.has_bus_range {
            (node.bus_range[0] as u8, node.bus_range[1] as u8)
        } else {
            (0, 255)
        };
        inventory.pcie_ecam = Some(PciHostEcamInfo {
            region,
            bus_start,
            bus_end,
            enabled: node.enabled,
        });
    }

    Ok(())
}

fn finalize_node<const N: usize>(
    node: NodeScratch,
    platform: &mut PlatformInfo<N>,
) -> Result<(), Error> {
    let is_cpu = node.cpu_name || node.device_type_cpu;
    if is_cpu && node.reg_len != 0 {
        let cells = node.parent_address_cells as usize;
        if cells == 0 || cells > 2 || (node.reg_len as usize) < cells {
            return Err(Error::UnsupportedCellCount);
        }
        let mpidr = decode_cells(&node.reg[..cells])?;
        platform.push_cpu(CpuInfo {
            mpidr,
            enabled: node.enabled,
        })?;
    }

    if node.psci_compatible
        && let Some(method) = node.psci_method
    {
        platform.psci = Some(method);
    }

    if node.gicv3_compatible {
        let tuple_cells = node.parent_address_cells as usize + node.parent_size_cells as usize;
        if tuple_cells == 0 || (node.reg_len as usize) < tuple_cells * 2 {
            return Err(Error::MalformedProperty);
        }
        let distributor = decode_reg_tuple(
            &node.reg,
            0,
            node.parent_address_cells,
            node.parent_size_cells,
        )?;
        let redistributor = decode_reg_tuple(
            &node.reg,
            tuple_cells,
            node.parent_address_cells,
            node.parent_size_cells,
        )?;
        platform.gic = Some(GicV3Info {
            distributor,
            redistributor,
        });
    }

    if node.timer_compatible {
        if node.interrupts_len < 12 {
            return Err(Error::MalformedProperty);
        }
        platform.timer_interrupts = Some(TimerInterrupts {
            secure_physical: decode_gic_interrupt(&node.interrupts[0..3])?,
            nonsecure_physical: decode_gic_interrupt(&node.interrupts[3..6])?,
            virtual_timer: decode_gic_interrupt(&node.interrupts[6..9])?,
            hypervisor: decode_gic_interrupt(&node.interrupts[9..12])?,
        });
    }

    if node.pl011_compatible && node.reg_len != 0 {
        platform.pl011 = Some(decode_reg_tuple(
            &node.reg,
            0,
            node.parent_address_cells,
            node.parent_size_cells,
        )?);
    }

    Ok(())
}

fn decode_reg_tuple(
    cells: &[u32],
    offset: usize,
    address_cells: u8,
    size_cells: u8,
) -> Result<MmioRegion, Error> {
    let address_cells = address_cells as usize;
    let size_cells = size_cells as usize;
    if !(1..=2).contains(&address_cells) || !(1..=2).contains(&size_cells) {
        return Err(Error::UnsupportedCellCount);
    }
    let address_end = offset
        .checked_add(address_cells)
        .ok_or(Error::MalformedProperty)?;
    let size_end = address_end
        .checked_add(size_cells)
        .ok_or(Error::MalformedProperty)?;
    let address = decode_cells(
        cells
            .get(offset..address_end)
            .ok_or(Error::MalformedProperty)?,
    )?;
    let size = decode_cells(
        cells
            .get(address_end..size_end)
            .ok_or(Error::MalformedProperty)?,
    )?;
    Ok(MmioRegion {
        base: address,
        size,
    })
}

fn decode_cells(cells: &[u32]) -> Result<u64, Error> {
    match cells {
        [low] => Ok(*low as u64),
        [high, low] => Ok(((*high as u64) << 32) | *low as u64),
        _ => Err(Error::UnsupportedCellCount),
    }
}

fn decode_gic_interrupt(cells: &[u32]) -> Result<u32, Error> {
    let [kind, number, _flags] = cells else {
        return Err(Error::MalformedProperty);
    };
    match *kind {
        0 => number.checked_add(32).ok_or(Error::MalformedProperty), // SPI
        1 => number.checked_add(16).ok_or(Error::MalformedProperty), // PPI
        _ => Err(Error::MalformedProperty),
    }
}

fn one_cell(value: &[u8]) -> Result<u8, Error> {
    let raw: [u8; 4] = value.try_into().map_err(|_| Error::MalformedProperty)?;
    let value = u32::from_be_bytes(raw);
    u8::try_from(value).map_err(|_| Error::UnsupportedCellCount)
}

fn property_string(value: &[u8]) -> Option<&str> {
    let end = value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len());
    core::str::from_utf8(&value[..end]).ok()
}

fn compatible_contains(value: &[u8], expected: &str) -> bool {
    value
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .any(|entry| entry == expected.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_fdt::MAGIC;

    const FDT_BEGIN_NODE: u32 = 1;
    const FDT_END_NODE: u32 = 2;
    const FDT_PROP: u32 = 3;
    const FDT_END: u32 = 9;

    struct Names {
        address_cells: u32,
        size_cells: u32,
        device_type: u32,
        reg: u32,
        status: u32,
        compatible: u32,
        method: u32,
        interrupts: u32,
    }

    fn intern(strings: &mut Vec<u8>, name: &str) -> u32 {
        let offset = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        offset
    }

    fn names(strings: &mut Vec<u8>) -> Names {
        Names {
            address_cells: intern(strings, "#address-cells"),
            size_cells: intern(strings, "#size-cells"),
            device_type: intern(strings, "device_type"),
            reg: intern(strings, "reg"),
            status: intern(strings, "status"),
            compatible: intern(strings, "compatible"),
            method: intern(strings, "method"),
            interrupts: intern(strings, "interrupts"),
        }
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn align_structure(bytes: &mut Vec<u8>) {
        while bytes.len() & 3 != 0 {
            bytes.push(0);
        }
    }

    fn begin_node(structure: &mut Vec<u8>, name: &str) {
        push_u32(structure, FDT_BEGIN_NODE);
        structure.extend_from_slice(name.as_bytes());
        structure.push(0);
        align_structure(structure);
    }

    fn end_node(structure: &mut Vec<u8>) {
        push_u32(structure, FDT_END_NODE);
    }

    fn property(structure: &mut Vec<u8>, name_offset: u32, value: &[u8]) {
        push_u32(structure, FDT_PROP);
        push_u32(structure, value.len() as u32);
        push_u32(structure, name_offset);
        structure.extend_from_slice(value);
        align_structure(structure);
    }

    fn cells(values: &[u32]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in values {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes
    }

    fn sample_dtb() -> Vec<u8> {
        let mut strings = Vec::new();
        let names = names(&mut strings);
        let mut structure = Vec::new();

        begin_node(&mut structure, "");
        property(&mut structure, names.address_cells, &2u32.to_be_bytes());
        property(&mut structure, names.size_cells, &2u32.to_be_bytes());

        begin_node(&mut structure, "cpus");
        property(&mut structure, names.address_cells, &1u32.to_be_bytes());
        property(&mut structure, names.size_cells, &0u32.to_be_bytes());
        begin_node(&mut structure, "cpu@0");
        property(&mut structure, names.device_type, b"cpu\0");
        property(&mut structure, names.reg, &cells(&[0]));
        end_node(&mut structure);
        begin_node(&mut structure, "cpu@1");
        property(&mut structure, names.device_type, b"cpu\0");
        property(&mut structure, names.reg, &cells(&[1]));
        property(&mut structure, names.status, b"okay\0");
        end_node(&mut structure);
        end_node(&mut structure);

        begin_node(&mut structure, "psci");
        property(
            &mut structure,
            names.compatible,
            b"arm,psci-0.2\0arm,psci\0",
        );
        property(&mut structure, names.method, b"hvc\0");
        end_node(&mut structure);

        begin_node(&mut structure, "intc@8000000");
        property(&mut structure, names.compatible, b"arm,gic-v3\0");
        property(
            &mut structure,
            names.reg,
            &cells(&[
                0,
                0x0800_0000,
                0,
                0x0001_0000,
                0,
                0x080a_0000,
                0,
                0x00f6_0000,
            ]),
        );
        end_node(&mut structure);

        begin_node(&mut structure, "timer");
        property(&mut structure, names.compatible, b"arm,armv8-timer\0");
        property(
            &mut structure,
            names.interrupts,
            &cells(&[1, 13, 4, 1, 14, 4, 1, 11, 4, 1, 10, 4]),
        );
        end_node(&mut structure);

        begin_node(&mut structure, "pl011@9000000");
        property(
            &mut structure,
            names.compatible,
            b"arm,pl011\0arm,primecell\0",
        );
        property(
            &mut structure,
            names.reg,
            &cells(&[0, 0x0900_0000, 0, 0x1000]),
        );
        end_node(&mut structure);

        // Generic PrimeCell compatibility must not be mistaken for the UART. Keeping this node
        // after PL011 makes the regression observable as an incorrect override.
        begin_node(&mut structure, "rtc@9010000");
        property(
            &mut structure,
            names.compatible,
            b"arm,pl031\0arm,primecell\0",
        );
        property(
            &mut structure,
            names.reg,
            &cells(&[0, 0x0901_0000, 0, 0x1000]),
        );
        end_node(&mut structure);

        end_node(&mut structure);
        push_u32(&mut structure, FDT_END);

        let reserve_offset = 40usize;
        let structure_offset = reserve_offset + 16;
        let strings_offset = structure_offset + structure.len();
        let total_size = strings_offset + strings.len();
        let mut blob = vec![0u8; total_size];
        blob[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        blob[4..8].copy_from_slice(&(total_size as u32).to_be_bytes());
        blob[8..12].copy_from_slice(&(structure_offset as u32).to_be_bytes());
        blob[12..16].copy_from_slice(&(strings_offset as u32).to_be_bytes());
        blob[16..20].copy_from_slice(&(reserve_offset as u32).to_be_bytes());
        blob[20..24].copy_from_slice(&17u32.to_be_bytes());
        blob[24..28].copy_from_slice(&16u32.to_be_bytes());
        blob[28..32].copy_from_slice(&0u32.to_be_bytes());
        blob[32..36].copy_from_slice(&(strings.len() as u32).to_be_bytes());
        blob[36..40].copy_from_slice(&(structure.len() as u32).to_be_bytes());
        blob[structure_offset..strings_offset].copy_from_slice(&structure);
        blob[strings_offset..].copy_from_slice(&strings);
        blob
    }

    #[test]
    fn discovers_qemu_virt_style_platform_without_fixed_addresses() {
        let bytes = sample_dtb();
        let blob = Blob::parse(&bytes).unwrap();
        let platform = parse_platform::<8>(&blob).unwrap();
        assert_eq!(
            platform.cpus(),
            &[
                CpuInfo {
                    mpidr: 0,
                    enabled: true
                },
                CpuInfo {
                    mpidr: 1,
                    enabled: true
                },
            ]
        );
        assert_eq!(platform.psci, Some(PsciConduit::Hvc));
        assert_eq!(
            platform.gic,
            Some(GicV3Info {
                distributor: MmioRegion {
                    base: 0x0800_0000,
                    size: 0x0001_0000
                },
                redistributor: MmioRegion {
                    base: 0x080a_0000,
                    size: 0x00f6_0000
                },
            })
        );
        assert_eq!(
            platform.timer_interrupts,
            Some(TimerInterrupts {
                secure_physical: 29,
                nonsecure_physical: 30,
                virtual_timer: 27,
                hypervisor: 26,
            })
        );
        assert_eq!(
            platform.pl011,
            Some(MmioRegion {
                base: 0x0900_0000,
                size: 0x1000
            })
        );
    }

    #[test]
    fn disabled_cpu_is_retained_but_not_marked_enabled() {
        let mut bytes = sample_dtb();
        let needle = b"okay\0";
        let position = bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap();
        bytes[position..position + needle.len()].copy_from_slice(b"fail\0");
        let blob = Blob::parse(&bytes).unwrap();
        let platform = parse_platform::<8>(&blob).unwrap();
        assert!(!platform.cpus()[1].enabled);
    }

    fn build_dtb_with_nodes(build: impl FnOnce(&mut Vec<u8>, &mut Vec<u8>)) -> Vec<u8> {
        let mut strings = Vec::new();
        let mut structure = Vec::new();
        begin_node(&mut structure, "");
        let addr_cells = intern(&mut strings, "#address-cells");
        let size_cells = intern(&mut strings, "#size-cells");
        property(&mut structure, addr_cells, &2u32.to_be_bytes());
        property(&mut structure, size_cells, &2u32.to_be_bytes());
        build(&mut strings, &mut structure);
        end_node(&mut structure);
        push_u32(&mut structure, FDT_END);

        let reserve_offset = 40usize;
        let structure_offset = reserve_offset + 16;
        let strings_offset = structure_offset + structure.len();
        let total_size = strings_offset + strings.len();
        let mut blob = vec![0u8; total_size];
        blob[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        blob[4..8].copy_from_slice(&(total_size as u32).to_be_bytes());
        blob[8..12].copy_from_slice(&(structure_offset as u32).to_be_bytes());
        blob[12..16].copy_from_slice(&(strings_offset as u32).to_be_bytes());
        blob[16..20].copy_from_slice(&(reserve_offset as u32).to_be_bytes());
        blob[20..24].copy_from_slice(&17u32.to_be_bytes());
        blob[24..28].copy_from_slice(&16u32.to_be_bytes());
        blob[28..32].copy_from_slice(&0u32.to_be_bytes());
        blob[32..36].copy_from_slice(&(strings.len() as u32).to_be_bytes());
        blob[36..40].copy_from_slice(&(structure.len() as u32).to_be_bytes());
        blob[structure_offset..strings_offset].copy_from_slice(&structure);
        blob[strings_offset..].copy_from_slice(&strings);
        blob
    }

    #[test]
    fn device_inventory_discovers_virtio_mmio_rtc_ecam_and_chosen() {
        let dtb = build_dtb_with_nodes(|strings, structure| {
            let compatible = intern(strings, "compatible");
            let reg = intern(strings, "reg");
            let interrupts = intern(strings, "interrupts");
            let bus_range = intern(strings, "bus-range");
            let bootargs = intern(strings, "bootargs");
            let rng_seed = intern(strings, "rng-seed");

            begin_node(structure, "chosen");
            property(
                structure,
                bootargs,
                b"root=/dev/vda1 rw rootfstype=ext4 console=ttyAMA0\0",
            );
            property(structure, rng_seed, &[0x5au8; 32]);
            end_node(structure);

            begin_node(structure, "pl011@9000000");
            property(structure, compatible, b"arm,pl011\0");
            property(structure, reg, &cells(&[0, 0x0900_0000, 0, 0x1000]));
            end_node(structure);

            begin_node(structure, "rtc@9010000");
            property(structure, compatible, b"arm,pl031\0");
            property(structure, reg, &cells(&[0, 0x0901_0000, 0, 0x1000]));
            property(structure, interrupts, &cells(&[0, 2, 4]));
            end_node(structure);

            begin_node(structure, "virtio_mmio@a000000");
            property(structure, compatible, b"virtio,mmio\0");
            property(structure, reg, &cells(&[0, 0x0a00_0000, 0, 0x200]));
            property(structure, interrupts, &cells(&[0, 16, 1]));
            end_node(structure);

            begin_node(structure, "virtio_mmio@a000200");
            property(structure, compatible, b"virtio,mmio\0");
            property(structure, reg, &cells(&[0, 0x0a00_0200, 0, 0x200]));
            property(structure, interrupts, &cells(&[0, 17, 1]));
            end_node(structure);

            begin_node(structure, "pcie@10000000");
            property(structure, compatible, b"pci-host-ecam-generic\0");
            property(structure, reg, &cells(&[0x40, 0x1000_0000, 0, 0x1000_0000]));
            property(structure, bus_range, &cells(&[0, 15]));
            end_node(structure);
        });

        let blob = Blob::parse(&dtb).unwrap();
        let inv = parse_device_inventory::<8>(&blob).unwrap();
        assert_eq!(inv.virtio_mmio_devices().len(), 2);
        assert_eq!(inv.virtio_mmio_devices()[0].region.base, 0x0a00_0000);
        assert_eq!(inv.virtio_mmio_devices()[0].irq, 48); // SPI 16 + 32
        assert_eq!(inv.virtio_mmio_devices()[1].irq, 49);
        assert_eq!(inv.pl031_rtc.unwrap().region.base, 0x0901_0000);
        assert_eq!(inv.pl031_rtc.unwrap().irq, Some(34));
        assert_eq!(inv.pcie_ecam.unwrap().bus_end, 15);
        assert_eq!(
            inv.chosen.bootargs(),
            b"root=/dev/vda1 rw rootfstype=ext4 console=ttyAMA0"
        );
        assert_eq!(inv.chosen.rng_seed_len, 32);
    }

    #[test]
    fn device_inventory_rejects_overlapping_zero_size_and_missing_irq_virtio() {
        let missing_irq = build_dtb_with_nodes(|strings, structure| {
            let compatible = intern(strings, "compatible");
            let reg = intern(strings, "reg");
            begin_node(structure, "virtio_mmio@a000000");
            property(structure, compatible, b"virtio,mmio\0");
            property(structure, reg, &cells(&[0, 0x0a00_0000, 0, 0x200]));
            end_node(structure);
        });
        assert_eq!(
            parse_device_inventory::<4>(&Blob::parse(&missing_irq).unwrap()),
            Err(Error::MissingProperty)
        );

        let zero_size = build_dtb_with_nodes(|strings, structure| {
            let compatible = intern(strings, "compatible");
            let reg = intern(strings, "reg");
            let interrupts = intern(strings, "interrupts");
            begin_node(structure, "virtio_mmio@a000000");
            property(structure, compatible, b"virtio,mmio\0");
            property(structure, reg, &cells(&[0, 0x0a00_0000, 0, 0]));
            property(structure, interrupts, &cells(&[0, 16, 1]));
            end_node(structure);
        });
        assert_eq!(
            parse_device_inventory::<4>(&Blob::parse(&zero_size).unwrap()),
            Err(Error::ZeroSizedRegion)
        );

        let overlapping = build_dtb_with_nodes(|strings, structure| {
            let compatible = intern(strings, "compatible");
            let reg = intern(strings, "reg");
            let interrupts = intern(strings, "interrupts");
            begin_node(structure, "virtio_mmio@a000000");
            property(structure, compatible, b"virtio,mmio\0");
            property(structure, reg, &cells(&[0, 0x0a00_0000, 0, 0x400]));
            property(structure, interrupts, &cells(&[0, 16, 1]));
            end_node(structure);

            begin_node(structure, "virtio_mmio@a000200");
            property(structure, compatible, b"virtio,mmio\0");
            property(structure, reg, &cells(&[0, 0x0a00_0200, 0, 0x200]));
            property(structure, interrupts, &cells(&[0, 17, 1]));
            end_node(structure);
        });
        assert_eq!(
            parse_device_inventory::<4>(&Blob::parse(&overlapping).unwrap()),
            Err(Error::OverlappingRegion)
        );
    }
}
