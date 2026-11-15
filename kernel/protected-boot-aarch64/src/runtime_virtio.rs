// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
use kernal_fdt_aarch64::VirtioMmioInfo;
use kernal_fdt_aarch64::{ChosenBootInfo, MmioRegion};
#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
use kernal_paging::PAGE_SIZE;

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
use crate::runtime_initrd::{AliasPlanError, PageSpan};

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_arch_aarch64::TranslationAccess;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_fdt_aarch64::parse_device_inventory;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_page_table_aarch64::{Mapper, MemoryType};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_paging::MapFlags;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use crate::runtime_initrd::{
    ProtectedInitrd, ProtectedInitrdError, invalidate_after_table_mutation, map_pages_with_type,
    unmap_read_only_pages, with_mapped_qemu_dtb,
};

pub const MAX_PROTECTED_VIRTIO_MMIO: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedVirtioMmioEntry {
    pub physical: MmioRegion,
    pub virtual_region: MmioRegion,
    pub irq: u32,
    pub enabled: bool,
}

impl ProtectedVirtioMmioEntry {
    pub const EMPTY: Self = Self {
        physical: MmioRegion { base: 0, size: 0 },
        virtual_region: MmioRegion { base: 0, size: 0 },
        irq: 0,
        enabled: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedVirtioMmioMap {
    entries: [ProtectedVirtioMmioEntry; MAX_PROTECTED_VIRTIO_MMIO],
    count: usize,
    chosen: ChosenBootInfo,
    virtual_page_end: u64,
}

impl ProtectedVirtioMmioMap {
    pub const fn empty() -> Self {
        Self {
            entries: [ProtectedVirtioMmioEntry::EMPTY; MAX_PROTECTED_VIRTIO_MMIO],
            count: 0,
            chosen: ChosenBootInfo::empty(),
            virtual_page_end: 0,
        }
    }

    pub fn entries(&self) -> &[ProtectedVirtioMmioEntry] {
        &self.entries[..self.count]
    }

    pub const fn chosen(&self) -> &ChosenBootInfo {
        &self.chosen
    }

    pub fn bootargs(&self) -> &[u8] {
        self.chosen.bootargs()
    }

    pub const fn virtual_page_end(&self) -> u64 {
        self.virtual_page_end
    }
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PlannedSpan {
    physical: PageSpan,
    virtual_start: u64,
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
impl PlannedSpan {
    const EMPTY: Self = Self {
        physical: PageSpan {
            start: 0,
            end: 0,
            offset: 0,
        },
        virtual_start: 0,
    };
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CoalescedVirtioPlan {
    spans: [PlannedSpan; MAX_PROTECTED_VIRTIO_MMIO],
    span_count: usize,
    virtual_page_end: u64,
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
fn plan_coalesced_virtio_mmio(
    devices: &[VirtioMmioInfo],
    chosen: ChosenBootInfo,
    alias_base: u64,
) -> Result<(CoalescedVirtioPlan, ProtectedVirtioMmioMap), AliasPlanError> {
    if alias_base & (PAGE_SIZE - 1) != 0 || alias_base >> 48 != 0xffff {
        return Err(AliasPlanError::InvalidLayout);
    }
    if devices.len() > MAX_PROTECTED_VIRTIO_MMIO {
        return Err(AliasPlanError::MmioPlanMismatch);
    }

    let mut raw_spans = [PageSpan {
        start: 0,
        end: 0,
        offset: 0,
    }; MAX_PROTECTED_VIRTIO_MMIO];
    let mut raw_count = 0usize;
    for dev in devices.iter().copied() {
        if !dev.enabled {
            continue;
        }
        raw_spans[raw_count] = PageSpan::from_data(dev.region.base, dev.region.size)?;
        raw_count += 1;
    }

    // Insertion-sort enabled physical page spans so overlapping/adjacent MMIO apertures coalesce
    // cleanly into disjoint physical page ranges (QEMU virt packs 8 slots per 4 KiB page).
    for idx in 1..raw_count {
        let key = raw_spans[idx];
        let mut pos = idx;
        while pos > 0
            && (raw_spans[pos - 1].start > key.start
                || (raw_spans[pos - 1].start == key.start && raw_spans[pos - 1].end > key.end))
        {
            raw_spans[pos] = raw_spans[pos - 1];
            pos -= 1;
        }
        raw_spans[pos] = key;
    }

    let mut plan = CoalescedVirtioPlan {
        spans: [PlannedSpan::EMPTY; MAX_PROTECTED_VIRTIO_MMIO],
        span_count: 0,
        virtual_page_end: alias_base,
    };

    for span in raw_spans[..raw_count].iter().copied() {
        if let Some(last) = plan
            .span_count
            .checked_sub(1)
            .map(|i| &mut plan.spans[i].physical)
            && span.start <= last.end
        {
            if span.end > last.end {
                last.end = span.end;
            }
            continue;
        }
        plan.spans[plan.span_count] = PlannedSpan {
            physical: PageSpan {
                start: span.start,
                end: span.end,
                offset: 0,
            },
            virtual_start: 0,
        };
        plan.span_count += 1;
    }

    let mut cursor = alias_base;
    for span in &mut plan.spans[..plan.span_count] {
        let len = span.physical.len();
        let next = cursor
            .checked_add(len)
            .ok_or(AliasPlanError::AddressOverflow)?;
        if ((next - 1) >> 48) != 0xffff {
            return Err(AliasPlanError::InvalidLayout);
        }
        span.virtual_start = cursor;
        cursor = next;
    }
    plan.virtual_page_end = cursor;

    let mut map = ProtectedVirtioMmioMap {
        entries: [ProtectedVirtioMmioEntry::EMPTY; MAX_PROTECTED_VIRTIO_MMIO],
        count: devices.len(),
        chosen,
        virtual_page_end: cursor,
    };

    for (dst, dev) in map.entries[..devices.len()]
        .iter_mut()
        .zip(devices.iter().copied())
    {
        if !dev.enabled {
            *dst = ProtectedVirtioMmioEntry {
                physical: dev.region,
                virtual_region: MmioRegion { base: 0, size: 0 },
                irq: dev.irq,
                enabled: false,
            };
            continue;
        }
        let dev_end = dev
            .region
            .base
            .checked_add(dev.region.size)
            .ok_or(AliasPlanError::AddressOverflow)?;
        let mut mapped_virtual = None;
        for planned in plan.spans[..plan.span_count].iter().copied() {
            if dev.region.base >= planned.physical.start && dev_end <= planned.physical.end {
                let offset = dev.region.base - planned.physical.start;
                let virt_base = planned
                    .virtual_start
                    .checked_add(offset)
                    .ok_or(AliasPlanError::AddressOverflow)?;
                mapped_virtual = Some(MmioRegion {
                    base: virt_base,
                    size: dev.region.size,
                });
                break;
            }
        }
        let virtual_region = mapped_virtual.ok_or(AliasPlanError::MmioPlanMismatch)?;
        *dst = ProtectedVirtioMmioEntry {
            physical: dev.region,
            virtual_region,
            irq: dev.irq,
            enabled: true,
        };
    }

    Ok((plan, map))
}

/// Discovers every QEMU VirtIO-MMIO aperture and `/chosen` metadata from the protected DTB view
/// and permanently maps each unique enabled MMIO page as NX/supervisor-only `DeviceNgnre` memory
/// starting immediately after `initrd`.
///
/// # Safety
/// - Must run in the one-shot protected BSP callback while `backend` holds the exclusive
///   `RuntimeTablePool` cursor and all secondary PEs are held with IRQ delivery masked.
/// - `initrd` must be the exact mapping returned by `map_qemu_initrd_high_alias`.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn map_qemu_virtio_mmio_high_aliases(
    backend: &mut crate::runtime_table::RuntimeTablePool,
    initrd: ProtectedInitrd,
) -> Result<ProtectedVirtioMmioMap, ProtectedInitrdError> {
    if !crate::runtime::runtime_table_pool_claim_ready() {
        return Err(ProtectedInitrdError::RuntimeNotReady);
    }

    let state = crate::boot_state();
    let alias_base = initrd.virtual_page_end()?;
    let inventory = with_mapped_qemu_dtb(backend, alias_base, |blob| {
        parse_device_inventory::<MAX_PROTECTED_VIRTIO_MMIO>(blob)
            .map_err(ProtectedInitrdError::DeviceInventory)
    })?;

    let (plan, map) = plan_coalesced_virtio_mmio(
        inventory.virtio_mmio_devices(),
        inventory.chosen,
        alias_base,
    )
    .map_err(|_| ProtectedInitrdError::AliasPlan)?;

    let spans = &plan.spans[..plan.span_count];
    let mut mapped_spans = 0usize;
    let map_result = (|| -> Result<(), ProtectedInitrdError> {
        for planned in spans.iter().copied() {
            {
                let mut mapper = Mapper::new(backend, state.root_table)?;
                map_pages_with_type(
                    &mut mapper,
                    planned.virtual_start,
                    planned.physical,
                    MapFlags::WRITE,
                    MemoryType::DeviceNgnre,
                )?;
            }
            mapped_spans += 1;
        }
        Ok(())
    })();

    // SAFETY: invalidate after mapping or rollback before exposing the virtual apertures.
    unsafe { invalidate_after_table_mutation() };
    if let Err(error) = map_result {
        let mut mapper = Mapper::new(backend, state.root_table)?;
        for planned in spans[..mapped_spans].iter().copied() {
            let _ = unmap_read_only_pages(
                &mut mapper,
                planned.virtual_start,
                planned.physical.start,
                planned.physical.end,
            );
        }
        // SAFETY: broadcast invalidation after rollback.
        unsafe { invalidate_after_table_mutation() };
        return Err(error);
    }

    let verify_result = (|| -> Result<(), ProtectedInitrdError> {
        let mapper = Mapper::new(backend, state.root_table)?;
        for planned in spans.iter().copied() {
            let first = mapper
                .translate(planned.virtual_start)
                .map_err(ProtectedInitrdError::PageTable)?;
            if first != planned.physical.start {
                return Err(ProtectedInitrdError::TranslationProof);
            }
            let last_virtual = planned
                .virtual_start
                .checked_add(planned.physical.len() - PAGE_SIZE)
                .ok_or(ProtectedInitrdError::AliasPlan)?;
            let last_physical = planned.physical.end - PAGE_SIZE;
            let last = mapper
                .translate(last_virtual)
                .map_err(ProtectedInitrdError::PageTable)?;
            if last != last_physical {
                return Err(ProtectedInitrdError::TranslationProof);
            }
            // SAFETY: translation address probe only checks page-table permissions without issuing
            // an MMIO bus transaction.
            let write_probe = unsafe {
                kernal_arch_aarch64::probe_el1_translation(
                    planned.virtual_start,
                    TranslationAccess::Write,
                )
            };
            if write_probe.faulted() {
                return Err(ProtectedInitrdError::TranslationProof);
            }
        }
        Ok(())
    })();

    if let Err(error) = verify_result {
        let mut mapper = Mapper::new(backend, state.root_table)?;
        for planned in spans.iter().copied() {
            let _ = unmap_read_only_pages(
                &mut mapper,
                planned.virtual_start,
                planned.physical.start,
                planned.physical.end,
            );
        }
        // SAFETY: broadcast invalidation after verification rollback.
        unsafe { invalidate_after_table_mutation() };
        return Err(error);
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesces_32_qemu_virtio_mmio_slots_into_four_contiguous_pages() {
        let mut devices = [VirtioMmioInfo {
            region: MmioRegion { base: 0, size: 0 },
            irq: 0,
            enabled: false,
        }; 32];
        for (i, slot) in devices.iter_mut().enumerate() {
            *slot = VirtioMmioInfo {
                region: MmioRegion {
                    base: 0x0a00_0000 + (i as u64) * 0x200,
                    size: 0x200,
                },
                irq: 16 + (i as u32),
                enabled: true,
            };
        }
        let alias_base = 0xffff_ffff_8050_0000;
        let (plan, map) = plan_coalesced_virtio_mmio(&devices, ChosenBootInfo::empty(), alias_base)
            .expect("plan should coalesce");

        assert_eq!(plan.span_count, 1);
        assert_eq!(plan.spans[0].physical.start, 0x0a00_0000);
        assert_eq!(plan.spans[0].physical.end, 0x0a00_4000);
        assert_eq!(plan.spans[0].virtual_start, alias_base);
        assert_eq!(plan.virtual_page_end, alias_base + 0x4000);

        assert_eq!(map.entries().len(), 32);
        for (i, entry) in map.entries().iter().enumerate() {
            assert!(entry.enabled);
            assert_eq!(entry.physical.base, 0x0a00_0000 + (i as u64) * 0x200);
            assert_eq!(entry.virtual_region.base, alias_base + (i as u64) * 0x200);
            assert_eq!(entry.virtual_region.size, 0x200);
            assert_eq!(entry.irq, 16 + (i as u32));
        }
    }

    #[test]
    fn handles_unsorted_discontiguous_and_disabled_slots() {
        let devices = [
            VirtioMmioInfo {
                region: MmioRegion {
                    base: 0x0a00_3200,
                    size: 0x200,
                },
                irq: 41,
                enabled: true,
            },
            VirtioMmioInfo {
                region: MmioRegion {
                    base: 0x0a00_8000,
                    size: 0x200,
                },
                irq: 42,
                enabled: false,
            },
            VirtioMmioInfo {
                region: MmioRegion {
                    base: 0x0a00_0e00,
                    size: 0x400,
                },
                irq: 23,
                enabled: true,
            },
        ];
        let alias_base = 0xffff_ffff_8100_0000;
        let (plan, map) = plan_coalesced_virtio_mmio(&devices, ChosenBootInfo::empty(), alias_base)
            .expect("discontiguous plan should succeed");

        // Slot 2 spans pages 0x0a00_0000..0x0a00_2000; slot 0 lives on 0x0a00_3000..0x0a00_4000.
        assert_eq!(plan.span_count, 2);
        assert_eq!(plan.spans[0].physical.start, 0x0a00_0000);
        assert_eq!(plan.spans[0].physical.end, 0x0a00_2000);
        assert_eq!(plan.spans[0].virtual_start, alias_base);
        assert_eq!(plan.spans[1].physical.start, 0x0a00_3000);
        assert_eq!(plan.spans[1].physical.end, 0x0a00_4000);
        assert_eq!(plan.spans[1].virtual_start, alias_base + 0x2000);

        let entries = map.entries();
        assert_eq!(entries[0].virtual_region.base, alias_base + 0x2200);
        assert!(!entries[1].enabled);
        assert_eq!(entries[1].virtual_region, MmioRegion { base: 0, size: 0 });
        assert_eq!(entries[2].virtual_region.base, alias_base + 0x0e00);
        assert_eq!(entries[2].virtual_region.size, 0x400);
    }
}
