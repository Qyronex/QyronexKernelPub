// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Bounded 4 KiB LRU block cache and sector-window abstraction for block devices.

use alloc::vec;
use alloc::vec::Vec;
use kernal_linux_abi::Errno;

pub const BLOCK_SECTOR_SIZE: usize = 512;
pub const CACHE_BLOCK_SIZE: usize = 4096;
pub const SECTORS_PER_CACHE_BLOCK: u64 = (CACHE_BLOCK_SIZE / BLOCK_SECTOR_SIZE) as u64;
pub const DEFAULT_CACHE_BLOCKS: usize = 256;

/// Abstract 512-byte-sector storage backend (real `virtio-blk` hardware or test/mock backing).
pub trait BlockDevice {
    fn total_sectors(&self) -> u64;

    fn block_size(&self) -> u32 {
        BLOCK_SECTOR_SIZE as u32
    }

    fn read_only(&self) -> bool {
        false
    }

    fn read_sectors(&mut self, start_sector: u64, out: &mut [u8]) -> Result<(), Errno>;
    fn write_sectors(&mut self, start_sector: u64, data: &[u8]) -> Result<(), Errno>;
    fn flush(&mut self) -> Result<(), Errno>;
}

/// Bounded sector slice mapping partition-relative sectors onto an underlying [`BlockDevice`].
pub struct PartitionSlice<'a> {
    inner: &'a mut dyn BlockDevice,
    start_sector: u64,
    sector_count: u64,
    force_read_only: bool,
}

impl<'a> PartitionSlice<'a> {
    pub fn new(
        inner: &'a mut dyn BlockDevice,
        start_sector: u64,
        sector_count: u64,
        force_read_only: bool,
    ) -> Result<Self, Errno> {
        let end = start_sector
            .checked_add(sector_count)
            .ok_or(Errno::EINVAL)?;
        if end > inner.total_sectors() {
            return Err(Errno::EINVAL);
        }
        Ok(Self {
            inner,
            start_sector,
            sector_count,
            force_read_only,
        })
    }

    fn map_range(&self, rel_sector: u64, byte_len: usize) -> Result<u64, Errno> {
        if !byte_len.is_multiple_of(BLOCK_SECTOR_SIZE) {
            return Err(Errno::EINVAL);
        }
        let sectors = u64::try_from(byte_len / BLOCK_SECTOR_SIZE).map_err(|_| Errno::EINVAL)?;
        let rel_end = rel_sector.checked_add(sectors).ok_or(Errno::ENOSPC)?;
        if rel_end > self.sector_count {
            return Err(Errno::ENOSPC);
        }
        self.start_sector
            .checked_add(rel_sector)
            .ok_or(Errno::EINVAL)
    }
}

impl BlockDevice for PartitionSlice<'_> {
    fn total_sectors(&self) -> u64 {
        self.sector_count
    }

    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn read_only(&self) -> bool {
        self.force_read_only || self.inner.read_only()
    }

    fn read_sectors(&mut self, start_sector: u64, out: &mut [u8]) -> Result<(), Errno> {
        if out.is_empty() {
            return Ok(());
        }
        let phys = self.map_range(start_sector, out.len())?;
        self.inner.read_sectors(phys, out)
    }

    fn write_sectors(&mut self, start_sector: u64, data: &[u8]) -> Result<(), Errno> {
        if self.read_only() {
            return Err(Errno::EROFS);
        }
        if data.is_empty() {
            return Ok(());
        }
        let phys = self.map_range(start_sector, data.len())?;
        self.inner.write_sectors(phys, data)
    }

    fn flush(&mut self) -> Result<(), Errno> {
        self.inner.flush()
    }
}

#[derive(Clone)]
struct CacheSlot {
    block_idx: u64,
    last_used_tick: u64,
    valid: bool,
    dirty: bool,
    data: [u8; CACHE_BLOCK_SIZE],
}

impl CacheSlot {
    const EMPTY: Self = Self {
        block_idx: 0,
        last_used_tick: 0,
        valid: false,
        dirty: false,
        data: [0; CACHE_BLOCK_SIZE],
    };
}

/// Bounded writeback 4 KiB LRU block cache over one contiguous sector span of a [`BlockDevice`].
pub struct CachedBlockDevice {
    start_sector: u64,
    sector_count: u64,
    read_only: bool,
    slots: Vec<CacheSlot>,
    tick: u64,
    hits: u64,
    misses: u64,
    writebacks: u64,
}

impl CachedBlockDevice {
    pub fn new(
        start_sector: u64,
        sector_count: u64,
        read_only: bool,
        capacity_blocks: usize,
    ) -> Self {
        let cap = capacity_blocks.max(4);
        Self {
            start_sector,
            sector_count,
            read_only,
            slots: vec![CacheSlot::EMPTY; cap],
            tick: 0,
            hits: 0,
            misses: 0,
            writebacks: 0,
        }
    }

    pub const fn total_sectors(&self) -> u64 {
        self.sector_count
    }

    pub const fn total_bytes(&self) -> u64 {
        self.sector_count.saturating_mul(BLOCK_SECTOR_SIZE as u64)
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    pub fn set_read_only(&mut self, read_only: bool) {
        self.read_only = read_only;
    }

    pub const fn stats(&self) -> (u64, u64, u64) {
        (self.hits, self.misses, self.writebacks)
    }

    pub fn invalidate_all(&mut self) {
        for slot in &mut self.slots {
            slot.valid = false;
            slot.dirty = false;
        }
    }

    fn block_sector_range(&self, block_idx: u64) -> Result<(u64, usize), Errno> {
        let rel_sector = block_idx
            .checked_mul(SECTORS_PER_CACHE_BLOCK)
            .ok_or(Errno::EINVAL)?;
        if rel_sector >= self.sector_count {
            return Err(Errno::ENOSPC);
        }
        let avail_sectors = (self.sector_count - rel_sector).min(SECTORS_PER_CACHE_BLOCK) as usize;
        let abs_sector = self
            .start_sector
            .checked_add(rel_sector)
            .ok_or(Errno::EINVAL)?;
        Ok((abs_sector, avail_sectors))
    }

    fn flush_slot(&mut self, dev: &mut dyn BlockDevice, idx: usize) -> Result<(), Errno> {
        if !self.slots[idx].valid || !self.slots[idx].dirty {
            return Ok(());
        }
        if self.read_only || dev.read_only() {
            return Err(Errno::EROFS);
        }
        let (abs_sector, avail_sectors) = self.block_sector_range(self.slots[idx].block_idx)?;
        let byte_len = avail_sectors * BLOCK_SECTOR_SIZE;
        dev.write_sectors(abs_sector, &self.slots[idx].data[..byte_len])?;
        self.slots[idx].dirty = false;
        self.writebacks = self.writebacks.saturating_add(1);
        Ok(())
    }

    fn acquire_slot(
        &mut self,
        dev: &mut dyn BlockDevice,
        block_idx: u64,
        populate_on_miss: bool,
    ) -> Result<usize, Errno> {
        self.tick = self.tick.saturating_add(1);
        let now = self.tick;

        if let Some(pos) = self
            .slots
            .iter()
            .position(|s| s.valid && s.block_idx == block_idx)
        {
            self.hits = self.hits.saturating_add(1);
            self.slots[pos].last_used_tick = now;
            return Ok(pos);
        }

        self.misses = self.misses.saturating_add(1);
        let (abs_sector, avail_sectors) = self.block_sector_range(block_idx)?;

        let victim = if let Some(free) = self.slots.iter().position(|s| !s.valid) {
            free
        } else {
            // Prefer evicting clean LRU lines first, otherwise oldest dirty line.
            let mut best_clean = None;
            let mut best_any = 0usize;
            for (i, slot) in self.slots.iter().enumerate() {
                if slot.last_used_tick < self.slots[best_any].last_used_tick {
                    best_any = i;
                }
                if !slot.dirty {
                    match best_clean {
                        None => best_clean = Some(i),
                        Some(prev) if slot.last_used_tick < self.slots[prev].last_used_tick => {
                            best_clean = Some(i);
                        }
                        _ => {}
                    }
                }
            }
            let chosen = best_clean.unwrap_or(best_any);
            if self.slots[chosen].dirty {
                self.flush_slot(dev, chosen)?;
            }
            chosen
        };

        self.slots[victim].valid = false;
        self.slots[victim].dirty = false;
        if populate_on_miss {
            let byte_len = avail_sectors * BLOCK_SECTOR_SIZE;
            if avail_sectors < SECTORS_PER_CACHE_BLOCK as usize {
                self.slots[victim].data[byte_len..].fill(0);
            }
            dev.read_sectors(abs_sector, &mut self.slots[victim].data[..byte_len])?;
        } else {
            self.slots[victim].data.fill(0);
        }
        self.slots[victim].block_idx = block_idx;
        self.slots[victim].last_used_tick = now;
        self.slots[victim].valid = true;
        Ok(victim)
    }

    pub fn read_block(
        &mut self,
        dev: &mut dyn BlockDevice,
        block_idx: u64,
        out: &mut [u8; CACHE_BLOCK_SIZE],
    ) -> Result<(), Errno> {
        let slot = self.acquire_slot(dev, block_idx, true)?;
        out.copy_from_slice(&self.slots[slot].data);
        Ok(())
    }

    pub fn write_block(
        &mut self,
        dev: &mut dyn BlockDevice,
        block_idx: u64,
        data: &[u8; CACHE_BLOCK_SIZE],
    ) -> Result<(), Errno> {
        if self.read_only || dev.read_only() {
            return Err(Errno::EROFS);
        }
        let slot = self.acquire_slot(dev, block_idx, false)?;
        self.slots[slot].data.copy_from_slice(data);
        self.slots[slot].dirty = true;
        Ok(())
    }

    /// Reads arbitrary byte range starting at `byte_offset` within this partition/device.
    pub fn read_bytes(
        &mut self,
        dev: &mut dyn BlockDevice,
        byte_offset: u64,
        out: &mut [u8],
    ) -> Result<(), Errno> {
        if out.is_empty() {
            return Ok(());
        }
        let len_u64 = u64::try_from(out.len()).map_err(|_| Errno::EINVAL)?;
        let end = byte_offset.checked_add(len_u64).ok_or(Errno::ENOSPC)?;
        if end > self.total_bytes() {
            return Err(Errno::ENOSPC);
        }

        let mut cursor = byte_offset;
        let mut written = 0usize;
        while written < out.len() {
            let block_idx = cursor / (CACHE_BLOCK_SIZE as u64);
            let inner_off = (cursor % (CACHE_BLOCK_SIZE as u64)) as usize;
            let take = (CACHE_BLOCK_SIZE - inner_off).min(out.len() - written);
            let slot = self.acquire_slot(dev, block_idx, true)?;
            out[written..written + take]
                .copy_from_slice(&self.slots[slot].data[inner_off..inner_off + take]);
            cursor += take as u64;
            written += take;
        }
        Ok(())
    }

    /// Writes arbitrary byte range starting at `byte_offset` with read-modify-write on partial blocks.
    pub fn write_bytes(
        &mut self,
        dev: &mut dyn BlockDevice,
        byte_offset: u64,
        data: &[u8],
    ) -> Result<(), Errno> {
        if self.read_only || dev.read_only() {
            return Err(Errno::EROFS);
        }
        if data.is_empty() {
            return Ok(());
        }
        let len_u64 = u64::try_from(data.len()).map_err(|_| Errno::EINVAL)?;
        let end = byte_offset.checked_add(len_u64).ok_or(Errno::ENOSPC)?;
        if end > self.total_bytes() {
            return Err(Errno::ENOSPC);
        }

        let mut cursor = byte_offset;
        let mut consumed = 0usize;
        while consumed < data.len() {
            let block_idx = cursor / (CACHE_BLOCK_SIZE as u64);
            let inner_off = (cursor % (CACHE_BLOCK_SIZE as u64)) as usize;
            let take = (CACHE_BLOCK_SIZE - inner_off).min(data.len() - consumed);
            let full_block_overwrite = inner_off == 0 && take == CACHE_BLOCK_SIZE;
            let slot = self.acquire_slot(dev, block_idx, !full_block_overwrite)?;
            self.slots[slot].data[inner_off..inner_off + take]
                .copy_from_slice(&data[consumed..consumed + take]);
            self.slots[slot].dirty = true;
            cursor += take as u64;
            consumed += take;
        }
        Ok(())
    }

    /// Writes back all dirty cache blocks in ascending block order and flushes the device.
    pub fn sync(&mut self, dev: &mut dyn BlockDevice) -> Result<(), Errno> {
        if self.read_only || dev.read_only() {
            return Ok(());
        }
        let mut dirty_indices: Vec<(u64, usize)> = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| (s.valid && s.dirty).then_some((s.block_idx, i)))
            .collect();
        dirty_indices.sort_unstable_by_key(|&(block_idx, _)| block_idx);
        for (_, idx) in dirty_indices {
            self.flush_slot(dev, idx)?;
        }
        dev.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemBlockDev {
        data: Vec<u8>,
        read_only: bool,
        reads: usize,
        writes: usize,
        flushes: usize,
    }

    impl MemBlockDev {
        fn new(sectors: usize) -> Self {
            Self {
                data: vec![0u8; sectors * BLOCK_SECTOR_SIZE],
                read_only: false,
                reads: 0,
                writes: 0,
                flushes: 0,
            }
        }
    }

    impl BlockDevice for MemBlockDev {
        fn total_sectors(&self) -> u64 {
            (self.data.len() / BLOCK_SECTOR_SIZE) as u64
        }

        fn read_only(&self) -> bool {
            self.read_only
        }

        fn read_sectors(&mut self, start_sector: u64, out: &mut [u8]) -> Result<(), Errno> {
            assert!(out.len().is_multiple_of(BLOCK_SECTOR_SIZE));
            let off = usize::try_from(start_sector).unwrap() * BLOCK_SECTOR_SIZE;
            let end = off.checked_add(out.len()).ok_or(Errno::ENOSPC)?;
            if end > self.data.len() {
                return Err(Errno::ENOSPC);
            }
            out.copy_from_slice(&self.data[off..end]);
            self.reads += 1;
            Ok(())
        }

        fn write_sectors(&mut self, start_sector: u64, data: &[u8]) -> Result<(), Errno> {
            if self.read_only {
                return Err(Errno::EROFS);
            }
            assert!(data.len().is_multiple_of(BLOCK_SECTOR_SIZE));
            let off = usize::try_from(start_sector).unwrap() * BLOCK_SECTOR_SIZE;
            let end = off.checked_add(data.len()).ok_or(Errno::ENOSPC)?;
            if end > self.data.len() {
                return Err(Errno::ENOSPC);
            }
            self.data[off..end].copy_from_slice(data);
            self.writes += 1;
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Errno> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn caches_hits_evicts_dirty_lru_and_handles_unaligned_bytes() {
        let mut dev = MemBlockDev::new(64);
        // Write across 4 blocks cache limit (cap=4) with unaligned byte offsets.
        let mut cache = CachedBlockDevice::new(8, 45, false, 4);

        let payload: Vec<u8> = (0..5000).map(|i| ((i * 13 + 5) & 0xff) as u8).collect();
        cache
            .write_bytes(&mut dev, 3000, &payload)
            .expect("unaligned cross-block write");

        // Read back from cache immediately: hits without extra underlying reads.
        let mut got = vec![0u8; 5000];
        let reads_before = dev.reads;
        cache
            .read_bytes(&mut dev, 3000, &mut got)
            .expect("cached read");
        assert_eq!(got, payload);
        assert_eq!(dev.reads, reads_before);

        // Force eviction by writing 5 more blocks, then sync remaining dirty blocks.
        let zeroes = [0xaa; CACHE_BLOCK_SIZE];
        for blk in 2..6 {
            cache.write_block(&mut dev, blk, &zeroes).unwrap();
        }
        cache.sync(&mut dev).expect("sync");
        assert_eq!(dev.flushes, 1);

        // Re-read payload cleanly from underlying storage into a fresh cold cache.
        let mut cold = CachedBlockDevice::new(8, 45, false, 4);
        let mut cold_got = vec![0u8; 5000];
        cold.read_bytes(&mut dev, 3000, &mut cold_got).unwrap();
        assert_eq!(cold_got, payload);
    }

    #[test]
    fn partition_slice_bounds_sectors_and_ro() {
        let mut dev = MemBlockDev::new(32);
        let mut slice = PartitionSlice::new(&mut dev, 4, 8, true).unwrap();
        assert_eq!(slice.total_sectors(), 8);
        assert!(slice.read_only());
        assert_eq!(slice.write_sectors(0, &[1u8; 512]), Err(Errno::EROFS));
        let mut buf = [0u8; 512];
        assert_eq!(slice.read_sectors(8, &mut buf), Err(Errno::ENOSPC));
    }
}
