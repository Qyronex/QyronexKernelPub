// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Bounded MBR and GPT (`EFI PART`) partition table discovery over [`BlockDevice`].

use kernal_linux_abi::Errno;

use crate::block_cache::{BLOCK_SECTOR_SIZE, BlockDevice};

pub const MAX_PARTITIONS: usize = 16;

const MBR_SIGNATURE_OFFSET: usize = 510;
const MBR_TABLE_OFFSET: usize = 446;
const MBR_ENTRY_SIZE: usize = 16;
const MBR_PART_TYPE_GPT_PROTECTIVE: u8 = 0xee;
const GPT_SIGNATURE: [u8; 8] = *b"EFI PART";
const MAX_GPT_ENTRIES_SCAN: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartitionEntry {
    pub number: u8,
    pub start_sector: u64,
    pub sector_count: u64,
    pub bootable: bool,
    pub mbr_type: u8,
    pub type_guid: [u8; 16],
    pub is_gpt: bool,
}

impl PartitionEntry {
    pub const EMPTY: Self = Self {
        number: 0,
        start_sector: 0,
        sector_count: 0,
        bootable: false,
        mbr_type: 0,
        type_guid: [0; 16],
        is_gpt: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartitionTable {
    pub entries: [PartitionEntry; MAX_PARTITIONS],
    pub count: usize,
    pub is_gpt: bool,
}

impl PartitionTable {
    pub const EMPTY: Self = Self {
        entries: [PartitionEntry::EMPTY; MAX_PARTITIONS],
        count: 0,
        is_gpt: false,
    };

    pub fn slice(&self) -> &[PartitionEntry] {
        &self.entries[..self.count]
    }

    pub fn by_number(&self, number: u8) -> Option<&PartitionEntry> {
        self.slice().iter().find(|entry| entry.number == number)
    }
}

/// Standard IEEE 802.3 CRC32 (reflected polynomial `0xedb8_8320`) used in GPT headers/arrays.
pub fn crc32_ieee_update(mut crc: u32, data: &[u8]) -> u32 {
    crc = !crc;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

pub fn crc32_ieee(data: &[u8]) -> u32 {
    crc32_ieee_update(0, data)
}

fn read_le_u32(src: &[u8]) -> u32 {
    u32::from_le_bytes([src[0], src[1], src[2], src[3]])
}

fn read_le_u64(src: &[u8]) -> u64 {
    u64::from_le_bytes([
        src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
    ])
}

/// Discovers MBR or GPT partitions on `dev`. Raw filesystems without an MBR/GPT signature return
/// an empty [`PartitionTable`] cleanly so `/dev/vda` whole-disk mounts still work.
pub fn parse_partitions(dev: &mut dyn BlockDevice) -> Result<PartitionTable, Errno> {
    let total_sectors = dev.total_sectors();
    if total_sectors == 0 {
        return Ok(PartitionTable::EMPTY);
    }

    let mut lba0 = [0u8; BLOCK_SECTOR_SIZE];
    dev.read_sectors(0, &mut lba0)?;
    if lba0[MBR_SIGNATURE_OFFSET] != 0x55 || lba0[MBR_SIGNATURE_OFFSET + 1] != 0xaa {
        return Ok(PartitionTable::EMPTY);
    }

    let mut has_protective_gpt = false;
    let mut mbr_table = PartitionTable::EMPTY;

    for slot in 0..4 {
        let base = MBR_TABLE_OFFSET + slot * MBR_ENTRY_SIZE;
        let entry = &lba0[base..base + MBR_ENTRY_SIZE];
        let part_type = entry[4];
        if part_type == 0 {
            continue;
        }
        if part_type == MBR_PART_TYPE_GPT_PROTECTIVE {
            has_protective_gpt = true;
            continue;
        }
        // Ignore extended container descriptors cleanly; primary partitions suffice.
        if matches!(part_type, 0x05 | 0x0f | 0x85) {
            continue;
        }
        let start_lba = u64::from(read_le_u32(&entry[8..12]));
        let sector_count = u64::from(read_le_u32(&entry[12..16]));
        if start_lba == 0 || sector_count == 0 {
            continue;
        }
        let Some(end) = start_lba.checked_add(sector_count) else {
            continue;
        };
        if end > total_sectors {
            continue;
        }
        if mbr_table.count < MAX_PARTITIONS {
            mbr_table.entries[mbr_table.count] = PartitionEntry {
                number: (slot as u8) + 1,
                start_sector: start_lba,
                sector_count,
                bootable: entry[0] == 0x80,
                mbr_type: part_type,
                type_guid: [0; 16],
                is_gpt: false,
            };
            mbr_table.count += 1;
        }
    }

    if has_protective_gpt && total_sectors >= 34 {
        if let Some(gpt) = try_parse_gpt(dev, total_sectors)? {
            return Ok(gpt);
        }
        return Err(Errno::EIO);
    }

    Ok(mbr_table)
}

fn try_parse_gpt(
    dev: &mut dyn BlockDevice,
    total_sectors: u64,
) -> Result<Option<PartitionTable>, Errno> {
    let mut lba1 = [0u8; BLOCK_SECTOR_SIZE];
    dev.read_sectors(1, &mut lba1)?;
    if lba1[..8] != GPT_SIGNATURE {
        return Ok(None);
    }

    let header_size = read_le_u32(&lba1[12..16]) as usize;
    if !(92..=BLOCK_SECTOR_SIZE).contains(&header_size) {
        return Ok(None);
    }
    let expected_hdr_crc = read_le_u32(&lba1[16..20]);
    let mut hdr_copy = [0u8; BLOCK_SECTOR_SIZE];
    hdr_copy[..header_size].copy_from_slice(&lba1[..header_size]);
    hdr_copy[16..20].fill(0);
    if crc32_ieee(&hdr_copy[..header_size]) != expected_hdr_crc {
        return Ok(None);
    }

    let my_lba = read_le_u64(&lba1[24..32]);
    let first_usable = read_le_u64(&lba1[40..48]);
    let last_usable = read_le_u64(&lba1[48..56]);
    let part_entry_lba = read_le_u64(&lba1[72..80]);
    let num_entries = read_le_u32(&lba1[80..84]) as usize;
    let entry_size = read_le_u32(&lba1[84..88]) as usize;
    let expected_array_crc = read_le_u32(&lba1[88..92]);

    if my_lba != 1
        || part_entry_lba < 2
        || first_usable > last_usable
        || last_usable >= total_sectors
        || entry_size < 128
        || !entry_size.is_power_of_two()
        || entry_size > BLOCK_SECTOR_SIZE
        || num_entries == 0
        || num_entries > MAX_GPT_ENTRIES_SCAN
    {
        return Ok(None);
    }

    let total_array_bytes = num_entries.checked_mul(entry_size).ok_or(Errno::EINVAL)?;
    let array_sectors =
        u64::try_from(total_array_bytes.div_ceil(BLOCK_SECTOR_SIZE)).map_err(|_| Errno::EINVAL)?;
    let array_end = part_entry_lba
        .checked_add(array_sectors)
        .ok_or(Errno::EINVAL)?;
    if array_end > total_sectors {
        return Ok(None);
    }

    let mut table = PartitionTable {
        entries: [PartitionEntry::EMPTY; MAX_PARTITIONS],
        count: 0,
        is_gpt: true,
    };

    let entries_per_sector = BLOCK_SECTOR_SIZE / entry_size;
    let mut computed_crc = 0u32;
    let mut entry_idx = 0usize;
    let mut sector_buf = [0u8; BLOCK_SECTOR_SIZE];

    for sec_offset in 0..array_sectors {
        dev.read_sectors(part_entry_lba + sec_offset, &mut sector_buf)?;
        let remaining_bytes = total_array_bytes - (sec_offset as usize) * BLOCK_SECTOR_SIZE;
        let used_in_sec = remaining_bytes.min(BLOCK_SECTOR_SIZE);
        computed_crc = crc32_ieee_update(computed_crc, &sector_buf[..used_in_sec]);

        for slot_in_sec in 0..entries_per_sector {
            if entry_idx >= num_entries {
                break;
            }
            let off = slot_in_sec * entry_size;
            let raw = &sector_buf[off..off + entry_size];
            let mut type_guid = [0u8; 16];
            type_guid.copy_from_slice(&raw[..16]);
            if type_guid != [0u8; 16] {
                let first_lba = read_le_u64(&raw[32..40]);
                let last_lba = read_le_u64(&raw[40..48]);
                if first_lba >= first_usable
                    && last_lba <= last_usable
                    && last_lba >= first_lba
                    && entry_idx < MAX_PARTITIONS
                    && table.count < MAX_PARTITIONS
                {
                    let count = last_lba - first_lba + 1;
                    table.entries[table.count] = PartitionEntry {
                        number: (entry_idx as u8) + 1,
                        start_sector: first_lba,
                        sector_count: count,
                        bootable: (read_le_u64(&raw[48..56]) & 0x4) != 0,
                        mbr_type: 0,
                        type_guid,
                        is_gpt: true,
                    };
                    table.count += 1;
                }
            }
            entry_idx += 1;
        }
    }

    if computed_crc != expected_array_crc {
        return Ok(None);
    }

    Ok(Some(table))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    struct VecDisk(Vec<u8>);

    impl BlockDevice for VecDisk {
        fn total_sectors(&self) -> u64 {
            (self.0.len() / BLOCK_SECTOR_SIZE) as u64
        }

        fn read_sectors(&mut self, start_sector: u64, out: &mut [u8]) -> Result<(), Errno> {
            let off = (start_sector as usize) * BLOCK_SECTOR_SIZE;
            out.copy_from_slice(&self.0[off..off + out.len()]);
            Ok(())
        }

        fn write_sectors(&mut self, _: u64, _: &[u8]) -> Result<(), Errno> {
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Errno> {
            Ok(())
        }
    }

    #[test]
    fn empty_mbr_yields_no_partitions_for_raw_superblock() {
        let mut disk = VecDisk(vec![0u8; 128 * BLOCK_SECTOR_SIZE]);
        let table = parse_partitions(&mut disk).expect("raw disk parses empty table");
        assert_eq!(table.count, 0);
        assert!(!table.is_gpt);
    }

    #[test]
    fn parses_primary_mbr_partitions() {
        let mut disk = VecDisk(vec![0u8; 4096 * BLOCK_SECTOR_SIZE]);
        disk.0[510] = 0x55;
        disk.0[511] = 0xaa;
        // Partition 1: bootable Linux 0x83 @ LBA 2048, len 1024
        disk.0[446] = 0x80;
        disk.0[446 + 4] = 0x83;
        disk.0[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
        disk.0[446 + 12..446 + 16].copy_from_slice(&1024u32.to_le_bytes());
        // Partition 2: Linux 0x83 @ LBA 3072, len 512
        disk.0[462 + 4] = 0x83;
        disk.0[462 + 8..462 + 12].copy_from_slice(&3072u32.to_le_bytes());
        disk.0[462 + 12..462 + 16].copy_from_slice(&512u32.to_le_bytes());

        let table = parse_partitions(&mut disk).unwrap();
        assert!(!table.is_gpt);
        assert_eq!(table.count, 2);
        assert_eq!(table.entries[0].number, 1);
        assert!(table.entries[0].bootable);
        assert_eq!(table.entries[0].start_sector, 2048);
        assert_eq!(table.entries[0].sector_count, 1024);
        assert_eq!(table.entries[1].number, 2);
        assert_eq!(table.entries[1].start_sector, 3072);
        assert_eq!(table.entries[1].sector_count, 512);
    }

    #[test]
    fn parses_and_verifies_gpt_partition_table() {
        let mut disk = VecDisk(vec![0u8; 4096 * BLOCK_SECTOR_SIZE]);
        // Protective MBR
        disk.0[510] = 0x55;
        disk.0[511] = 0xaa;
        disk.0[446 + 4] = 0xee;
        disk.0[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        disk.0[446 + 12..446 + 16].copy_from_slice(&4095u32.to_le_bytes());

        // Partition entries at LBA 2..34 (128 entries * 128 bytes = 16384 bytes)
        let linux_guid = [
            0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47,
            0x7d, 0xe4,
        ];
        let p0 = 2 * BLOCK_SECTOR_SIZE;
        disk.0[p0..p0 + 16].copy_from_slice(&linux_guid);
        disk.0[p0 + 32..p0 + 40].copy_from_slice(&2048u64.to_le_bytes());
        disk.0[p0 + 40..p0 + 48].copy_from_slice(&4060u64.to_le_bytes());
        let array_crc = crc32_ieee(&disk.0[p0..p0 + 128 * 128]);

        // GPT Header at LBA 1
        let h = BLOCK_SECTOR_SIZE;
        disk.0[h..h + 8].copy_from_slice(b"EFI PART");
        disk.0[h + 8..h + 12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        disk.0[h + 12..h + 16].copy_from_slice(&92u32.to_le_bytes());
        disk.0[h + 24..h + 32].copy_from_slice(&1u64.to_le_bytes());
        disk.0[h + 40..h + 48].copy_from_slice(&34u64.to_le_bytes());
        disk.0[h + 48..h + 56].copy_from_slice(&4062u64.to_le_bytes());
        disk.0[h + 72..h + 80].copy_from_slice(&2u64.to_le_bytes());
        disk.0[h + 80..h + 84].copy_from_slice(&128u32.to_le_bytes());
        disk.0[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes());
        disk.0[h + 88..h + 92].copy_from_slice(&array_crc.to_le_bytes());
        let hdr_crc = crc32_ieee(&disk.0[h..h + 92]);
        disk.0[h + 16..h + 20].copy_from_slice(&hdr_crc.to_le_bytes());

        let table = parse_partitions(&mut disk).expect("valid GPT");
        assert!(table.is_gpt);
        assert_eq!(table.count, 1);
        assert_eq!(table.entries[0].number, 1);
        assert_eq!(table.entries[0].start_sector, 2048);
        assert_eq!(table.entries[0].sector_count, 2013);
        assert_eq!(table.entries[0].type_guid, linux_guid);

        // Corrupt array CRC -> fail closed
        disk.0[p0 + 100] ^= 1;
        assert_eq!(parse_partitions(&mut disk), Err(Errno::EIO));
    }
}
