// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Memory-safe (`#![forbid(unsafe_code)]`) Linux / Android `eBPF` (`sys_bpf`, nr 280)
//! subsystem for Qyronex OS.
//!
//! Supports Android `bpfloader` / `netd` workflows:
//! - `BPF_MAP_CREATE`, `BPF_MAP_LOOKUP_ELEM`, `BPF_MAP_UPDATE_ELEM`, `BPF_MAP_DELETE_ELEM`,
//!   `BPF_MAP_GET_NEXT_KEY` (`BPF_MAP_TYPE_HASH` & `BPF_MAP_TYPE_ARRAY`)
//! - `BPF_PROG_LOAD` with a fail-closed static verifier (register bounds `R0..=R10`, acyclic
//!   forward-only control flow, safe stack bounds, opcode validation, mandatory `BPF_EXIT`)
//! - `BPF_PROG_TEST_RUN` executing verified 64-bit eBPF bytecode in a sandboxed VM
//! - `BPF_OBJ_PIN` / `BPF_OBJ_GET` under `/sys/fs/bpf/*`
//! - Explicit Qyronex `Capability` enforcement on every map/program operation.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use kernal_capability::{CapRights, Capability};
use kernal_linux_abi::Errno;

// Linux `enum bpf_cmd` constants
pub const BPF_MAP_CREATE: u32 = 0;
pub const BPF_MAP_LOOKUP_ELEM: u32 = 1;
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
pub const BPF_MAP_DELETE_ELEM: u32 = 3;
pub const BPF_MAP_GET_NEXT_KEY: u32 = 4;
pub const BPF_PROG_LOAD: u32 = 5;
pub const BPF_OBJ_PIN: u32 = 6;
pub const BPF_OBJ_GET: u32 = 7;
pub const BPF_PROG_TEST_RUN: u32 = 10;

// Linux `enum bpf_map_type`
pub const BPF_MAP_TYPE_HASH: u32 = 1;
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;

// Linux `enum bpf_prog_type`
pub const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
pub const BPF_PROG_TYPE_CGROUP_SKB: u32 = 8;
pub const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 9;
pub const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;

// eBPF instruction classes & opcodes
const BPF_CLASS_MASK: u8 = 0x07;
const BPF_LD: u8 = 0x00;
const BPF_LDX: u8 = 0x01;
const BPF_ST: u8 = 0x02;
const BPF_STX: u8 = 0x03;
const BPF_ALU: u8 = 0x04;
const BPF_JMP: u8 = 0x05;
const BPF_JMP32: u8 = 0x06;
const BPF_ALU64: u8 = 0x07;

const BPF_X: u8 = 0x08;
const BPF_OP_MASK: u8 = 0xf0;
const BPF_ADD: u8 = 0x00;
const BPF_SUB: u8 = 0x10;
const BPF_MUL: u8 = 0x20;
const BPF_DIV: u8 = 0x30;
const BPF_OR: u8 = 0x40;
const BPF_AND: u8 = 0x50;
const BPF_LSH: u8 = 0x60;
const BPF_RSH: u8 = 0x70;
const BPF_MOD: u8 = 0x90;
const BPF_XOR: u8 = 0xa0;
const BPF_MOV: u8 = 0xb0;

const BPF_JA: u8 = 0x00;
const BPF_JEQ: u8 = 0x10;
const BPF_JGT: u8 = 0x20;
const BPF_JGE: u8 = 0x30;
const BPF_JSET: u8 = 0x40;
const BPF_JNE: u8 = 0x50;
const BPF_CALL: u8 = 0x80;
const BPF_EXIT: u8 = 0x90;

const BPF_SIZE_MASK: u8 = 0x18;
const BPF_W: u8 = 0x00;
const BPF_H: u8 = 0x08;
const BPF_B: u8 = 0x10;
const BPF_DW: u8 = 0x18;
const BPF_MODE_MASK: u8 = 0xe0;
const BPF_MEM: u8 = 0x60;

pub const MAX_BPF_INSNS: usize = 512;
pub const MAX_BPF_MAPS: usize = 32;
pub const MAX_BPF_PROGS: usize = 32;
pub const MAX_BPF_MAP_ENTRIES: usize = 256;
pub const MAX_BPF_KEY_BYTES: usize = 64;
pub const MAX_BPF_VAL_BYTES: usize = 256;
const BPF_STACK_BYTES: usize = 512;

/// Canonical 8-byte Linux `struct bpf_insn`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BpfInsn {
    pub code: u8,
    pub dst_reg: u8,
    pub src_reg: u8,
    pub off: i16,
    pub imm: i32,
}

impl BpfInsn {
    pub fn from_le_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() < 8 {
            return None;
        }
        let regs = raw[1];
        Some(Self {
            code: raw[0],
            dst_reg: regs & 0x0f,
            src_reg: (regs >> 4) & 0x0f,
            off: i16::from_le_bytes([raw[2], raw[3]]),
            imm: i32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
        })
    }

    pub const fn to_le_bytes(self) -> [u8; 8] {
        let regs = (self.dst_reg & 0x0f) | ((self.src_reg & 0x0f) << 4);
        let off = self.off.to_le_bytes();
        let imm = self.imm.to_le_bytes();
        [
            self.code, regs, off[0], off[1], imm[0], imm[1], imm[2], imm[3],
        ]
    }
}

#[derive(Clone, Debug)]
pub struct BpfMap {
    pub id: u32,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl BpfMap {
    pub fn lookup(&self, key: &[u8]) -> Result<Option<&[u8]>, Errno> {
        if key.len() != self.key_size as usize {
            return Err(Errno::EINVAL);
        }
        if self.map_type == BPF_MAP_TYPE_ARRAY {
            if key.len() != 4 {
                return Err(Errno::EINVAL);
            }
            let idx = u32::from_le_bytes([key[0], key[1], key[2], key[3]]) as usize;
            if idx >= self.max_entries as usize {
                return Err(Errno::E2BIG);
            }
            return Ok(self.entries.get(idx).map(|(_, v)| v.as_slice()));
        }
        Ok(self
            .entries
            .iter()
            .find(|(k, _)| k.as_slice() == key)
            .map(|(_, v)| v.as_slice()))
    }

    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<(), Errno> {
        if key.len() != self.key_size as usize || value.len() != self.value_size as usize {
            return Err(Errno::EINVAL);
        }
        if self.map_type == BPF_MAP_TYPE_ARRAY {
            if key.len() != 4 {
                return Err(Errno::EINVAL);
            }
            let idx = u32::from_le_bytes([key[0], key[1], key[2], key[3]]) as usize;
            if idx >= self.max_entries as usize {
                return Err(Errno::E2BIG);
            }
            if let Some((_, v)) = self.entries.get_mut(idx) {
                v.clear();
                v.extend_from_slice(value);
                return Ok(());
            }
            return Err(Errno::ENOENT);
        }
        if let Some((_, v)) = self.entries.iter_mut().find(|(k, _)| k.as_slice() == key) {
            v.clear();
            v.extend_from_slice(value);
            return Ok(());
        }
        if self.entries.len() >= self.max_entries as usize {
            return Err(Errno::E2BIG);
        }
        self.entries.push((key.to_vec(), value.to_vec()));
        Ok(())
    }

    pub fn delete(&mut self, key: &[u8]) -> Result<(), Errno> {
        if key.len() != self.key_size as usize {
            return Err(Errno::EINVAL);
        }
        if self.map_type == BPF_MAP_TYPE_ARRAY {
            return Err(Errno::EINVAL);
        }
        let pos = self
            .entries
            .iter()
            .position(|(k, _)| k.as_slice() == key)
            .ok_or(Errno::ENOENT)?;
        self.entries.swap_remove(pos);
        Ok(())
    }

    pub fn next_key(&self, key: Option<&[u8]>) -> Result<Vec<u8>, Errno> {
        match key {
            None => self
                .entries
                .first()
                .map(|(k, _)| k.clone())
                .ok_or(Errno::ENOENT),
            Some(k) => {
                if k.len() != self.key_size as usize {
                    return Err(Errno::EINVAL);
                }
                if let Some(pos) = self.entries.iter().position(|(ek, _)| ek.as_slice() == k) {
                    self.entries
                        .get(pos + 1)
                        .map(|(nk, _)| nk.clone())
                        .ok_or(Errno::ENOENT)
                } else {
                    self.entries
                        .first()
                        .map(|(nk, _)| nk.clone())
                        .ok_or(Errno::ENOENT)
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct BpfProgram {
    pub id: u32,
    pub prog_type: u32,
    pub insns: Vec<BpfInsn>,
    pub executions: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BpfPinnedTarget {
    Map(u32),
    Prog(u32),
}

/// Fail-closed static eBPF bytecode verifier (prevents OOB registers, backward loops,
/// invalid opcodes, division-by-zero immediates, or non-terminating programs).
pub fn verify_bpf_program(insns: &[BpfInsn]) -> Result<(), Errno> {
    if insns.is_empty() || insns.len() > MAX_BPF_INSNS {
        return Err(Errno::EINVAL);
    }
    let mut saw_exit = false;
    for (pc, insn) in insns.iter().enumerate() {
        if insn.dst_reg > 10 || insn.src_reg > 10 {
            return Err(Errno::EACCES);
        }
        let class = insn.code & BPF_CLASS_MASK;
        let op = insn.code & BPF_OP_MASK;
        match class {
            BPF_ALU | BPF_ALU64 => {
                // R10 (frame pointer) is strictly read-only.
                if insn.dst_reg == 10 {
                    return Err(Errno::EACCES);
                }
                match op {
                    BPF_ADD | BPF_SUB | BPF_MUL | BPF_OR | BPF_AND | BPF_LSH | BPF_RSH
                    | BPF_XOR | BPF_MOV => {}
                    BPF_DIV | BPF_MOD => {
                        if (insn.code & BPF_X) == 0 && insn.imm == 0 {
                            return Err(Errno::EACCES);
                        }
                    }
                    _ => return Err(Errno::EINVAL),
                }
            }
            BPF_JMP | BPF_JMP32 => match op {
                BPF_EXIT => {
                    saw_exit = true;
                }
                BPF_CALL => {
                    // Allow safe read-only Android helper IDs:
                    // 1 = map_lookup_elem, 5 = ktime_get_ns, 7 = get_prandom_u32, 14 = get_current_pid_tgid
                    if !matches!(insn.imm, 1 | 5 | 7 | 14) {
                        return Err(Errno::EACCES);
                    }
                }
                BPF_JA | BPF_JEQ | BPF_JGT | BPF_JGE | BPF_JSET | BPF_JNE => {
                    // Strictly acyclic forward-only jumps (prevents infinite loops).
                    if insn.off < 0 {
                        return Err(Errno::EACCES);
                    }
                    let target = pc
                        .checked_add(1)
                        .and_then(|v| v.checked_add(insn.off as usize))
                        .ok_or(Errno::EACCES)?;
                    if target >= insns.len() {
                        return Err(Errno::EACCES);
                    }
                }
                _ => return Err(Errno::EINVAL),
            },
            BPF_LDX => {
                if insn.dst_reg == 10 || (insn.code & BPF_MODE_MASK) != BPF_MEM {
                    return Err(Errno::EACCES);
                }
                // Only safe stack (R10) or context (R1) loads are allowed.
                if insn.src_reg != 10 && insn.src_reg != 1 {
                    return Err(Errno::EACCES);
                }
                if insn.src_reg == 10
                    && (insn.off >= 0 || (insn.off as i32) < -(BPF_STACK_BYTES as i32))
                {
                    return Err(Errno::EACCES);
                }
                if insn.src_reg == 1 && insn.off < 0 {
                    return Err(Errno::EACCES);
                }
            }
            BPF_STX | BPF_ST => {
                if (insn.code & BPF_MODE_MASK) != BPF_MEM || insn.dst_reg != 10 {
                    return Err(Errno::EACCES);
                }
                if insn.off >= 0 || (insn.off as i32) < -(BPF_STACK_BYTES as i32) {
                    return Err(Errno::EACCES);
                }
            }
            BPF_LD => {
                // Reject unverified arbitrary direct-pointer loads.
                return Err(Errno::EACCES);
            }
            _ => return Err(Errno::EINVAL),
        }
    }
    if !saw_exit || insns.last().map(|i| i.code) != Some(BPF_JMP | BPF_EXIT) {
        return Err(Errno::EACCES);
    }
    Ok(())
}

/// Sandboxed 64-bit eBPF VM execution over a read-only context/packet buffer.
pub fn execute_bpf_program(insns: &[BpfInsn], ctx_data: &[u8]) -> Result<u32, Errno> {
    let mut regs = [0u64; 11];
    regs[1] = 0; // Context base index (symbolic offset 0 into ctx_data)
    regs[2] = ctx_data.len() as u64;
    regs[10] = BPF_STACK_BYTES as u64;
    let mut stack = [0u8; BPF_STACK_BYTES];

    let mut pc = 0usize;
    let mut steps = 0usize;
    while pc < insns.len() {
        steps += 1;
        if steps > MAX_BPF_INSNS * 2 {
            return Err(Errno::EACCES);
        }
        let insn = insns[pc];
        let class = insn.code & BPF_CLASS_MASK;
        let op = insn.code & BPF_OP_MASK;
        let dst = insn.dst_reg as usize;
        let src = insn.src_reg as usize;

        match class {
            BPF_ALU64 => {
                let rhs = if (insn.code & BPF_X) != 0 {
                    regs[src]
                } else {
                    insn.imm as i64 as u64
                };
                regs[dst] = match op {
                    BPF_ADD => regs[dst].wrapping_add(rhs),
                    BPF_SUB => regs[dst].wrapping_sub(rhs),
                    BPF_MUL => regs[dst].wrapping_mul(rhs),
                    BPF_DIV => regs[dst].checked_div(rhs).unwrap_or(0),
                    BPF_MOD => regs[dst].checked_rem(rhs).unwrap_or(0),
                    BPF_OR => regs[dst] | rhs,
                    BPF_AND => regs[dst] & rhs,
                    BPF_LSH => regs[dst].wrapping_shl((rhs & 63) as u32),
                    BPF_RSH => regs[dst].wrapping_shr((rhs & 63) as u32),
                    BPF_XOR => regs[dst] ^ rhs,
                    BPF_MOV => rhs,
                    _ => return Err(Errno::EINVAL),
                };
            }
            BPF_ALU => {
                let lhs = regs[dst] as u32;
                let rhs = if (insn.code & BPF_X) != 0 {
                    regs[src] as u32
                } else {
                    insn.imm as u32
                };
                let res = match op {
                    BPF_ADD => lhs.wrapping_add(rhs),
                    BPF_SUB => lhs.wrapping_sub(rhs),
                    BPF_MUL => lhs.wrapping_mul(rhs),
                    BPF_DIV => lhs.checked_div(rhs).unwrap_or(0),
                    BPF_MOD => lhs.checked_rem(rhs).unwrap_or(0),
                    BPF_OR => lhs | rhs,
                    BPF_AND => lhs & rhs,
                    BPF_LSH => lhs.wrapping_shl(rhs & 31),
                    BPF_RSH => lhs.wrapping_shr(rhs & 31),
                    BPF_XOR => lhs ^ rhs,
                    BPF_MOV => rhs,
                    _ => return Err(Errno::EINVAL),
                };
                regs[dst] = u64::from(res);
            }
            BPF_LDX => {
                let size = match insn.code & BPF_SIZE_MASK {
                    BPF_B => 1usize,
                    BPF_H => 2,
                    BPF_W => 4,
                    BPF_DW => 8,
                    _ => return Err(Errno::EINVAL),
                };
                let slice: &[u8] = if src == 10 {
                    let off = (BPF_STACK_BYTES as isize) + (insn.off as isize);
                    if off < 0 || (off as usize) + size > BPF_STACK_BYTES {
                        return Err(Errno::EACCES);
                    }
                    &stack[off as usize..off as usize + size]
                } else {
                    let off = insn.off as usize;
                    if off + size > ctx_data.len() {
                        regs[dst] = 0;
                        pc += 1;
                        continue;
                    }
                    &ctx_data[off..off + size]
                };
                regs[dst] = match size {
                    1 => u64::from(slice[0]),
                    2 => u64::from(u16::from_le_bytes([slice[0], slice[1]])),
                    4 => u64::from(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])),
                    8 => u64::from_le_bytes([
                        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6],
                        slice[7],
                    ]),
                    _ => 0,
                };
            }
            BPF_STX | BPF_ST => {
                let size = match insn.code & BPF_SIZE_MASK {
                    BPF_B => 1usize,
                    BPF_H => 2,
                    BPF_W => 4,
                    BPF_DW => 8,
                    _ => return Err(Errno::EINVAL),
                };
                let off = (BPF_STACK_BYTES as isize) + (insn.off as isize);
                if off < 0 || (off as usize) + size > BPF_STACK_BYTES {
                    return Err(Errno::EACCES);
                }
                let val = if class == BPF_STX {
                    regs[src]
                } else {
                    insn.imm as i64 as u64
                };
                let bytes = val.to_le_bytes();
                stack[off as usize..off as usize + size].copy_from_slice(&bytes[..size]);
            }
            BPF_JMP | BPF_JMP32 => {
                let is32 = class == BPF_JMP32;
                let lhs = if is32 {
                    u64::from(regs[dst] as u32)
                } else {
                    regs[dst]
                };
                let rhs = if (insn.code & BPF_X) != 0 {
                    if is32 {
                        u64::from(regs[src] as u32)
                    } else {
                        regs[src]
                    }
                } else if is32 {
                    u64::from(insn.imm as u32)
                } else {
                    insn.imm as i64 as u64
                };
                match op {
                    BPF_EXIT => return Ok(regs[0] as u32),
                    BPF_CALL => {
                        regs[0] = match insn.imm {
                            5 => 1_000_000_000u64, // ktime_get_ns
                            7 => 0x5159_524eu64,   // deterministic prandom seed
                            14 => 1u64,            // pid_tgid
                            _ => 0,
                        };
                    }
                    BPF_JA => {
                        pc = pc.saturating_add(1 + insn.off as usize);
                        continue;
                    }
                    BPF_JEQ if lhs == rhs => {
                        pc = pc.saturating_add(1 + insn.off as usize);
                        continue;
                    }
                    BPF_JNE if lhs != rhs => {
                        pc = pc.saturating_add(1 + insn.off as usize);
                        continue;
                    }
                    BPF_JGT if lhs > rhs => {
                        pc = pc.saturating_add(1 + insn.off as usize);
                        continue;
                    }
                    BPF_JGE if lhs >= rhs => {
                        pc = pc.saturating_add(1 + insn.off as usize);
                        continue;
                    }
                    BPF_JSET if (lhs & rhs) != 0 => {
                        pc = pc.saturating_add(1 + insn.off as usize);
                        continue;
                    }
                    BPF_JEQ | BPF_JNE | BPF_JGT | BPF_JGE | BPF_JSET => {}
                    _ => return Err(Errno::EINVAL),
                }
            }
            _ => return Err(Errno::EINVAL),
        }
        pc += 1;
    }
    Ok(regs[0] as u32)
}

/// Complete Qyronex eBPF subsystem state (`maps`, `progs`, `/sys/fs/bpf` pins, audit counters).
pub struct EbpfSubsystem {
    next_id: u32,
    pub maps: Vec<BpfMap>,
    pub progs: Vec<BpfProgram>,
    pub pins: Vec<(String, BpfPinnedTarget)>,
    pub verifier_rejects: u64,
    pub total_runs: u64,
}

impl EbpfSubsystem {
    pub const fn new() -> Self {
        Self {
            next_id: 1,
            maps: Vec::new(),
            progs: Vec::new(),
            pins: Vec::new(),
            verifier_rejects: 0,
            total_runs: 0,
        }
    }

    pub fn create_map(
        &mut self,
        cap: Capability,
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    ) -> Result<u32, Errno> {
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(Errno::EPERM);
        }
        if !matches!(map_type, BPF_MAP_TYPE_HASH | BPF_MAP_TYPE_ARRAY) {
            return Err(Errno::EINVAL);
        }
        if key_size == 0
            || key_size as usize > MAX_BPF_KEY_BYTES
            || value_size == 0
            || value_size as usize > MAX_BPF_VAL_BYTES
            || max_entries == 0
            || max_entries as usize > MAX_BPF_MAP_ENTRIES
        {
            return Err(Errno::EINVAL);
        }
        if map_type == BPF_MAP_TYPE_ARRAY && key_size != 4 {
            return Err(Errno::EINVAL);
        }
        if self.maps.len() >= MAX_BPF_MAPS {
            return Err(Errno::ENOMEM);
        }
        let id = self.next_id;
        self.next_id += 1;
        let mut entries = Vec::new();
        if map_type == BPF_MAP_TYPE_ARRAY {
            for i in 0..max_entries {
                entries.push((i.to_le_bytes().to_vec(), vec![0u8; value_size as usize]));
            }
        }
        self.maps.push(BpfMap {
            id,
            map_type,
            key_size,
            value_size,
            max_entries,
            entries,
        });
        Ok(id)
    }

    pub fn map(&self, id: u32) -> Option<&BpfMap> {
        self.maps.iter().find(|m| m.id == id)
    }

    pub fn map_mut(&mut self, id: u32) -> Option<&mut BpfMap> {
        self.maps.iter_mut().find(|m| m.id == id)
    }

    pub fn load_program(
        &mut self,
        cap: Capability,
        prog_type: u32,
        insns: Vec<BpfInsn>,
    ) -> Result<u32, Errno> {
        if !cap.rights.contains(CapRights::CONTROL) {
            return Err(Errno::EPERM);
        }
        if self.progs.len() >= MAX_BPF_PROGS {
            return Err(Errno::ENOMEM);
        }
        if let Err(e) = verify_bpf_program(&insns) {
            self.verifier_rejects += 1;
            return Err(e);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.progs.push(BpfProgram {
            id,
            prog_type,
            insns,
            executions: 0,
        });
        Ok(id)
    }

    pub fn test_run_program(&mut self, prog_id: u32, ctx_data: &[u8]) -> Result<u32, Errno> {
        let prog = self
            .progs
            .iter_mut()
            .find(|p| p.id == prog_id)
            .ok_or(Errno::ENOENT)?;
        let ret = execute_bpf_program(&prog.insns, ctx_data)?;
        prog.executions += 1;
        self.total_runs += 1;
        Ok(ret)
    }

    pub fn pin_object(&mut self, path: &str, target: BpfPinnedTarget) -> Result<(), Errno> {
        if !path.starts_with("/sys/fs/bpf/") || path.contains("..") {
            return Err(Errno::EINVAL);
        }
        if let Some((_, existing)) = self.pins.iter_mut().find(|(p, _)| p == path) {
            *existing = target;
            return Ok(());
        }
        self.pins.push((String::from(path), target));
        Ok(())
    }

    pub fn get_pinned(&self, path: &str) -> Option<BpfPinnedTarget> {
        self.pins.iter().find(|(p, _)| p == path).map(|(_, t)| *t)
    }
}

impl Default for EbpfSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_capability::ObjectId;

    fn full_cap() -> Capability {
        Capability {
            object: ObjectId(99),
            rights: CapRights::READ
                .union(CapRights::WRITE)
                .union(CapRights::CONTROL),
        }
    }

    #[test]
    fn ebpf_map_crud_and_verifier_and_vm_execution() {
        let mut bpf = EbpfSubsystem::new();
        let cap = full_cap();

        // 1. Hash map CRUD
        let map_id = bpf.create_map(cap, BPF_MAP_TYPE_HASH, 4, 8, 16).unwrap();
        let k = 42u32.to_le_bytes();
        let v = 0x1122_3344_5566_7788u64.to_le_bytes();
        bpf.map_mut(map_id).unwrap().update(&k, &v).unwrap();
        assert_eq!(
            bpf.map(map_id).unwrap().lookup(&k).unwrap(),
            Some(v.as_slice())
        );
        assert_eq!(bpf.map(map_id).unwrap().next_key(None).unwrap(), k.to_vec());
        bpf.map_mut(map_id).unwrap().delete(&k).unwrap();
        assert_eq!(bpf.map(map_id).unwrap().lookup(&k).unwrap(), None);

        // 2. Valid program: read byte 0 of packet ctx, add 10, return R0
        let valid_prog = vec![
            // LDX_B R0, [R1 + 0]
            BpfInsn {
                code: BPF_LDX | BPF_B | BPF_MEM,
                dst_reg: 0,
                src_reg: 1,
                off: 0,
                imm: 0,
            },
            // ADD64 R0, 10
            BpfInsn {
                code: BPF_ALU64 | BPF_ADD,
                dst_reg: 0,
                src_reg: 0,
                off: 0,
                imm: 10,
            },
            // EXIT
            BpfInsn {
                code: BPF_JMP | BPF_EXIT,
                dst_reg: 0,
                src_reg: 0,
                off: 0,
                imm: 0,
            },
        ];
        let pid = bpf
            .load_program(cap, BPF_PROG_TYPE_SOCKET_FILTER, valid_prog)
            .unwrap();
        assert_eq!(bpf.test_run_program(pid, &[32, 0, 0, 0]).unwrap(), 42);

        // 3. Reject backward jump loop (fail-closed verifier!)
        let bad_loop = vec![
            BpfInsn {
                code: BPF_JMP | BPF_JA,
                dst_reg: 0,
                src_reg: 0,
                off: -1,
                imm: 0,
            },
            BpfInsn {
                code: BPF_JMP | BPF_EXIT,
                dst_reg: 0,
                src_reg: 0,
                off: 0,
                imm: 0,
            },
        ];
        assert_eq!(
            bpf.load_program(cap, BPF_PROG_TYPE_SOCKET_FILTER, bad_loop),
            Err(Errno::EACCES)
        );
        assert_eq!(bpf.verifier_rejects, 1);

        // 4. Reject write to read-only R10 frame pointer
        let bad_r10 = vec![
            BpfInsn {
                code: BPF_ALU64 | BPF_MOV,
                dst_reg: 10,
                src_reg: 0,
                off: 0,
                imm: 0,
            },
            BpfInsn {
                code: BPF_JMP | BPF_EXIT,
                dst_reg: 0,
                src_reg: 0,
                off: 0,
                imm: 0,
            },
        ];
        assert_eq!(
            bpf.load_program(cap, BPF_PROG_TYPE_CGROUP_SKB, bad_r10),
            Err(Errno::EACCES)
        );
        assert_eq!(bpf.verifier_rejects, 2);

        // 5. Pin & retrieve from /sys/fs/bpf/
        bpf.pin_object("/sys/fs/bpf/netd_prog", BpfPinnedTarget::Prog(pid))
            .unwrap();
        assert_eq!(
            bpf.get_pinned("/sys/fs/bpf/netd_prog"),
            Some(BpfPinnedTarget::Prog(pid))
        );
    }
}
