// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_fdt::{Blob, Event};

pub const AT_RANDOM_BYTES: usize = 16;
const QEMU_RNG_SEED_BYTES: usize = AT_RANDOM_BYTES * 2;

const EMPTY: u8 = 0;
const INSTALLING: u8 = 1;
const FIRST_READY: u8 = 2;
const FIRST_BORROWED: u8 = 3;
const SECOND_READY: u8 = 4;
const SECOND_BORROWED: u8 = 5;
const EXHAUSTED: u8 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Fdt(kernal_fdt::Error),
    MissingSeed,
    SeedTooShort,
    AllZeroSeed,
    DuplicateSeed,
    AlreadyPublished,
    Busy,
    Exhausted,
    InvalidState,
    QemuDtbUnavailable,
}

impl From<kernal_fdt::Error> for Error {
    fn from(value: kernal_fdt::Error) -> Self {
        Self::Fdt(value)
    }
}

/// Bounded two-grant owner for QEMU's complete 32-byte `/chosen/rng-seed` value.
///
/// Step 30 needs exactly two Linux `AT_RANDOM` payloads: one for the initial image and one for the
/// single real exec exercised by the final QEMU oracle. The two payloads are the two disjoint halves
/// of the host-provided seed. No clock/counter input, deterministic expansion, or payload reuse is
/// accepted. A third request fails closed until a reusable cryptographic entropy owner is introduced.
struct SeedCell {
    state: AtomicU8,
    bytes: UnsafeCell<[u8; QEMU_RNG_SEED_BYTES]>,
}

// SAFETY: EMPTY -> INSTALLING gives one publisher. FIRST_READY/SECOND_READY -> *_BORROWED gives one
// temporary reader/mutator. The first grant is copied and erased before publishing SECOND_READY. The
// second grant is either erased before EXHAUSTED or left intact before rolling back to SECOND_READY;
// no reference to retained seed bytes can escape.
unsafe impl Sync for SeedCell {}

impl SeedCell {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            bytes: UnsafeCell::new([0; QEMU_RNG_SEED_BYTES]),
        }
    }

    fn publish(&self, seed: [u8; QEMU_RNG_SEED_BYTES]) -> Result<(), Error> {
        match self
            .state
            .compare_exchange(EMPTY, INSTALLING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(INSTALLING | FIRST_BORROWED | SECOND_BORROWED) => return Err(Error::Busy),
            Err(FIRST_READY | SECOND_READY | EXHAUSTED) => return Err(Error::AlreadyPublished),
            Err(_) => return Err(Error::InvalidState),
        }
        // SAFETY: INSTALLING is exclusive writer ownership and no reader can observe a ready state.
        unsafe { *self.bytes.get() = seed };
        self.state.store(FIRST_READY, Ordering::Release);
        Ok(())
    }

    fn take(&self) -> Result<[u8; AT_RANDOM_BYTES], Error> {
        let (offset, next_state) = loop {
            match self.state.load(Ordering::Acquire) {
                EMPTY => return Err(Error::MissingSeed),
                INSTALLING | FIRST_BORROWED | SECOND_BORROWED => return Err(Error::Busy),
                FIRST_READY => {
                    if self
                        .state
                        .compare_exchange(
                            FIRST_READY,
                            FIRST_BORROWED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break (0, SECOND_READY);
                    }
                }
                SECOND_READY => {
                    if self
                        .state
                        .compare_exchange(
                            SECOND_READY,
                            SECOND_BORROWED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break (AT_RANDOM_BYTES, EXHAUSTED);
                    }
                }
                EXHAUSTED => return Err(Error::Exhausted),
                _ => return Err(Error::InvalidState),
            }
        };

        let mut output = [0u8; AT_RANDOM_BYTES];
        // SAFETY: the successful *_READY -> *_BORROWED transition is the sole access right for this
        // half. The bytes are copied out by value and then erased before the next state is published.
        unsafe {
            let bytes = &mut *self.bytes.get();
            let end = offset + AT_RANDOM_BYTES;
            output.copy_from_slice(&bytes[offset..end]);
            bytes[offset..end].fill(0);
        }
        self.state.store(next_state, Ordering::Release);
        Ok(output)
    }

    /// Runs one reversible preparation transaction against the second AT_RANDOM grant.
    ///
    /// The owner retains the original bytes while `operation` stages the replacement image. A normal
    /// preparation error republishes the exact same second grant for a later exec retry. Only success
    /// erases the retained bytes and advances the owner to EXHAUSTED. This keeps Linux-visible exec
    /// failures before the irreversible image commit from consuming the process's sole exec grant.
    fn with_second_transaction<R, E>(
        &self,
        operation: impl FnOnce([u8; AT_RANDOM_BYTES]) -> Result<R, E>,
    ) -> Result<Result<R, E>, Error> {
        loop {
            match self.state.load(Ordering::Acquire) {
                EMPTY => return Err(Error::MissingSeed),
                INSTALLING | FIRST_BORROWED | SECOND_BORROWED => return Err(Error::Busy),
                FIRST_READY => return Err(Error::InvalidState),
                SECOND_READY => {
                    if self
                        .state
                        .compare_exchange(
                            SECOND_READY,
                            SECOND_BORROWED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break;
                    }
                }
                EXHAUSTED => return Err(Error::Exhausted),
                _ => return Err(Error::InvalidState),
            }
        }

        let mut grant = [0u8; AT_RANDOM_BYTES];
        // SAFETY: SECOND_BORROWED is exclusive access to the retained second half. Unlike `take`, the
        // owner copy is deliberately not erased until the staging operation reports success.
        unsafe {
            let bytes = &*self.bytes.get();
            grant.copy_from_slice(&bytes[AT_RANDOM_BYTES..QEMU_RNG_SEED_BYTES]);
        }

        match operation(grant) {
            Ok(value) => {
                // SAFETY: this transaction still owns SECOND_BORROWED, so no other accessor can read
                // or mutate the retained second half before EXHAUSTED is published.
                unsafe {
                    let bytes = &mut *self.bytes.get();
                    bytes[AT_RANDOM_BYTES..QEMU_RNG_SEED_BYTES].fill(0);
                }
                self.state.store(EXHAUSTED, Ordering::Release);
                Ok(Ok(value))
            }
            Err(error) => {
                // The retained owner copy was never changed, so releasing SECOND_READY makes the
                // identical grant available to a later reversible exec attempt.
                self.state.store(SECOND_READY, Ordering::Release);
                Ok(Err(error))
            }
        }
    }
}

static QEMU_AT_RANDOM: SeedCell = SeedCell::new();

const CSPRNG_READY: u8 = 2;
const CSPRNG_BORROWED: u8 = 3;
const CHACHA_DOMAIN_NONCE: [u32; 3] = [0x2d52_5951, 0x5045_5453, 0x472d_3133];

struct CsprngCell {
    state: AtomicU8,
    key: UnsafeCell<[u8; QEMU_RNG_SEED_BYTES]>,
    generation: UnsafeCell<u64>,
}

// SAFETY: EMPTY -> INSTALLING gives one publisher; CSPRNG_READY -> CSPRNG_BORROWED gives one
// exclusive caller that rekeys and advances generation before releasing CSPRNG_READY.
unsafe impl Sync for CsprngCell {}

impl CsprngCell {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            key: UnsafeCell::new([0; QEMU_RNG_SEED_BYTES]),
            generation: UnsafeCell::new(0),
        }
    }

    #[cfg_attr(
        not(any(test, all(target_arch = "aarch64", target_os = "none"))),
        allow(dead_code)
    )]
    fn publish(&self, seed: [u8; QEMU_RNG_SEED_BYTES]) -> Result<(), Error> {
        if seed == [0u8; QEMU_RNG_SEED_BYTES] {
            return Err(Error::AllZeroSeed);
        }
        match self
            .state
            .compare_exchange(EMPTY, INSTALLING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(INSTALLING | CSPRNG_BORROWED) => return Err(Error::Busy),
            Err(CSPRNG_READY) => return Err(Error::AlreadyPublished),
            Err(_) => return Err(Error::InvalidState),
        }
        // Derive an initial key distinct from raw AT_RANDOM halves via domain-separated ChaCha20.
        let initial_block = chacha20_block(&seed, 0, CHACHA_DOMAIN_NONCE);
        let mut derived_key = [0u8; QEMU_RNG_SEED_BYTES];
        derived_key.copy_from_slice(&initial_block[..QEMU_RNG_SEED_BYTES]);
        // SAFETY: INSTALLING is exclusive writer ownership before CSPRNG_READY publication.
        unsafe {
            *self.key.get() = derived_key;
            *self.generation.get() = 1;
        }
        self.state.store(CSPRNG_READY, Ordering::Release);
        Ok(())
    }

    fn fill(&self, dest: &mut [u8]) -> Result<(), Error> {
        loop {
            match self.state.load(Ordering::Acquire) {
                EMPTY => return Err(Error::MissingSeed),
                INSTALLING | CSPRNG_BORROWED => return Err(Error::Busy),
                CSPRNG_READY => {
                    if self
                        .state
                        .compare_exchange(
                            CSPRNG_READY,
                            CSPRNG_BORROWED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break;
                    }
                }
                _ => return Err(Error::InvalidState),
            }
        }

        // SAFETY: CSPRNG_BORROWED grants exclusive access to `key` and `generation`.
        let (current_key, current_gen) = unsafe { (*self.key.get(), *self.generation.get()) };
        let nonce = [
            current_gen as u32,
            (current_gen >> 32) as u32,
            CHACHA_DOMAIN_NONCE[2],
        ];
        let mut block0 = chacha20_block(&current_key, 0, nonce);
        let mut next_key = [0u8; QEMU_RNG_SEED_BYTES];
        next_key.copy_from_slice(&block0[..QEMU_RNG_SEED_BYTES]);

        let mut written = 0usize;
        let first_take = dest.len().min(32);
        dest[..first_take].copy_from_slice(&block0[32..32 + first_take]);
        written += first_take;
        block0.fill(0);

        let mut counter = 1u32;
        while written < dest.len() {
            let mut block = chacha20_block(&current_key, counter, nonce);
            let take = (dest.len() - written).min(64);
            dest[written..written + take].copy_from_slice(&block[..take]);
            written += take;
            block.fill(0);
            counter = counter.wrapping_add(1);
        }

        // SAFETY: still holding CSPRNG_BORROWED; overwrite key with forward-secure rekeyed state.
        unsafe {
            *self.key.get() = next_key;
            *self.generation.get() = current_gen.wrapping_add(1);
        }
        next_key.fill(0);
        self.state.store(CSPRNG_READY, Ordering::Release);
        Ok(())
    }
}

fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: [u32; 3]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for i in 0..8 {
        let offset = i * 4;
        state[4 + i] = u32::from_le_bytes([
            key[offset],
            key[offset + 1],
            key[offset + 2],
            key[offset + 3],
        ]);
    }
    state[12] = counter;
    state[13] = nonce[0];
    state[14] = nonce[1];
    state[15] = nonce[2];

    let initial = state;
    for _ in 0..10 {
        chacha20_quarter_round(&mut state, 0, 4, 8, 12);
        chacha20_quarter_round(&mut state, 1, 5, 9, 13);
        chacha20_quarter_round(&mut state, 2, 6, 10, 14);
        chacha20_quarter_round(&mut state, 3, 7, 11, 15);
        chacha20_quarter_round(&mut state, 0, 5, 10, 15);
        chacha20_quarter_round(&mut state, 1, 6, 11, 12);
        chacha20_quarter_round(&mut state, 2, 7, 8, 13);
        chacha20_quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = state[i].wrapping_add(initial[i]).to_le_bytes();
        let offset = i * 4;
        out[offset..offset + 4].copy_from_slice(&word);
    }
    out
}

static QEMU_GETRANDOM: CsprngCell = CsprngCell::new();

/// Extracts the complete 32-byte root `/chosen/rng-seed` property prefix from a validated DTB.
///
/// QEMU ARM `virt` publishes 32 host-random bytes when DTB randomness is enabled. Step 30 retains
/// exactly those bytes so the initial image and one real exec receive disjoint 16-byte payloads.
/// Nested `rng-seed` properties do not count. Short, all-zero, or duplicate root-chosen seeds fail
/// closed.
pub fn extract_at_random(blob: &Blob<'_>) -> Result<[u8; QEMU_RNG_SEED_BYTES], Error> {
    let mut depth = 0usize;
    let mut chosen_depth = None;
    let mut found = None;

    for event in blob.events() {
        match event? {
            Event::BeginNode(name) => {
                depth = depth.checked_add(1).ok_or(Error::InvalidState)?;
                if depth == 2 && name == "chosen" {
                    chosen_depth = Some(depth);
                }
            }
            Event::Property { name, value } => {
                if chosen_depth == Some(depth) && name == "rng-seed" {
                    if found.is_some() {
                        return Err(Error::DuplicateSeed);
                    }
                    let prefix = value
                        .get(..QEMU_RNG_SEED_BYTES)
                        .ok_or(Error::SeedTooShort)?;
                    if prefix[..AT_RANDOM_BYTES] == [0u8; AT_RANDOM_BYTES]
                        || prefix[AT_RANDOM_BYTES..QEMU_RNG_SEED_BYTES] == [0u8; AT_RANDOM_BYTES]
                    {
                        return Err(Error::AllZeroSeed);
                    }
                    let mut seed = [0u8; QEMU_RNG_SEED_BYTES];
                    seed.copy_from_slice(prefix);
                    found = Some(seed);
                }
            }
            Event::EndNode => {
                if chosen_depth == Some(depth) {
                    chosen_depth = None;
                }
                depth = depth.checked_sub(1).ok_or(Error::InvalidState)?;
            }
        }
    }

    found.ok_or(Error::MissingSeed)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn read_be_cells(bytes: &[u8]) -> Option<u64> {
    match bytes.len() {
        4 => Some(u64::from(u32::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]))),
        8 => Some(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])),
        _ => None,
    }
}

/// Extracts usable physical RAM size starting at `expected_base` from DTB `/memory`.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) fn extract_memory_bytes(blob: &Blob<'_>, expected_base: u64) -> Option<u64> {
    let mut depth = 0usize;
    let mut addr_cells: usize = 2;
    let mut size_cells: usize = 1;
    let mut in_mem_node = false;
    let mut mem_name_match = false;
    let mut mem_type_match = false;
    let mut reg_buf = [0u8; 64];
    let mut reg_len = 0usize;

    for event in blob.events() {
        match event.ok()? {
            Event::BeginNode(name) => {
                depth = depth.checked_add(1)?;
                if depth == 2 {
                    in_mem_node = true;
                    mem_name_match = name == "memory" || name.starts_with("memory@");
                    mem_type_match = false;
                    reg_len = 0;
                }
            }
            Event::Property { name, value } => {
                if depth == 1 {
                    if name == "#address-cells" && value.len() == 4 {
                        addr_cells = usize::try_from(u32::from_be_bytes([
                            value[0], value[1], value[2], value[3],
                        ]))
                        .ok()?
                        .clamp(1, 2);
                    } else if name == "#size-cells" && value.len() == 4 {
                        size_cells = usize::try_from(u32::from_be_bytes([
                            value[0], value[1], value[2], value[3],
                        ]))
                        .ok()?
                        .clamp(1, 2);
                    }
                } else if depth == 2 && in_mem_node {
                    if name == "device_type" && (value == b"memory\0" || value == b"memory") {
                        mem_type_match = true;
                    } else if name == "reg" {
                        let take = value.len().min(reg_buf.len());
                        reg_buf[..take].copy_from_slice(&value[..take]);
                        reg_len = take;
                    }
                }
            }
            Event::EndNode => {
                if depth == 2 && in_mem_node {
                    if (mem_name_match || mem_type_match) && reg_len > 0 {
                        let a_bytes = addr_cells * 4;
                        let s_bytes = size_cells * 4;
                        let stride = a_bytes + s_bytes;
                        for entry in reg_buf[..reg_len].chunks_exact(stride) {
                            let base = read_be_cells(&entry[..a_bytes])?;
                            let size = read_be_cells(&entry[a_bytes..stride])?;
                            if base == expected_base && size > 0 {
                                return Some(size & !4095u64);
                            }
                        }
                    }
                    in_mem_node = false;
                }
                depth = depth.checked_sub(1)?;
            }
        }
    }
    None
}

/// Captures QEMU's complete DTB-provided randomness while the original DTB mapping is available.
///
/// # Safety
/// Must run in the QEMU proof boot before the protected-regime transition, under the parent module's
/// existing `qemu_dtb` bare-metal contract.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn publish_qemu_at_random() -> Result<(), Error> {
    // SAFETY: delegated caller contract; parent helper performs bounded header/Blob validation.
    let blob = unsafe {
        super::super::qemu_dtb(super::super::QEMU_VIRT_RAM_BASE).ok_or(Error::QemuDtbUnavailable)?
    };
    if let Some(ram_bytes) = extract_memory_bytes(&blob, super::super::QEMU_VIRT_RAM_BASE) {
        super::memory::publish_dtb_ram_bytes(ram_bytes);
    }
    let seed = extract_at_random(&blob)?;
    QEMU_AT_RANDOM.publish(seed)?;
    QEMU_GETRANDOM.publish(seed)
}

/// Seeds `AT_RANDOM` and the kernel ChaCha20 CSPRNG on native Raspberry Pi hardware.
///
/// Prefers `/chosen/rng-seed` from the firmware DTB when present, and falls back cleanly to a
/// ChaCha20-mixed seed combining VideoCore hardware revision, ARM memory size, and the hardware
/// virtual counter when booting with static official Raspberry Pi DTBs.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn publish_rpi_hardware_at_random(
    blob: &Blob<'_>,
    board_rev: u32,
    arm_ram_bytes: u32,
    counter: u64,
) -> Result<(), Error> {
    let seed = match extract_at_random(blob) {
        Ok(dtb_seed) => dtb_seed,
        Err(_) => {
            let mut key = [0u8; QEMU_RNG_SEED_BYTES];
            key[0..4].copy_from_slice(&board_rev.to_le_bytes());
            key[4..8].copy_from_slice(&arm_ram_bytes.to_le_bytes());
            key[8..16].copy_from_slice(&counter.to_le_bytes());
            key[16..24].copy_from_slice(&kernal_arch_aarch64::read_mpidr_el1().to_le_bytes());
            key[24..32].copy_from_slice(b"QYRN-RPI");
            let block = chacha20_block(&key, 1, [0x5250_4933, 0x3435_4857, 0x5345_4544]);
            let mut mixed = [0u8; QEMU_RNG_SEED_BYTES];
            mixed.copy_from_slice(&block[..QEMU_RNG_SEED_BYTES]);
            if mixed[..AT_RANDOM_BYTES] == [0u8; AT_RANDOM_BYTES] {
                mixed[0] = 0x5a;
            }
            if mixed[AT_RANDOM_BYTES..QEMU_RNG_SEED_BYTES] == [0u8; AT_RANDOM_BYTES] {
                mixed[AT_RANDOM_BYTES] = 0xa5;
            }
            mixed
        }
    };
    QEMU_AT_RANDOM.publish(seed)?;
    QEMU_GETRANDOM.publish(seed)
}

/// Fills `dest` with forward-secure ChaCha20 random bytes derived from the DTB seed for Step-31
/// `getrandom(2)` and Step-32 `/dev/random` / `/dev/urandom`.
pub fn fill_getrandom(dest: &mut [u8]) -> Result<(), Error> {
    QEMU_GETRANDOM.fill(dest)
}

/// Reports whether the DTB-seeded ChaCha20 CSPRNG has been initialized and is ready to serve
/// Step-31 `getrandom(2)` and Step-32 `/dev/random` / `/dev/urandom` reads.
pub fn is_csprng_ready() -> bool {
    QEMU_GETRANDOM.state.load(Ordering::Acquire) == CSPRNG_READY
}

/// Consumes the next of exactly two boot-provided Linux `AT_RANDOM` payloads.
///
/// Grant 0 is used by the initial Linux image. The live Step-30 exec path must use
/// [`with_exec_at_random`] for grant 1 so a reversible staging failure does not exhaust it.
pub fn take_at_random() -> Result<[u8; AT_RANDOM_BYTES], Error> {
    QEMU_AT_RANDOM.take()
}

/// Runs reversible live-exec staging with the second boot-provided `AT_RANDOM` payload.
///
/// The nested result separates entropy-owner failure from the caller's normal staging error. `Err(E)`
/// from `operation` restores the second grant unchanged; `Ok(R)` commits it permanently and every
/// later request fails with [`Error::Exhausted`]. The closure must encompass every ordinary fallible
/// preparation step before the live exec path crosses its irreversible old-image commit boundary.
pub fn with_exec_at_random<R, E>(
    operation: impl FnOnce([u8; AT_RANDOM_BYTES]) -> Result<R, E>,
) -> Result<Result<R, E>, Error> {
    QEMU_AT_RANDOM.with_second_transaction(operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_fdt::{CURRENT_VERSION, HEADER_SIZE, MAGIC};

    const BEGIN: u32 = 1;
    const END_NODE: u32 = 2;
    const PROP: u32 = 3;
    const END: u32 = 9;

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn align4(bytes: &mut Vec<u8>) {
        while !bytes.len().is_multiple_of(4) {
            bytes.push(0);
        }
    }

    fn begin(bytes: &mut Vec<u8>, name: &str) {
        push_u32(bytes, BEGIN);
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        align4(bytes);
    }

    fn prop(bytes: &mut Vec<u8>, name_offset: u32, value: &[u8]) {
        push_u32(bytes, PROP);
        push_u32(bytes, value.len() as u32);
        push_u32(bytes, name_offset);
        bytes.extend_from_slice(value);
        align4(bytes);
    }

    fn blob(seed: Option<&[u8]>, nested: bool, duplicate: bool) -> Vec<u8> {
        let reserve_offset = HEADER_SIZE;
        let structure_offset = reserve_offset + 16;
        let strings = b"rng-seed\0";
        let mut structure = Vec::new();
        begin(&mut structure, "");
        begin(&mut structure, "chosen");
        if let Some(seed) = seed {
            prop(&mut structure, 0, seed);
            if duplicate {
                prop(&mut structure, 0, seed);
            }
        }
        if nested {
            begin(&mut structure, "nested");
            prop(&mut structure, 0, &[0xa5; QEMU_RNG_SEED_BYTES]);
            push_u32(&mut structure, END_NODE);
        }
        push_u32(&mut structure, END_NODE);
        push_u32(&mut structure, END_NODE);
        push_u32(&mut structure, END);

        let strings_offset = structure_offset + structure.len();
        let total = strings_offset + strings.len();
        let mut bytes = vec![0u8; total];
        bytes[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        bytes[4..8].copy_from_slice(&(total as u32).to_be_bytes());
        bytes[8..12].copy_from_slice(&(structure_offset as u32).to_be_bytes());
        bytes[12..16].copy_from_slice(&(strings_offset as u32).to_be_bytes());
        bytes[16..20].copy_from_slice(&(reserve_offset as u32).to_be_bytes());
        bytes[20..24].copy_from_slice(&CURRENT_VERSION.to_be_bytes());
        bytes[24..28].copy_from_slice(&CURRENT_VERSION.to_be_bytes());
        bytes[32..36].copy_from_slice(&(strings.len() as u32).to_be_bytes());
        bytes[36..40].copy_from_slice(&(structure.len() as u32).to_be_bytes());
        bytes[structure_offset..strings_offset].copy_from_slice(&structure);
        bytes[strings_offset..].copy_from_slice(strings);
        bytes
    }

    #[test]
    fn extracts_complete_root_chosen_seed() {
        let mut source = [0x40u8; QEMU_RNG_SEED_BYTES];
        source[AT_RANDOM_BYTES..].fill(0x80);
        let bytes = blob(Some(&source), false, false);
        let parsed = Blob::parse(&bytes).unwrap();
        assert_eq!(extract_at_random(&parsed).unwrap(), source);
    }

    #[test]
    fn nested_seed_does_not_replace_root_seed() {
        let source = [0x31u8; QEMU_RNG_SEED_BYTES];
        let bytes = blob(Some(&source), true, false);
        let parsed = Blob::parse(&bytes).unwrap();
        assert_eq!(extract_at_random(&parsed).unwrap(), source);
    }

    #[test]
    fn missing_short_and_duplicate_seed_fail_closed() {
        let bytes = blob(None, false, false);
        assert_eq!(
            extract_at_random(&Blob::parse(&bytes).unwrap()),
            Err(Error::MissingSeed)
        );
        let short = blob(Some(&[7u8; QEMU_RNG_SEED_BYTES - 1]), false, false);
        assert_eq!(
            extract_at_random(&Blob::parse(&short).unwrap()),
            Err(Error::SeedTooShort)
        );
        let duplicate = blob(Some(&[9u8; QEMU_RNG_SEED_BYTES]), false, true);
        assert_eq!(
            extract_at_random(&Blob::parse(&duplicate).unwrap()),
            Err(Error::DuplicateSeed)
        );
    }

    #[test]
    fn seed_cell_serves_two_disjoint_linear_grants_then_exhausts() {
        let cell = SeedCell::new();
        assert_eq!(cell.take(), Err(Error::MissingSeed));

        let mut seed = [0u8; QEMU_RNG_SEED_BYTES];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = index as u8;
        }
        cell.publish(seed).unwrap();

        let expected_first: [u8; AT_RANDOM_BYTES] = core::array::from_fn(|index| index as u8);
        let expected_second: [u8; AT_RANDOM_BYTES] =
            core::array::from_fn(|index| (index + AT_RANDOM_BYTES) as u8);
        assert_eq!(cell.take().unwrap(), expected_first);
        assert_eq!(cell.take().unwrap(), expected_second);
        assert_eq!(cell.take(), Err(Error::Exhausted));
        assert_eq!(cell.publish(seed), Err(Error::AlreadyPublished));
    }

    #[test]
    fn exec_grant_rolls_back_on_failed_staging_and_commits_only_on_success() {
        let cell = SeedCell::new();
        let mut seed = [0u8; QEMU_RNG_SEED_BYTES];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = index as u8;
        }
        cell.publish(seed).unwrap();

        let expected_first: [u8; AT_RANDOM_BYTES] = core::array::from_fn(|index| index as u8);
        let expected_second: [u8; AT_RANDOM_BYTES] =
            core::array::from_fn(|index| (index + AT_RANDOM_BYTES) as u8);

        assert_eq!(
            cell.with_second_transaction(|_| Ok::<(), ()>(())),
            Err(Error::InvalidState)
        );
        assert_eq!(cell.take().unwrap(), expected_first);

        let failed = cell
            .with_second_transaction(|grant| {
                assert_eq!(grant, expected_second);
                Err::<(), u8>(7)
            })
            .unwrap();
        assert_eq!(failed, Err(7));

        let retried = cell.with_second_transaction(Ok::<_, u8>).unwrap();
        assert_eq!(retried, Ok(expected_second));
        assert_eq!(cell.take(), Err(Error::Exhausted));
        assert_eq!(
            cell.with_second_transaction(|_| Ok::<(), ()>(())),
            Err(Error::Exhausted)
        );
    }

    #[test]
    fn all_zero_rng_seed_half_is_rejected_by_extract_at_random() {
        let mut first_half_zero = [0x11u8; QEMU_RNG_SEED_BYTES];
        first_half_zero[..AT_RANDOM_BYTES].fill(0);
        let bytes = blob(Some(&first_half_zero), false, false);
        assert_eq!(
            extract_at_random(&Blob::parse(&bytes).unwrap()),
            Err(Error::AllZeroSeed)
        );

        let mut second_half_zero = [0x11u8; QEMU_RNG_SEED_BYTES];
        second_half_zero[AT_RANDOM_BYTES..].fill(0);
        let bytes = blob(Some(&second_half_zero), false, false);
        assert_eq!(
            extract_at_random(&Blob::parse(&bytes).unwrap()),
            Err(Error::AllZeroSeed)
        );
    }

    #[test]
    fn csprng_cell_produces_forward_secure_non_zero_getrandom_streams() {
        let csprng = CsprngCell::new();
        let mut out1 = [0u8; 96];
        let mut out2 = [0u8; 96];
        assert_eq!(csprng.fill(&mut out1), Err(Error::MissingSeed));
        assert_eq!(
            csprng.publish([0u8; QEMU_RNG_SEED_BYTES]),
            Err(Error::AllZeroSeed)
        );

        let seed: [u8; QEMU_RNG_SEED_BYTES] = core::array::from_fn(|i| (i as u8).wrapping_add(1));
        csprng.publish(seed).unwrap();
        assert_eq!(csprng.publish(seed), Err(Error::AlreadyPublished));

        csprng.fill(&mut out1).unwrap();
        csprng.fill(&mut out2).unwrap();
        assert_ne!(out1, [0u8; 96]);
        assert_ne!(out2, [0u8; 96]);
        assert_ne!(out1, out2);
        assert_ne!(&out1[..16], &seed[..16]);
        assert_ne!(&out1[..16], &seed[16..32]);
    }
}
