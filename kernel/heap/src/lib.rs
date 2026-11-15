// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::{NonNull, null_mut};
use core::sync::atomic::{AtomicBool, Ordering};

const MIN_BLOCK_BYTES: usize = 16;

#[repr(C)]
struct FreeNode {
    size: usize,
    next: Option<NonNull<FreeNode>>,
}

const _: () = assert!(core::mem::size_of::<FreeNode>() <= MIN_BLOCK_BYTES);
const _: () = assert!(MIN_BLOCK_BYTES.is_power_of_two());
const _: () = assert!(core::mem::align_of::<FreeNode>() <= MIN_BLOCK_BYTES);

/// Bounded allocation statistics reported by [`LockedArenaHeap::stats`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HeapStats {
    pub initialized: bool,
    pub total_bytes: usize,
    pub used_bytes: usize,
    pub free_bytes: usize,
    pub peak_used_bytes: usize,
    pub free_blocks: usize,
    pub allocation_count: usize,
}

/// Initialization error for [`LockedArenaHeap::init_range`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeapError {
    InvalidRange,
    AlreadyInitialized,
}

struct ArenaHeap {
    initialized: bool,
    head: Option<NonNull<FreeNode>>,
    total_bytes: usize,
    used_bytes: usize,
    peak_used_bytes: usize,
    allocation_count: usize,
}

impl ArenaHeap {
    const fn empty() -> Self {
        Self {
            initialized: false,
            head: None,
            total_bytes: 0,
            used_bytes: 0,
            peak_used_bytes: 0,
            allocation_count: 0,
        }
    }

    unsafe fn init_range(&mut self, start: *mut u8, len: usize) -> Result<(), HeapError> {
        if self.initialized {
            return Err(HeapError::AlreadyInitialized);
        }
        if start.is_null() || len < MIN_BLOCK_BYTES {
            return Err(HeapError::InvalidRange);
        }

        let raw_start = start as usize;
        let raw_end = raw_start.checked_add(len).ok_or(HeapError::InvalidRange)?;
        let aligned_start = align_up(raw_start, MIN_BLOCK_BYTES).ok_or(HeapError::InvalidRange)?;
        let aligned_end = align_down(raw_end, MIN_BLOCK_BYTES);
        if aligned_end <= aligned_start {
            return Err(HeapError::InvalidRange);
        }
        let usable = aligned_end - aligned_start;
        if usable < MIN_BLOCK_BYTES {
            return Err(HeapError::InvalidRange);
        }

        let node_ptr = start.wrapping_add(aligned_start - raw_start) as *mut FreeNode;
        // SAFETY: caller guarantees `[start, start + len)` is exclusively owned RW memory inside a
        // single allocated/linker-reserved region, and `aligned_start` is 16-byte aligned with at
        // least `MIN_BLOCK_BYTES` bytes before `aligned_end`.
        unsafe {
            node_ptr.write(FreeNode {
                size: usable,
                next: None,
            });
        }
        self.head = NonNull::new(node_ptr);
        self.total_bytes = usable;
        self.used_bytes = 0;
        self.peak_used_bytes = 0;
        self.allocation_count = 0;
        self.initialized = true;
        Ok(())
    }

    fn allocate(&mut self, layout: Layout) -> *mut u8 {
        if !self.initialized {
            return null_mut();
        }
        let Some(req_size) = align_up(layout.size().max(MIN_BLOCK_BYTES), MIN_BLOCK_BYTES) else {
            return null_mut();
        };
        let req_align = layout.align().max(MIN_BLOCK_BYTES);
        if !req_align.is_power_of_two() {
            return null_mut();
        }

        let mut prev: Option<NonNull<FreeNode>> = None;
        let mut cursor = self.head;
        while let Some(cur_nn) = cursor {
            let cur_ptr = cur_nn.as_ptr();
            // SAFETY: every node on `self.head` was initialized by `init_range`, split, or `dealloc`
            // within the exclusively owned arena while the heap lock is held.
            let (node_size, next) = unsafe { ((*cur_ptr).size, (*cur_ptr).next) };
            let node_start = cur_ptr as usize;
            let Some(node_end) = node_start.checked_add(node_size) else {
                return null_mut();
            };

            let Some(alloc_start) = align_up(node_start, req_align) else {
                prev = Some(cur_nn);
                cursor = next;
                continue;
            };
            let Some(alloc_end) = alloc_start.checked_add(req_size) else {
                prev = Some(cur_nn);
                cursor = next;
                continue;
            };
            if alloc_end > node_end {
                prev = Some(cur_nn);
                cursor = next;
                continue;
            }

            let prefix = alloc_start - node_start;
            let suffix = node_end - alloc_end;
            debug_assert!(prefix == 0 || prefix >= MIN_BLOCK_BYTES);
            debug_assert!(suffix == 0 || suffix >= MIN_BLOCK_BYTES);

            let replacement = if prefix > 0 {
                if suffix > 0 {
                    let suffix_ptr =
                        (cur_ptr as *mut u8).wrapping_add(alloc_end - node_start) as *mut FreeNode;
                    // SAFETY: `[alloc_end, node_end)` lies strictly inside `cur_ptr`'s free region,
                    // is 16-byte aligned, and holds at least `MIN_BLOCK_BYTES` bytes.
                    unsafe {
                        suffix_ptr.write(FreeNode { size: suffix, next });
                    }
                    // SAFETY: `cur_ptr` remains exclusively owned for `[node_start, alloc_start)`.
                    unsafe {
                        (*cur_ptr).size = prefix;
                        (*cur_ptr).next = NonNull::new(suffix_ptr);
                    }
                } else {
                    // SAFETY: `cur_ptr` remains exclusively owned for `[node_start, alloc_start)`.
                    unsafe {
                        (*cur_ptr).size = prefix;
                        (*cur_ptr).next = next;
                    }
                }
                Some(cur_nn)
            } else if suffix > 0 {
                let suffix_ptr =
                    (cur_ptr as *mut u8).wrapping_add(alloc_end - node_start) as *mut FreeNode;
                // SAFETY: `[alloc_end, node_end)` lies strictly inside `cur_ptr`'s free region,
                // is 16-byte aligned, and holds at least `MIN_BLOCK_BYTES` bytes.
                unsafe {
                    suffix_ptr.write(FreeNode { size: suffix, next });
                }
                NonNull::new(suffix_ptr)
            } else {
                next
            };

            match prev {
                // SAFETY: `prev_nn` is a valid free-list node whose `next` field pointed to `cur_nn`.
                Some(prev_nn) => unsafe { (*prev_nn.as_ptr()).next = replacement },
                None => self.head = replacement,
            }

            self.used_bytes += req_size;
            if self.used_bytes > self.peak_used_bytes {
                self.peak_used_bytes = self.used_bytes;
            }
            self.allocation_count += 1;
            return (cur_ptr as *mut u8).wrapping_add(prefix);
        }

        null_mut()
    }

    unsafe fn deallocate(&mut self, ptr: *mut u8, layout: Layout) {
        if !self.initialized || ptr.is_null() {
            return;
        }
        let Some(freed_size) = align_up(layout.size().max(MIN_BLOCK_BYTES), MIN_BLOCK_BYTES) else {
            return;
        };
        let freed_addr = ptr as usize;
        if freed_addr & (MIN_BLOCK_BYTES - 1) != 0 {
            return;
        }
        let Some(freed_end) = freed_addr.checked_add(freed_size) else {
            return;
        };

        let mut prev: Option<NonNull<FreeNode>> = None;
        let mut cur = self.head;
        while let Some(cur_nn) = cur {
            let cur_addr = cur_nn.as_ptr() as usize;
            if cur_addr > freed_addr {
                break;
            }
            prev = Some(cur_nn);
            // SAFETY: every node reachable from `self.head` is a valid free-list node under lock.
            cur = unsafe { (*cur_nn.as_ptr()).next };
        }

        let freed_ptr = ptr as *mut FreeNode;
        // SAFETY: caller returns ownership of the `[ptr, ptr + freed_size)` block originally
        // handed out by `allocate` for `layout`; its address and size satisfy `FreeNode`.
        unsafe {
            freed_ptr.write(FreeNode {
                size: freed_size,
                next: cur,
            });
        }
        let mut active_nn = match NonNull::new(freed_ptr) {
            Some(nn) => nn,
            None => return,
        };

        // Coalesce with immediate address successor if contiguous.
        if let Some(next_nn) = cur {
            let next_addr = next_nn.as_ptr() as usize;
            if freed_end == next_addr {
                // SAFETY: both `active_nn` and `next_nn` are contiguous free-list blocks.
                unsafe {
                    (*active_nn.as_ptr()).size += (*next_nn.as_ptr()).size;
                    (*active_nn.as_ptr()).next = (*next_nn.as_ptr()).next;
                }
            }
        }

        // Link to predecessor and coalesce if contiguous.
        match prev {
            Some(prev_nn) => {
                let prev_addr = prev_nn.as_ptr() as usize;
                // SAFETY: `prev_nn` is a valid free-list node under the heap lock.
                let prev_size = unsafe { (*prev_nn.as_ptr()).size };
                if prev_addr + prev_size == freed_addr {
                    // SAFETY: `prev_nn` and `active_nn` are contiguous free-list blocks.
                    unsafe {
                        (*prev_nn.as_ptr()).size = prev_size + (*active_nn.as_ptr()).size;
                        (*prev_nn.as_ptr()).next = (*active_nn.as_ptr()).next;
                    }
                    active_nn = prev_nn;
                } else {
                    // SAFETY: `prev_nn` precedes `active_nn` in sorted address order.
                    unsafe { (*prev_nn.as_ptr()).next = Some(active_nn) };
                }
            }
            None => {
                self.head = Some(active_nn);
            }
        }

        let _ = active_nn;
        self.used_bytes = self.used_bytes.saturating_sub(freed_size);
    }

    fn stats(&self) -> HeapStats {
        let mut free_bytes = 0usize;
        let mut free_blocks = 0usize;
        let mut cursor = self.head;
        while let Some(cur_nn) = cursor {
            // SAFETY: every node in `self.head` is valid under the heap lock.
            let (size, next) = unsafe { ((*cur_nn.as_ptr()).size, (*cur_nn.as_ptr()).next) };
            free_bytes += size;
            free_blocks += 1;
            cursor = next;
        }
        HeapStats {
            initialized: self.initialized,
            total_bytes: self.total_bytes,
            used_bytes: self.used_bytes,
            free_bytes,
            peak_used_bytes: self.peak_used_bytes,
            free_blocks,
            allocation_count: self.allocation_count,
        }
    }
}

/// Bounded coalescing free-list kernel heap guarded by an IRQ-safe spinlock.
///
/// Fails closed (returns null pointers and `HeapStats::default()`) until [`init_range`] succeeds.
pub struct LockedArenaHeap {
    locked: AtomicBool,
    heap: UnsafeCell<ArenaHeap>,
}

// SAFETY: mutable access to `heap` is serialized across CPUs/contexts by `locked` + IRQ masking.
unsafe impl Sync for LockedArenaHeap {}

impl LockedArenaHeap {
    /// Creates an uninitialized fail-closed allocator suitable for `static` storage.
    pub const fn empty() -> Self {
        Self {
            locked: AtomicBool::new(false),
            heap: UnsafeCell::new(ArenaHeap::empty()),
        }
    }

    /// Initializes the heap over the half-open RW region `[start, start + len)`.
    ///
    /// # Safety
    ///
    /// Caller must ensure `[start, start + len)` points to valid, exclusively owned, mutable RW
    /// memory that outlives every allocation made from this heap.
    pub unsafe fn init_range(&self, start: *mut u8, len: usize) -> Result<(), HeapError> {
        let _guard = self.lock();
        // SAFETY: `_guard` serializes exclusive mutable access to `self.heap`.
        unsafe { (*self.heap.get()).init_range(start, len) }
    }

    /// Returns a point-in-time snapshot of heap utilization and fragmentation.
    pub fn stats(&self) -> HeapStats {
        let _guard = self.lock();
        // SAFETY: `_guard` serializes access to `self.heap`.
        unsafe { (*self.heap.get()).stats() }
    }

    fn lock(&self) -> HeapGuard<'_> {
        let saved_daif = irq_save_and_mask();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        HeapGuard {
            locked: &self.locked,
            saved_daif,
        }
    }
}

unsafe impl GlobalAlloc for LockedArenaHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _guard = self.lock();
        // SAFETY: `_guard` serializes exclusive mutable access to `self.heap`.
        unsafe { (*self.heap.get()).allocate(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _guard = self.lock();
        // SAFETY: `_guard` serializes exclusive mutable access to `self.heap`, and `GlobalAlloc`
        // contract guarantees `ptr`/`layout` came from a matching prior allocation.
        unsafe { (*self.heap.get()).deallocate(ptr, layout) }
    }
}

struct HeapGuard<'a> {
    locked: &'a AtomicBool,
    saved_daif: u64,
}

impl Drop for HeapGuard<'_> {
    fn drop(&mut self) {
        self.locked.store(false, Ordering::Release);
        irq_restore(self.saved_daif);
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline]
fn irq_save_and_mask() -> u64 {
    let daif: u64;
    // SAFETY: reading and masking DAIF.I on EL1 bare-metal prevents single-CPU IRQ reentrancy
    // while the heap lock is held; the original DAIF mask is restored on guard drop.
    unsafe {
        core::arch::asm!(
            "mrs {0}, daif",
            "msr daifset, #2",
            out(reg) daif,
            options(nomem, nostack),
        );
    }
    daif
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
#[inline]
fn irq_save_and_mask() -> u64 {
    0
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline]
fn irq_restore(saved_daif: u64) {
    // SAFETY: restores the exact DAIF state saved in `irq_save_and_mask`.
    unsafe {
        core::arch::asm!(
            "msr daif, {0}",
            in(reg) saved_daif,
            options(nomem, nostack),
        );
    }
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
#[inline]
fn irq_restore(_saved_daif: u64) {}

const fn align_up(value: usize, align: usize) -> Option<usize> {
    let mask = align - 1;
    match value.checked_add(mask) {
        Some(v) => Some(v & !mask),
        None => None,
    }
}

const fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(4096))]
    struct AlignedBacking<const N: usize>([u8; N]);

    #[test]
    fn uninitialized_heap_fails_closed() {
        let heap = LockedArenaHeap::empty();
        let layout = Layout::from_size_align(64, 8).unwrap();
        // SAFETY: exercising fail-closed uninitialized allocation path.
        let ptr = unsafe { heap.alloc(layout) };
        assert!(ptr.is_null());
        assert!(!heap.stats().initialized);
    }

    #[test]
    fn init_rejects_invalid_and_double_init() {
        let heap = LockedArenaHeap::empty();
        // SAFETY: invalid null/tiny ranges are rejected before dereferencing.
        assert_eq!(
            unsafe { heap.init_range(null_mut(), 4096) },
            Err(HeapError::InvalidRange)
        );

        let mut backing = AlignedBacking([0u8; 4096]);
        // SAFETY: too small after alignment cannot even hold one block.
        assert_eq!(
            unsafe { heap.init_range(backing.0.as_mut_ptr(), 8) },
            Err(HeapError::InvalidRange)
        );

        // SAFETY: exclusive test backing buffer.
        assert_eq!(
            unsafe { heap.init_range(backing.0.as_mut_ptr(), backing.0.len()) },
            Ok(())
        );
        // SAFETY: double initialization must fail closed.
        assert_eq!(
            unsafe { heap.init_range(backing.0.as_mut_ptr(), backing.0.len()) },
            Err(HeapError::AlreadyInitialized)
        );
    }

    #[test]
    fn alloc_align_and_out_of_order_coalesce_preserves_every_byte() {
        let mut backing = AlignedBacking([0u8; 16384]);
        let heap = LockedArenaHeap::empty();
        // SAFETY: exclusive test buffer outlives `heap`.
        unsafe { heap.init_range(backing.0.as_mut_ptr(), backing.0.len()) }.unwrap();

        let l1 = Layout::from_size_align(24, 8).unwrap();
        let l2 = Layout::from_size_align(100, 64).unwrap();
        let l3 = Layout::from_size_align(4096, 4096).unwrap();
        let l4 = Layout::from_size_align(256, 16).unwrap();

        // SAFETY: valid initialized heap and non-zero layouts.
        let p1 = unsafe { heap.alloc(l1) };
        let p2 = unsafe { heap.alloc(l2) };
        let p3 = unsafe { heap.alloc(l3) };
        let p4 = unsafe { heap.alloc(l4) };

        assert!(!p1.is_null());
        assert!(!p2.is_null());
        assert_eq!((p2 as usize) % 64, 0);
        assert!(!p3.is_null());
        assert_eq!((p3 as usize) % 4096, 0);
        assert!(!p4.is_null());

        // Write distinct sentinel patterns to verify disjointness.
        // SAFETY: allocated regions belong exclusively to each pointer and do not overlap.
        unsafe {
            p1.write_bytes(0x11, l1.size());
            p2.write_bytes(0x22, l2.size());
            p3.write_bytes(0x33, l3.size());
            p4.write_bytes(0x44, l4.size());
        }

        // Free out of order so prefix + middle + suffix coalescing all execute.
        // SAFETY: each pointer matches its exact allocation layout.
        unsafe {
            heap.dealloc(p2, l2);
            heap.dealloc(p4, l4);
            heap.dealloc(p1, l1);
            heap.dealloc(p3, l3);
        }

        let stats = heap.stats();
        assert_eq!(stats.used_bytes, 0);
        assert_eq!(stats.free_bytes, 16384);
        assert_eq!(stats.free_blocks, 1);

        // Entire 16 KiB can now be reallocated cleanly in one chunk!
        let whole = Layout::from_size_align(16384, 4096).unwrap();
        // SAFETY: re-acquires the fully coalesced block.
        let pw = unsafe { heap.alloc(whole) };
        assert!(!pw.is_null());
        assert_eq!((pw as usize) % 4096, 0);
        // SAFETY: freeing exact full-arena block.
        unsafe { heap.dealloc(pw, whole) };
        assert_eq!(heap.stats().free_blocks, 1);
    }

    #[test]
    fn oom_fails_closed_without_corrupting_existing_allocations() {
        let mut backing = AlignedBacking([0u8; 4096]);
        let heap = LockedArenaHeap::empty();
        // SAFETY: exclusive buffer outlives `heap`.
        unsafe { heap.init_range(backing.0.as_mut_ptr(), backing.0.len()) }.unwrap();

        let l1 = Layout::from_size_align(2048, 64).unwrap();
        let huge = Layout::from_size_align(4096, 16).unwrap();

        // SAFETY: valid heap allocations.
        let p1 = unsafe { heap.alloc(l1) };
        assert!(!p1.is_null());
        // SAFETY: exercising fail-closed OOM path.
        let p2 = unsafe { heap.alloc(huge) };
        assert!(p2.is_null());

        let stats = heap.stats();
        assert_eq!(stats.used_bytes, 2048);
        assert_eq!(stats.free_bytes, 2048);

        // SAFETY: matches `p1`.
        unsafe { heap.dealloc(p1, l1) };
        assert_eq!(heap.stats().used_bytes, 0);
    }

    #[test]
    fn unaligned_range_trims_cleanly_to_16_byte_invariants() {
        let mut backing = AlignedBacking([0u8; 4096]);
        let heap = LockedArenaHeap::empty();
        // Offset start by 3 bytes and shrink length by 5 bytes.
        // SAFETY: slice lies inside `backing`.
        let unaligned_ptr = unsafe { backing.0.as_mut_ptr().add(3) };
        // SAFETY: `[unaligned_ptr, unaligned_ptr + 4088)` stays inside `backing`.
        unsafe { heap.init_range(unaligned_ptr, 4088) }.unwrap();

        let stats = heap.stats();
        assert_eq!(stats.total_bytes % MIN_BLOCK_BYTES, 0);
        assert_eq!(stats.free_bytes, stats.total_bytes);
        assert!(stats.total_bytes >= 4064);
    }
}
