// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_abi::{Errno, linux_signed_int};
use kernal_vm::{PAGE_SIZE, VmPerms};

use crate::{
    BackendFailure, DEFAULT_MMAP_CEILING, Error, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ,
    PROT_WRITE, PageBackend, align_up_page, no_memory_error, page_rounded_length,
    validate_page_range,
};

/// Linux `PROT_NONE` protection constant (`0x0`, guard-page reservations).
pub const PROT_NONE: u64 = 0x0;
/// Linux `MAP_SHARED` flag (`0x01`, shared mapping).
pub const MAP_SHARED: u64 = 0x01;
/// Linux `MAP_SHARED_VALIDATE` flag (`0x03`).
pub const MAP_SHARED_VALIDATE: u64 = 0x03;
/// Linux `MAP_FIXED` flag (`0x10`, exact page-aligned address placement/replacement).
pub const MAP_FIXED: u64 = 0x10;
/// Linux `MAP_DENYWRITE` flag (`0x0800`, ignored per Linux UAPI, passed by `ld.so`).
pub const MAP_DENYWRITE: u64 = 0x0800;
/// Linux `MAP_EXECUTABLE` flag (`0x1000`, ignored per Linux UAPI, passed by `ld.so`).
pub const MAP_EXECUTABLE: u64 = 0x1000;
/// Linux `MAP_NORESERVE` flag (`0x4000`, ignored on eager-backing mappings).
pub const MAP_NORESERVE: u64 = 0x4000;
/// Linux `MAP_POPULATE` flag (`0x8000`, satisfied by eager page population).
pub const MAP_POPULATE: u64 = 0x8000;
/// Linux `MAP_NONBLOCK` flag (`0x10000`, ignored together with `MAP_POPULATE`).
pub const MAP_NONBLOCK: u64 = 0x10000;
/// Linux `MAP_STACK` flag (`0x20000`, advisory stack mapping hint passed by `glibc` `pthread_create`).
pub const MAP_STACK: u64 = 0x20000;

/// Complete mask of `mmap(2)` flags accepted by the Step-31 dynamic linker and libc VM owner.
pub const STEP31_ALLOWED_MMAP_FLAGS: u64 = MAP_SHARED
    | MAP_PRIVATE
    | MAP_ANONYMOUS
    | MAP_FIXED
    | MAP_DENYWRITE
    | MAP_EXECUTABLE
    | MAP_NORESERVE
    | MAP_POPULATE
    | MAP_NONBLOCK
    | MAP_STACK;

/// Extension of [`PageBackend`] that can populate a freshly allocated physical frame with file
/// bytes before exposing the mapping to userspace.
///
/// This preserves strict `W^X`: a `PROT_READ | PROT_EXEC` or `PROT_READ` file segment is populated
/// through the kernel's temporary KMap window while still unmapped in TTBR0, then mapped with its
/// final read-only/executable user permissions.
pub trait DynamicPageBackend: PageBackend {
    fn allocate_initialized_page(
        &mut self,
        bytes: &[u8; PAGE_SIZE as usize],
    ) -> Result<u64, BackendFailure>;
}

/// Source data for a Step-31 `mmap(2)` transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmapFileBacking<'a> {
    Anonymous,
    FileSlice { bytes: &'a [u8], file_offset: u64 },
}

/// Validated Step-31 `mmap(2)` flag and protection parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Step31MmapSpec {
    pub perms: VmPerms,
    pub anonymous: bool,
    pub shared: bool,
    pub fixed: bool,
    pub offset: u64,
}

/// Parses and validates `mmap(2)` / `mprotect(2)` protection flags for Step-31 dynamic loading.
///
/// Admits `PROT_NONE` (`0`), `PROT_READ`, `PROT_READ | PROT_WRITE`, `PROT_READ | PROT_EXEC`, and
/// `PROT_EXEC` while rejecting any `W+X` (`PROT_WRITE | PROT_EXEC`) combination or unknown flag
/// bits with `EINVAL`.
pub fn parse_step31_perms(protection: u64) -> Result<VmPerms, Error> {
    if protection & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    let mut perms = VmPerms::NONE;
    if protection & PROT_READ != 0 {
        perms = perms.union(VmPerms::READ);
    }
    if protection & PROT_WRITE != 0 {
        perms = perms.union(VmPerms::WRITE);
    }
    if protection & PROT_EXEC != 0 {
        perms = perms.union(VmPerms::EXECUTE);
    }
    if perms.writable() && !perms.readable() {
        return Err(Error::Linux(Errno::EINVAL));
    }
    if perms.validate().is_err() {
        return Err(Error::Linux(Errno::EINVAL));
    }
    Ok(perms)
}

/// Validates Step-31 `mmap(2)` flags, file descriptor sentinel, and page-aligned offset.
pub fn validate_step31_mmap_spec(
    protection: u64,
    flags: u64,
    fd: u64,
    offset: u64,
) -> Result<Step31MmapSpec, Error> {
    let share_kind = flags & 0x03;
    if !matches!(share_kind, MAP_SHARED | MAP_PRIVATE | MAP_SHARED_VALIDATE)
        || (flags & !STEP31_ALLOWED_MMAP_FLAGS) != 0
    {
        return Err(Error::Linux(Errno::EINVAL));
    }
    if offset & (PAGE_SIZE - 1) != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    let anonymous = flags & MAP_ANONYMOUS != 0;
    if anonymous && (linux_signed_int(fd) != -1 || offset != 0) {
        return Err(Error::Linux(Errno::EINVAL));
    }
    let perms = parse_step31_perms(protection)?;
    Ok(Step31MmapSpec {
        perms,
        anonymous,
        shared: share_kind != MAP_PRIVATE,
        fixed: flags & MAP_FIXED != 0,
        offset,
    })
}

/// Executes a Step-31 dynamic linker `mmap(2)` transaction supporting `MAP_PRIVATE`, `MAP_FIXED`,
/// `MAP_DENYWRITE`, `PROT_NONE`, `PROT_EXEC` (W^X), and file-backed segment population.
#[allow(clippy::too_many_arguments)]
pub fn mmap_step31_dynamic<const TX_PAGES: usize, B: DynamicPageBackend>(
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    fd: u64,
    offset: u64,
    backing: MmapFileBacking<'_>,
    backend: &mut B,
) -> Result<u64, Error> {
    let spec = validate_step31_mmap_spec(protection, flags, fd, offset)?;
    match (spec.anonymous, backing) {
        (true, MmapFileBacking::Anonymous) | (false, MmapFileBacking::FileSlice { .. }) => {}
        _ => return Err(Error::Linux(Errno::EINVAL)),
    }

    let len = page_rounded_length(length).ok_or(Error::Linux(Errno::EINVAL))?;
    let pages = usize::try_from(len / PAGE_SIZE).map_err(|_| no_memory_error())?;
    if pages > TX_PAGES {
        return Err(no_memory_error());
    }

    let start = if spec.fixed {
        validate_page_range(address, len)?;
        address
    } else if address == 0 {
        find_gap(backend, len)?
    } else {
        validate_page_range(address, len)?;
        match backend.range_is_free(address, len) {
            Ok(true) => address,
            Ok(false) => find_gap(backend, len)?,
            Err(BackendFailure::NoMemory) => return Err(no_memory_error()),
            Err(_) => return Err(Error::BackendInvariant),
        }
    };
    validate_page_range(start, len)?;

    let mut had_displaced = false;
    if spec.fixed {
        for page in 0..pages {
            let va = start + page as u64 * PAGE_SIZE;
            match backend.unmap_page(va) {
                Ok(frame) => {
                    if core::num::NonZeroU64::new(frame).is_none()
                        || backend.free_page(frame).is_err()
                    {
                        backend.poison();
                        return Err(Error::BackendInvariant);
                    }
                    had_displaced = true;
                }
                Err(BackendFailure::NotMapped) => {}
                Err(_) => {
                    backend.poison();
                    return Err(Error::BackendInvariant);
                }
            }
        }
    } else {
        match backend.range_is_free(start, len) {
            Ok(true) => {}
            Ok(false) => return Err(Error::BackendInvariant),
            Err(BackendFailure::NoMemory) => return Err(no_memory_error()),
            Err(_) => return Err(Error::BackendInvariant),
        }
    }

    for page in 0..pages {
        let va = start + page as u64 * PAGE_SIZE;
        let alloc_result = match backing {
            MmapFileBacking::Anonymous => backend.allocate_page(),
            MmapFileBacking::FileSlice { bytes, file_offset } => {
                let page_file_offset = file_offset.saturating_add(page as u64 * PAGE_SIZE);
                if let Ok(start_idx) = usize::try_from(page_file_offset)
                    && start_idx < bytes.len()
                {
                    let end_idx = start_idx
                        .saturating_add(PAGE_SIZE as usize)
                        .min(bytes.len());
                    let slice = &bytes[start_idx..end_idx];
                    let mut page_buf = [0u8; PAGE_SIZE as usize];
                    page_buf[..slice.len()].copy_from_slice(slice);
                    backend.allocate_initialized_page(&page_buf)
                } else {
                    backend.allocate_page()
                }
            }
        };
        let frame = match alloc_result {
            Ok(frame) => frame,
            Err(BackendFailure::NoMemory) => {
                rollback_dynamic_mmap(backend, start, page, had_displaced);
                return Err(no_memory_error());
            }
            Err(_) => {
                rollback_dynamic_mmap(backend, start, page, had_displaced);
                return Err(Error::BackendInvariant);
            }
        };

        if let Err(err) = backend.map_page(va, frame, spec.perms) {
            let _ = backend.free_page(frame);
            rollback_dynamic_mmap(backend, start, page, had_displaced);
            return match err {
                BackendFailure::NoMemory => Err(no_memory_error()),
                _ => Err(Error::BackendInvariant),
            };
        }
    }

    Ok(start)
}

/// Executes Step-31 `mprotect(2)` admitting `PROT_NONE`, `PROT_READ`, `PROT_READ | PROT_WRITE`,
/// and `PROT_READ | PROT_EXEC` while rejecting `W+X`.
pub fn mprotect_step31<const TX_PAGES: usize, B: PageBackend>(
    address: u64,
    length: u64,
    protection: u64,
    backend: &mut B,
) -> Result<(), Error> {
    let perms = parse_step31_perms(protection)?;
    if length == 0 {
        return validate_page_range(address, PAGE_SIZE);
    }
    let len = page_rounded_length(length).ok_or(Error::Linux(Errno::EINVAL))?;
    validate_page_range(address, len)?;
    let pages = usize::try_from(len / PAGE_SIZE).map_err(|_| no_memory_error())?;
    if pages > TX_PAGES {
        return Err(no_memory_error());
    }

    for page in 0..pages {
        let va = address + page as u64 * PAGE_SIZE;
        match backend.page_is_mapped(va) {
            Ok(true) => {}
            Ok(false) | Err(BackendFailure::NotMapped | BackendFailure::NoMemory) => {
                return Err(no_memory_error());
            }
            Err(BackendFailure::Invariant) => return Err(Error::BackendInvariant),
        }
    }

    let mut mutated = false;
    for page in 0..pages {
        let va = address + page as u64 * PAGE_SIZE;
        match backend.protect_page(va, perms) {
            Ok(()) => mutated = true,
            Err(_) => {
                if mutated {
                    backend.poison();
                }
                return Err(Error::BackendInvariant);
            }
        }
    }
    let _ = align_up_page(address);
    Ok(())
}

fn find_gap<B: PageBackend>(backend: &mut B, len: u64) -> Result<u64, Error> {
    match backend.find_gap_top_down(len, DEFAULT_MMAP_CEILING) {
        Ok(start) => Ok(start),
        Err(BackendFailure::NoMemory) => Err(no_memory_error()),
        Err(_) => Err(Error::BackendInvariant),
    }
}

fn rollback_dynamic_mmap<B: PageBackend>(
    backend: &mut B,
    start: u64,
    mapped_new: usize,
    had_displaced: bool,
) {
    let mut complete = true;
    for page in (0..mapped_new).rev() {
        let va = start + page as u64 * PAGE_SIZE;
        match backend.unmap_page(va) {
            Ok(frame) => {
                if backend.free_page(frame).is_err() {
                    complete = false;
                }
            }
            Err(_) => complete = false,
        }
    }
    if had_displaced {
        // Displaced frames may have had heterogeneous original permissions; quarantine if a
        // MAP_FIXED replacement fails mid-transaction.
        complete = false;
    }
    if !complete {
        backend.poison();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::USER_MIN;

    struct TestDynamicBackend {
        pages: [(bool, u64, u64, VmPerms, [u8; 16]); 16],
        next_frame: u64,
        poisoned: bool,
    }

    impl TestDynamicBackend {
        fn new() -> Self {
            Self {
                pages: [(false, 0, 0, VmPerms::NONE, [0u8; 16]); 16],
                next_frame: 0x40_0000,
                poisoned: false,
            }
        }

        fn page_at(&self, va: u64) -> Option<(VmPerms, [u8; 16])> {
            self.pages
                .iter()
                .find(|p| p.0 && p.1 == va)
                .map(|p| (p.3, p.4))
        }
    }

    impl PageBackend for TestDynamicBackend {
        fn range_is_free(&mut self, start: u64, len: u64) -> Result<bool, BackendFailure> {
            let end = start + len;
            Ok(!self
                .pages
                .iter()
                .any(|p| p.0 && p.1 < end && p.1 + PAGE_SIZE > start))
        }

        fn find_gap_top_down(&mut self, len: u64, ceiling: u64) -> Result<u64, BackendFailure> {
            let start = (ceiling - len) & !(PAGE_SIZE - 1);
            if start >= USER_MIN {
                Ok(start)
            } else {
                Err(BackendFailure::NoMemory)
            }
        }

        fn page_is_mapped(&mut self, virtual_address: u64) -> Result<bool, BackendFailure> {
            Ok(self.pages.iter().any(|p| p.0 && p.1 == virtual_address))
        }

        fn allocate_page(&mut self) -> Result<u64, BackendFailure> {
            let f = self.next_frame;
            self.next_frame += PAGE_SIZE;
            Ok(f)
        }

        fn map_page(
            &mut self,
            virtual_address: u64,
            physical_address: u64,
            perms: VmPerms,
        ) -> Result<(), BackendFailure> {
            if let Some(slot) = self
                .pages
                .iter_mut()
                .find(|p| p.0 && p.2 == physical_address)
            {
                slot.1 = virtual_address;
                slot.3 = perms;
                return Ok(());
            }
            let slot = self
                .pages
                .iter_mut()
                .find(|p| !p.0)
                .ok_or(BackendFailure::NoMemory)?;
            *slot = (true, virtual_address, physical_address, perms, [0u8; 16]);
            Ok(())
        }

        fn protect_page(
            &mut self,
            virtual_address: u64,
            perms: VmPerms,
        ) -> Result<(), BackendFailure> {
            let slot = self
                .pages
                .iter_mut()
                .find(|p| p.0 && p.1 == virtual_address)
                .ok_or(BackendFailure::NotMapped)?;
            slot.3 = perms;
            Ok(())
        }

        fn unmap_page(&mut self, virtual_address: u64) -> Result<u64, BackendFailure> {
            let slot = self
                .pages
                .iter_mut()
                .find(|p| p.0 && p.1 == virtual_address)
                .ok_or(BackendFailure::NotMapped)?;
            let frame = slot.2;
            *slot = (false, 0, 0, VmPerms::NONE, [0u8; 16]);
            Ok(frame)
        }

        fn free_page(&mut self, _physical_address: u64) -> Result<(), BackendFailure> {
            Ok(())
        }

        fn poison(&mut self) {
            self.poisoned = true;
        }
    }

    impl DynamicPageBackend for TestDynamicBackend {
        fn allocate_initialized_page(
            &mut self,
            bytes: &[u8; PAGE_SIZE as usize],
        ) -> Result<u64, BackendFailure> {
            let physical_address = self.allocate_page()?;
            let slot = self
                .pages
                .iter_mut()
                .find(|p| !p.0)
                .ok_or(BackendFailure::NoMemory)?;
            let mut preview = [0u8; 16];
            preview.copy_from_slice(&bytes[..16]);
            *slot = (true, 0, physical_address, VmPerms::NONE, preview);
            Ok(physical_address)
        }
    }

    #[test]
    fn dynamic_mmap_supports_prot_none_guard_reservation_and_file_backed_map_fixed_segments() {
        let mut backend = TestDynamicBackend::new();
        let file_data = b"\x7fELF-shared-lib-code-segment";

        // 1. Reserve 2-page span with PROT_NONE | MAP_PRIVATE | MAP_ANONYMOUS.
        let base = mmap_step31_dynamic::<16, _>(
            0,
            2 * PAGE_SIZE,
            PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            u64::MAX,
            0,
            MmapFileBacking::Anonymous,
            &mut backend,
        )
        .unwrap();
        assert_eq!(backend.page_at(base).unwrap().0, VmPerms::NONE);

        // 2. Overlay first page with file-backed PROT_READ | PROT_EXEC | MAP_PRIVATE | MAP_FIXED | MAP_DENYWRITE.
        let code_va = mmap_step31_dynamic::<16, _>(
            base,
            PAGE_SIZE,
            PROT_READ | PROT_EXEC,
            MAP_PRIVATE | MAP_FIXED | MAP_DENYWRITE,
            3,
            0,
            MmapFileBacking::FileSlice {
                bytes: file_data,
                file_offset: 0,
            },
            &mut backend,
        )
        .unwrap();
        assert_eq!(code_va, base);
        let (perms, preview) = backend.page_at(base).unwrap();
        assert_eq!(perms, VmPerms::READ.union(VmPerms::EXECUTE));
        assert_eq!(&preview[..4], b"\x7fELF");

        // 2b. Overlay second page with RW data and then seal RELRO via mprotect_step31(PROT_READ).
        let data_va = mmap_step31_dynamic::<16, _>(
            base + PAGE_SIZE,
            PAGE_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_FIXED | MAP_DENYWRITE,
            3,
            0,
            MmapFileBacking::FileSlice {
                bytes: file_data,
                file_offset: 0,
            },
            &mut backend,
        )
        .unwrap();
        assert_eq!(data_va, base + PAGE_SIZE);
        assert_eq!(
            backend.page_at(base + PAGE_SIZE).unwrap().0,
            VmPerms::READ.union(VmPerms::WRITE)
        );
        mprotect_step31::<16, _>(base + PAGE_SIZE, PAGE_SIZE, PROT_READ, &mut backend).unwrap();
        assert_eq!(backend.page_at(base + PAGE_SIZE).unwrap().0, VmPerms::READ);

        // 3. Reject W+X before mutating existing mappings.
        assert_eq!(
            mmap_step31_dynamic::<16, _>(
                base,
                PAGE_SIZE,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                u64::MAX,
                0,
                MmapFileBacking::Anonymous,
                &mut backend,
            ),
            Err(Error::Linux(Errno::EINVAL))
        );
        assert!(!backend.poisoned);
    }

    #[test]
    fn dynamic_mmap_admits_advisory_stack_noreserve_and_populate_flags() {
        let mut backend = TestDynamicBackend::new();
        let stack_guard = mmap_step31_dynamic::<16, _>(
            0,
            2 * PAGE_SIZE,
            PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
            u64::MAX,
            0,
            MmapFileBacking::Anonymous,
            &mut backend,
        )
        .unwrap();
        assert_eq!(backend.page_at(stack_guard).unwrap().0, VmPerms::NONE);
        mprotect_step31::<16, _>(
            stack_guard + PAGE_SIZE,
            PAGE_SIZE,
            PROT_READ | PROT_WRITE,
            &mut backend,
        )
        .unwrap();
        assert_eq!(
            backend.page_at(stack_guard + PAGE_SIZE).unwrap().0,
            VmPerms::READ.union(VmPerms::WRITE)
        );

        let hint_spec = validate_step31_mmap_spec(
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_POPULATE | MAP_NONBLOCK,
            u64::MAX,
            0,
        )
        .unwrap();
        assert!(hint_spec.anonymous);
        assert!(!hint_spec.shared);
        assert!(!hint_spec.fixed);

        let shared_spec =
            validate_step31_mmap_spec(PROT_READ | PROT_WRITE, MAP_SHARED, 3, 0).unwrap();
        assert!(!shared_spec.anonymous);
        assert!(shared_spec.shared);
    }
}
