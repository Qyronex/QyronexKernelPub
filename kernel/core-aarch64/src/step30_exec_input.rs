// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_capability::ObjectId;
use kernal_linux_abi::Errno;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_linux_abi::{Step30RuntimeCall, linux_signed_int};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_linux_exec::ExecLookupPlan;
use kernal_linux_exec::{Error as LinuxExecError, ExecArgumentStaging, ExecStringVector};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_scheduler_smp::GlobalThreadId;
use kernal_user_elf_runtime_aarch64::LinuxProcessStart;
#[cfg(not(feature = "step31-debian-qemu"))]
use kernal_user_elf_runtime_aarch64::{MAX_ARGC, MAX_ARGV0_BYTES, MAX_ENVC, MAX_STRING_BYTES};
use kernal_usercopy::Error as ExecUsercopyError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ExecInputError {
    Linux(Errno),
    Invariant,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReversibleExecError {
    Input(ExecInputError),
    Source(super::step30_exec_source::ExecSourceError),
    Stage(super::live_vm::ExecStageError),
    Invariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecScratchEntry {
    start: usize,
    len: usize,
}

/// Complete bounded argv/envp copy captured while the old userspace image is still active.
///
/// The sole byte buffer is sized from the canonical Linux initial-stack owner. Entry metadata stores
/// only offsets into that buffer, so the value is not self-referential and can safely cross the later
/// fresh-AddressSpace staging boundary. Pointer/range validation remains owned by `ExecStringVector`;
/// this type only owns the copied bytes needed after the old TTBR0 is no longer usable.
#[cfg(feature = "step31-debian-qemu")]
use kernal_user_elf_runtime_aarch64::{
    MAX_EXTENDED_ARGC, MAX_EXTENDED_ARGV0_BYTES, MAX_EXTENDED_ENVC, MAX_EXTENDED_STRING_BYTES,
};

#[cfg(not(feature = "step31-debian-qemu"))]
const EXEC_ARGV0_BYTES: usize = MAX_ARGV0_BYTES;
#[cfg(feature = "step31-debian-qemu")]
const EXEC_ARGV0_BYTES: usize = MAX_EXTENDED_ARGV0_BYTES;

#[cfg(not(feature = "step31-debian-qemu"))]
const EXEC_ARGC: usize = MAX_ARGC;
#[cfg(feature = "step31-debian-qemu")]
const EXEC_ARGC: usize = MAX_EXTENDED_ARGC;

#[cfg(not(feature = "step31-debian-qemu"))]
const EXEC_ENVC: usize = MAX_ENVC;
#[cfg(feature = "step31-debian-qemu")]
const EXEC_ENVC: usize = MAX_EXTENDED_ENVC;

#[cfg(not(feature = "step31-debian-qemu"))]
const EXEC_STRING_BYTES: usize = MAX_STRING_BYTES;
#[cfg(feature = "step31-debian-qemu")]
const EXEC_STRING_BYTES: usize = MAX_EXTENDED_STRING_BYTES;

const EXEC_EXTENDED_VECTORS: bool = cfg!(feature = "step31-debian-qemu");

pub(super) struct StagedExecVectors {
    bytes: [u8; EXEC_STRING_BYTES],
    used: usize,
    argv: [Option<ExecScratchEntry>; EXEC_ARGC],
    argc: usize,
    envp: [Option<ExecScratchEntry>; EXEC_ENVC],
    envc: usize,
}

impl StagedExecVectors {
    const fn new() -> Self {
        Self {
            bytes: [0; EXEC_STRING_BYTES],
            used: 0,
            argv: [None; EXEC_ARGC],
            argc: 0,
            envp: [None; EXEC_ENVC],
            envc: 0,
        }
    }

    /// Builds the canonical borrowed Linux process-start view only for one synchronous operation.
    ///
    /// Slice arrays are temporary stack metadata over this owned scratch buffer. They never escape the
    /// callback, so no self-referential storage or heap allocation is introduced.
    pub(super) fn with_linux_start<R>(
        &self,
        random: [u8; 16],
        operation: impl FnOnce(LinuxProcessStart<'_>) -> R,
    ) -> Result<R, ExecInputError> {
        if self.argc == 0 {
            // The accepted bounded Linux stack owner requires a concrete argv[0]. Do not synthesize
            // one from the pathname or silently widen that contract in Core.
            return Err(ExecInputError::Linux(Errno::EINVAL));
        }

        let mut argv_refs: [&[u8]; EXEC_ARGC] = [&[]; EXEC_ARGC];
        for (index, slot) in self.argv.iter().copied().enumerate().take(self.argc) {
            let entry = slot.ok_or(ExecInputError::Invariant)?;
            argv_refs[index] = self.entry_bytes(entry)?;
        }
        let mut env_refs: [&[u8]; EXEC_ENVC] = [&[]; EXEC_ENVC];
        for (index, slot) in self.envp.iter().copied().enumerate().take(self.envc) {
            let entry = slot.ok_or(ExecInputError::Invariant)?;
            env_refs[index] = self.entry_bytes(entry)?;
        }

        let start = LinuxProcessStart::with_vectors(
            argv_refs[0],
            &argv_refs[1..self.argc],
            &env_refs[..self.envc],
            random,
        )
        .with_extended_vectors(EXEC_EXTENDED_VECTORS);
        Ok(operation(start))
    }

    pub(super) fn with_linux_start_with_prefix<R>(
        &self,
        random: [u8; 16],
        prefix: &[&[u8]],
        operation: impl FnOnce(LinuxProcessStart<'_>) -> R,
    ) -> Result<R, ExecInputError> {
        if prefix.is_empty() {
            return self.with_linux_start(random, operation);
        }
        if self.argc == 0 {
            return Err(ExecInputError::Linux(Errno::EINVAL));
        }

        let mut argv_refs: [&[u8]; EXEC_ARGC] = [&[]; EXEC_ARGC];
        let mut out_argc = 0usize;
        for arg in prefix {
            if out_argc >= EXEC_ARGC {
                return Err(ExecInputError::Linux(Errno::E2BIG));
            }
            argv_refs[out_argc] = arg;
            out_argc += 1;
        }
        for slot in self.argv.iter().copied().take(self.argc).skip(1) {
            if out_argc >= EXEC_ARGC {
                return Err(ExecInputError::Linux(Errno::E2BIG));
            }
            let entry = slot.ok_or(ExecInputError::Invariant)?;
            argv_refs[out_argc] = self.entry_bytes(entry)?;
            out_argc += 1;
        }

        let mut env_refs: [&[u8]; EXEC_ENVC] = [&[]; EXEC_ENVC];
        for (index, slot) in self.envp.iter().copied().enumerate().take(self.envc) {
            let entry = slot.ok_or(ExecInputError::Invariant)?;
            env_refs[index] = self.entry_bytes(entry)?;
        }

        let start = LinuxProcessStart::with_vectors(
            argv_refs[0],
            &argv_refs[1..out_argc],
            &env_refs[..self.envc],
            random,
        )
        .with_extended_vectors(EXEC_EXTENDED_VECTORS);
        Ok(operation(start))
    }

    pub(super) fn encode_cmdline(&self, out: &mut [u8; 128]) -> usize {
        let mut pos = 0usize;
        for slot in self.argv.iter().copied().take(self.argc) {
            let Some(entry) = slot else {
                break;
            };
            let Ok(bytes) = self.entry_bytes(entry) else {
                break;
            };
            let take = bytes.len().min(out.len().saturating_sub(pos));
            out[pos..pos + take].copy_from_slice(&bytes[..take]);
            pos += take;
            if pos < out.len() {
                out[pos] = 0;
                pos += 1;
            }
        }
        pos
    }

    fn entry_bytes(&self, entry: ExecScratchEntry) -> Result<&[u8], ExecInputError> {
        let end = entry
            .start
            .checked_add(entry.len)
            .ok_or(ExecInputError::Invariant)?;
        self.bytes
            .get(entry.start..end)
            .ok_or(ExecInputError::Invariant)
    }
}

/// Successfully staged replacement-image receipt returned at the final ordinary recoverable boundary.
///
/// `process` is observation only: it was obtained from the exact current scheduler generation through
/// the canonical LinuxIdentity relation and is retained solely to select that Process's Step-29 FD/VFS
/// view later. `staged` remains unpublished replacement-image authority until the final runtime owner
/// activates and swaps it. Returning this receipt means every ordinary Linux-visible preparation step
/// succeeded; later owner failures are invariant/fail-stop rather than recoverable exec errors.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) struct PreparedExecImage {
    process: ObjectId,
    staged: alloc::boxed::Box<super::live_vm::StagedExecImage>,
    exe_path: [u8; 128],
    exe_len: u8,
    cmdline: [u8; 128],
    cmdline_len: u8,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl PreparedExecImage {
    pub(super) const fn process(&self) -> ObjectId {
        self.process
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        alloc::boxed::Box<super::live_vm::StagedExecImage>,
        [u8; 128],
        usize,
        [u8; 128],
        usize,
    ) {
        (
            self.staged,
            self.exe_path,
            usize::from(self.exe_len),
            self.cmdline,
            usize::from(self.cmdline_len),
        )
    }
}

/// Copies argv/envp through the canonical AArch64 usercopy owner while the old image is active.
///
/// Every pointer-table slot is first derived by `ExecStringVector::next_pointer_slot`. Every non-null
/// C string is copied into one aggregate scratch budget and then committed back to the same metadata
/// owner with `push_validated_c_string`; the final null pointer is proved through `finish(0)`. No user
/// address is retained as byte authority after this function returns.
pub(super) fn stage_exec_vectors(
    argv_base: u64,
    envp_base: u64,
) -> Result<StagedExecVectors, ExecInputError> {
    let mut staged = StagedExecVectors::new();
    let argv = stage_one_vector::<EXEC_ARGC>(
        argv_base,
        &mut staged.bytes,
        &mut staged.used,
        &mut staged.argv,
        true,
    )?;
    let envp = stage_one_vector::<EXEC_ENVC>(
        envp_base,
        &mut staged.bytes,
        &mut staged.used,
        &mut staged.envp,
        false,
    )?;
    let metadata =
        ExecArgumentStaging::new(argv, envp, EXEC_STRING_BYTES).map_err(map_linux_exec_error)?;
    if metadata.total_bytes() != staged.used {
        return Err(ExecInputError::Invariant);
    }
    staged.argc = metadata.argv().len();
    staged.envc = metadata.envp().len();
    Ok(staged)
}

/// Performs every ordinary reversible live-exec preparation step using only existing canonical owners.
///
/// The caller supplies the second AT_RANDOM grant but retains ownership of the entropy transaction;
/// this helper never commits or consumes that grant itself. Path and vector usercopy, exact Process
/// selection, Process-local FD/VFS lookup and complete ELF/Linux-stack staging all finish while the old
/// image remains current. Error provenance stays typed so the final runtime owner can distinguish
/// input, VFS/source, and ELF/resource staging failures without fabricating a Linux errno.
///
/// # Safety
/// Caller must own the exact current lower-EL synchronous no-switch window for `current`. The supplied
/// `random` bytes must be the currently claimed exec AT_RANDOM grant. The successful typed staging result is the AT_RANDOM
/// transaction commit signal and the final ordinary recoverable exec failure boundary. After `Ok(PreparedExecImage)`,
/// every later owner failure must fail-stop rather than recover the old image.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) unsafe fn stage_exec_image_with_core_frames(
    call: Step30RuntimeCall,
    current: GlobalThreadId,
    random: [u8; 16],
) -> Result<PreparedExecImage, ReversibleExecError> {
    let (path, argv_base, envp_base, lookup) = match call {
        Step30RuntimeCall::Execve {
            filename,
            argv,
            envp,
        } => {
            let path = super::step29_fd::copy_user_path_allow_empty(filename, false)
                .map_err(map_step29_path_error)
                .map_err(ReversibleExecError::Input)?;
            let lookup = ExecLookupPlan::execve(path.as_bytes().is_empty())
                .map_err(map_exec_lookup_error)
                .map_err(ReversibleExecError::Input)?;
            (path, argv, envp, lookup)
        }
        Step30RuntimeCall::Execveat {
            dirfd,
            pathname,
            argv,
            envp,
            flags,
        } => {
            let path = super::step29_fd::copy_user_path_allow_empty(pathname, true)
                .map_err(map_step29_path_error)
                .map_err(ReversibleExecError::Input)?;
            let lookup = ExecLookupPlan::execveat(
                linux_signed_int(dirfd),
                path.as_bytes().is_empty(),
                flags,
            )
            .map_err(map_exec_lookup_error)
            .map_err(ReversibleExecError::Input)?;
            (path, argv, envp, lookup)
        }
        _ => return Err(ReversibleExecError::Invariant),
    };

    let vectors = capture_exec_vectors_boxed(argv_base, envp_base)?;

    // Resolve Process authority from the exact running scheduler generation. ObjectId is copied out
    // only after the retained Process/AddressSpace pair and current TTBR0 binding are revalidated.
    let process = super::runtime::with_linux_runtime(|state| {
        let (process, address_space, _tid) = state.process_parts_for_scheduler_thread(current)?;
        address_space
            .current_owner(process)
            .map_err(super::runtime::Error::AddressSpace)?;
        Ok::<ObjectId, super::runtime::Error>(process.id())
    })
    .map_err(|_| ReversibleExecError::Invariant)?
    .map_err(|_| ReversibleExecError::Invariant)?;

    let (source, extra_prefix) = resolve_exec_shebang(process, lookup, path.as_bytes())?;
    let staged = stage_exec_from_source(current, process, source, &vectors, &extra_prefix, random)?;

    let mut exe_path = [0u8; 128];
    let raw_exe = if path.as_bytes().is_empty() {
        vectors
            .argv
            .first()
            .and_then(|s| s.and_then(|e| vectors.entry_bytes(e).ok()))
            .unwrap_or(&b""[..])
    } else {
        path.as_bytes()
    };
    let exe_len = raw_exe.len().min(exe_path.len());
    exe_path[..exe_len].copy_from_slice(&raw_exe[..exe_len]);
    let mut cmdline = [0u8; 128];
    let cmdline_len = vectors.encode_cmdline(&mut cmdline);

    Ok(PreparedExecImage {
        process,
        staged,
        exe_path,
        exe_len: exe_len as u8,
        cmdline,
        cmdline_len: cmdline_len as u8,
    })
}

#[inline(never)]
fn capture_exec_vectors_boxed(
    argv_base: u64,
    envp_base: u64,
) -> Result<alloc::boxed::Box<StagedExecVectors>, ReversibleExecError> {
    stage_exec_vectors(argv_base, envp_base)
        .map(alloc::boxed::Box::new)
        .map_err(ReversibleExecError::Input)
}

#[inline(never)]
fn resolve_exec_shebang(
    process: ObjectId,
    lookup: ExecLookupPlan,
    initial_path: &[u8],
) -> Result<
    (
        super::step30_exec_source::ExecImageSource,
        alloc::vec::Vec<alloc::vec::Vec<u8>>,
    ),
    ReversibleExecError,
> {
    let mut source =
        super::step30_exec_source::select_exec_image_source(process, lookup, initial_path)
            .map_err(ReversibleExecError::Source)?;
    let mut shebang_depth: u8 = 0;
    let mut extra_prefix: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
    loop {
        let parsed = source
            .with_image_bytes(|bytes| kernal_linux_dpkg::parse_shebang(bytes, shebang_depth))
            .map_err(ReversibleExecError::Source)?;
        match parsed {
            Ok(None) => return Ok((source, extra_prefix)),
            Err(errno) => {
                return Err(ReversibleExecError::Source(
                    super::step30_exec_source::ExecSourceError::Linux(errno),
                ));
            }
            Ok(Some(spec)) => {
                let mut next_prefix = alloc::vec::Vec::with_capacity(extra_prefix.len() + 2);
                next_prefix.push(spec.interpreter().to_vec());
                if let Some(opt) = spec.optional_arg()
                    && !opt.is_empty()
                {
                    next_prefix.push(opt.to_vec());
                }
                if shebang_depth == 0 {
                    if initial_path.is_empty() {
                        next_prefix.push(b"/dev/fd".to_vec());
                    } else {
                        next_prefix.push(initial_path.to_vec());
                    }
                } else {
                    next_prefix.extend(extra_prefix);
                }
                extra_prefix = next_prefix;
                let interp_lookup = ExecLookupPlan::execve(spec.interpreter().is_empty())
                    .map_err(map_exec_lookup_error)
                    .map_err(ReversibleExecError::Input)?;
                source = super::step30_exec_source::select_exec_image_source(
                    process,
                    interp_lookup,
                    spec.interpreter(),
                )
                .map_err(ReversibleExecError::Source)?;
                shebang_depth = shebang_depth.saturating_add(1);
            }
        }
    }
}

#[inline(never)]
fn stage_exec_from_source(
    current: kernal_scheduler_smp::GlobalThreadId,
    process: ObjectId,
    source: super::step30_exec_source::ExecImageSource,
    vectors: &StagedExecVectors,
    extra_prefix: &[alloc::vec::Vec<u8>],
    random: [u8; 16],
) -> Result<alloc::boxed::Box<super::live_vm::StagedExecImage>, ReversibleExecError> {
    let prefix_slices: alloc::vec::Vec<&[u8]> =
        extra_prefix.iter().map(alloc::vec::Vec::as_slice).collect();
    source
        .with_image_bytes(|image| -> Result<_, ReversibleExecError> {
            let interpreter_source =
                super::step30_exec_source::select_optional_interpreter_source(process, image)
                    .map_err(ReversibleExecError::Source)?;
            super::step30_exec_source::with_optional_source_bytes(
                interpreter_source,
                |interpreter| {
                    vectors.with_linux_start_with_prefix(random, &prefix_slices, |start| {
                        // SAFETY: delegated caller contract owns the exact same lower-EL no-switch window;
                        // image/start borrows remain valid for this complete synchronous staging call.
                        unsafe {
                            super::live_vm::stage_exec_image(current, image, interpreter, start)
                        }
                    })
                },
            )
            .map_err(ReversibleExecError::Source)?
            .map_err(ReversibleExecError::Input)?
            .map_err(ReversibleExecError::Stage)
        })
        .map_err(ReversibleExecError::Source)?
}

fn stage_one_vector<const N: usize>(
    vector_base: u64,
    scratch: &mut [u8; EXEC_STRING_BYTES],
    used: &mut usize,
    entries: &mut [Option<ExecScratchEntry>; N],
    enforce_argv0_limit: bool,
) -> Result<ExecStringVector<N>, ExecInputError> {
    let mut vector = ExecStringVector::<N>::new();
    loop {
        let slot = vector
            .next_pointer_slot(vector_base)
            .map_err(map_linux_exec_error)?;
        let pointer = copy_user_pointer(slot.start())?;
        if pointer == 0 {
            return vector.finish(0).map_err(map_linux_exec_error);
        }
        if vector.len() == N {
            return Err(ExecInputError::Linux(Errno::E2BIG));
        }

        let index = vector.len();
        let entry = copy_user_c_string(pointer, scratch, used, enforce_argv0_limit && index == 0)?;
        let len_with_nul = entry
            .len
            .checked_add(1)
            .ok_or(ExecInputError::Linux(Errno::E2BIG))?;
        vector
            .push_validated_c_string(pointer, len_with_nul)
            .map_err(map_linux_exec_error)?;
        let target = entries.get_mut(index).ok_or(ExecInputError::Invariant)?;
        if target.is_some() {
            return Err(ExecInputError::Invariant);
        }
        *target = Some(entry);
    }
}

fn copy_user_pointer(address: u64) -> Result<u64, ExecInputError> {
    let mut bytes = [0u8; core::mem::size_of::<u64>()];
    kernal_usercopy_aarch64::copy_from_user(&mut bytes, address).map_err(map_usercopy_error)?;
    Ok(u64::from_le_bytes(bytes))
}

fn copy_user_c_string(
    address: u64,
    scratch: &mut [u8; EXEC_STRING_BYTES],
    used: &mut usize,
    enforce_argv0_limit: bool,
) -> Result<ExecScratchEntry, ExecInputError> {
    let start = *used;
    let remaining = EXEC_STRING_BYTES
        .checked_sub(start)
        .ok_or(ExecInputError::Invariant)?;
    if remaining == 0 {
        return Err(ExecInputError::Linux(Errno::E2BIG));
    }

    let mut byte = [0u8; 1];
    for offset in 0..remaining {
        let user = address
            .checked_add(u64::try_from(offset).map_err(|_| ExecInputError::Linux(Errno::EFAULT))?)
            .ok_or(ExecInputError::Linux(Errno::EFAULT))?;
        kernal_usercopy_aarch64::copy_from_user(&mut byte, user).map_err(map_usercopy_error)?;
        if byte[0] == 0 {
            if enforce_argv0_limit && offset > EXEC_ARGV0_BYTES {
                return Err(ExecInputError::Linux(Errno::E2BIG));
            }
            let len_with_nul = offset
                .checked_add(1)
                .ok_or(ExecInputError::Linux(Errno::E2BIG))?;
            let next = start
                .checked_add(len_with_nul)
                .ok_or(ExecInputError::Linux(Errno::E2BIG))?;
            let nul = scratch
                .get_mut(start + offset)
                .ok_or(ExecInputError::Invariant)?;
            *nul = 0;
            *used = next;
            return Ok(ExecScratchEntry { start, len: offset });
        }
        let destination = scratch
            .get_mut(start + offset)
            .ok_or(ExecInputError::Invariant)?;
        *destination = byte[0];
    }

    Err(ExecInputError::Linux(Errno::E2BIG))
}

fn map_linux_exec_error(error: LinuxExecError) -> ExecInputError {
    match error {
        LinuxExecError::TooManyVectorEntries | LinuxExecError::ArgumentBytesExceeded => {
            ExecInputError::Linux(Errno::E2BIG)
        }
        LinuxExecError::Usercopy(error) => map_usercopy_error(error),
        LinuxExecError::InvalidStringLength => ExecInputError::Invariant,
        LinuxExecError::UnsupportedExecveatFlags
        | LinuxExecError::EmptyPath
        | LinuxExecError::NotLinuxProcess
        | LinuxExecError::InactiveProcess
        | LinuxExecError::ProcessChanged
        | LinuxExecError::Fd(_) => ExecInputError::Invariant,
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn map_exec_lookup_error(error: LinuxExecError) -> ExecInputError {
    match error {
        LinuxExecError::UnsupportedExecveatFlags => ExecInputError::Linux(Errno::EINVAL),
        LinuxExecError::EmptyPath => ExecInputError::Linux(Errno::ENOENT),
        LinuxExecError::NotLinuxProcess
        | LinuxExecError::InactiveProcess
        | LinuxExecError::ProcessChanged
        | LinuxExecError::TooManyVectorEntries
        | LinuxExecError::ArgumentBytesExceeded
        | LinuxExecError::InvalidStringLength
        | LinuxExecError::Usercopy(_)
        | LinuxExecError::Fd(_) => ExecInputError::Invariant,
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn map_step29_path_error(error: super::step29_fd::Error) -> ExecInputError {
    match error {
        super::step29_fd::Error::Linux(errno) => ExecInputError::Linux(errno),
        super::step29_fd::Error::Invariant => ExecInputError::Invariant,
    }
}

fn map_usercopy_error(error: ExecUsercopyError) -> ExecInputError {
    match error {
        ExecUsercopyError::NullGuard
        | ExecUsercopyError::OutsideUserRange
        | ExecUsercopyError::Overflow
        | ExecUsercopyError::TooLarge
        | ExecUsercopyError::Fault => ExecInputError::Linux(Errno::EFAULT),
        ExecUsercopyError::PanUnavailable
        | ExecUsercopyError::PanStateLeak
        | ExecUsercopyError::FaultHandlerUnavailable => ExecInputError::Invariant,
    }
}
