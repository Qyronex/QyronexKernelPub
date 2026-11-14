// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

const STEP15_QEMU: &str = include_str!("../../core-aarch64/src/step15_qemu.rs");
const STEP31_RUNTIME: &str = include_str!("../../core-aarch64/src/step31_runtime.rs");
const EXEC_SOURCE: &str = include_str!("../../core-aarch64/src/step30_exec_source.rs");
const EXEC_INPUT: &str = include_str!("../../core-aarch64/src/step30_exec_input.rs");
const LIVE_VM: &str = include_str!("../../core-aarch64/src/step15_live_vm.rs");
const LOADER_FRAMES: &str = include_str!("../../core-aarch64/src/step15_loader_frames.rs");

#[test]
fn step31_dynamic_interpreter_resolution_reuses_canonical_vfs_exec_source() {
    assert!(
        EXEC_SOURCE.contains("select_optional_interpreter_source")
            && EXEC_SOURCE.contains("aarch64_elf_interpreter_path")
            && EXEC_SOURCE.contains("select_exec_image_source(process, lookup, interp_path)"),
        "PT_INTERP resolution must re-enter the process-local Step-29 VFS exec-source owner"
    );
    assert!(
        EXEC_INPUT.contains("select_optional_interpreter_source")
            && EXEC_INPUT.contains("with_optional_source_bytes")
            && LIVE_VM.contains("interpreter: Option<&[u8]>")
            && LOADER_FRAMES.contains("load_aarch64_dynamic_linux_elf"),
        "staged live exec must pass the optional PT_INTERP bytes into the canonical dynamic ELF loader"
    );
}

#[test]
fn step31_glibc_syscalls_route_getrandom_through_csprng_and_rseq_to_enosys() {
    assert!(
        STEP15_QEMU.contains("#[path = \"step31_runtime.rs\"]")
            && STEP15_QEMU.contains("step31_runtime::handle(request)"),
        "live AArch64 SVC dispatch must wire the Step-31 glibc runtime handler"
    );
    assert!(
        STEP31_RUNTIME.contains("classify_step31_glibc")
            && STEP31_RUNTIME.contains("decode_getrandom_flags")
            && STEP31_RUNTIME.contains("fill_getrandom")
            && STEP31_RUNTIME.contains("copy_to_user")
            && STEP31_RUNTIME.contains(
                "Step31GlibcCall::Rseq { .. } => Ok(Some(SyscallReturn::error(Errno::ENOSYS)))"
            ),
        "Step-31 runtime must serve getrandom via the CSPRNG + audited usercopy and reject rseq with -ENOSYS"
    );
}
