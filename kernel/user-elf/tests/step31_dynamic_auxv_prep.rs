// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_elf::{Image, Machine};
use kernal_load_plan::PAGE_SIZE;
use kernal_user_elf::linux_stack::{
    Error as LinuxStackError, LinuxInitialStackSpec, initialize_linux_stack_page,
    plan_linux_initial_stack,
};
use kernal_user_elf::{
    DEFAULT_DYN_LOAD_BIAS, DEFAULT_INTERP_LOAD_BIAS, DynamicLoadPolicy, DynamicUserLoadPlan,
    Error as PlanError, LoadPolicy, UserLoadPlan,
};

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;
const AARCH64_INTERP_NUL: &[u8] = b"/lib/ld-linux-aarch64.so.1\0";

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;

fn dynamic_aarch64_elf() -> [u8; 0x200] {
    let mut bytes = [0u8; 0x200];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT
    bytes[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
    bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x100u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&(ELF64_EHDR_SIZE as u64).to_le_bytes());
    bytes[52..54].copy_from_slice(&(ELF64_EHDR_SIZE as u16).to_le_bytes());
    bytes[54..56].copy_from_slice(&(ELF64_PHDR_SIZE as u16).to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

    let image_len = bytes.len() as u64;
    let ph = ELF64_EHDR_SIZE;
    bytes[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
    bytes[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // R-X
    bytes[ph + 8..ph + 16].copy_from_slice(&0u64.to_le_bytes());
    bytes[ph + 16..ph + 24].copy_from_slice(&0u64.to_le_bytes());
    bytes[ph + 24..ph + 32].copy_from_slice(&0u64.to_le_bytes());
    bytes[ph + 32..ph + 40].copy_from_slice(&image_len.to_le_bytes());
    bytes[ph + 40..ph + 48].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes
}

fn dynamic_aarch64_elf_with_interp() -> [u8; 0x300] {
    let mut bytes = [0u8; 0x300];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
    bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x180u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&(ELF64_EHDR_SIZE as u64).to_le_bytes());
    bytes[52..54].copy_from_slice(&(ELF64_EHDR_SIZE as u16).to_le_bytes());
    bytes[54..56].copy_from_slice(&(ELF64_PHDR_SIZE as u16).to_le_bytes());
    bytes[56..58].copy_from_slice(&2u16.to_le_bytes());

    let interp_offset = 0x120usize;
    bytes[interp_offset..interp_offset + AARCH64_INTERP_NUL.len()]
        .copy_from_slice(AARCH64_INTERP_NUL);

    let ph0 = ELF64_EHDR_SIZE;
    bytes[ph0..ph0 + 4].copy_from_slice(&PT_INTERP.to_le_bytes());
    bytes[ph0 + 4..ph0 + 8].copy_from_slice(&4u32.to_le_bytes());
    bytes[ph0 + 8..ph0 + 16].copy_from_slice(&(interp_offset as u64).to_le_bytes());
    bytes[ph0 + 16..ph0 + 24].copy_from_slice(&(interp_offset as u64).to_le_bytes());
    bytes[ph0 + 24..ph0 + 32].copy_from_slice(&0u64.to_le_bytes());
    bytes[ph0 + 32..ph0 + 40].copy_from_slice(&(AARCH64_INTERP_NUL.len() as u64).to_le_bytes());
    bytes[ph0 + 40..ph0 + 48].copy_from_slice(&(AARCH64_INTERP_NUL.len() as u64).to_le_bytes());
    bytes[ph0 + 48..ph0 + 56].copy_from_slice(&1u64.to_le_bytes());

    let image_len = bytes.len() as u64;
    let ph1 = ELF64_EHDR_SIZE + ELF64_PHDR_SIZE;
    bytes[ph1..ph1 + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
    bytes[ph1 + 4..ph1 + 8].copy_from_slice(&5u32.to_le_bytes());
    bytes[ph1 + 8..ph1 + 16].copy_from_slice(&0u64.to_le_bytes());
    bytes[ph1 + 16..ph1 + 24].copy_from_slice(&0u64.to_le_bytes());
    bytes[ph1 + 24..ph1 + 32].copy_from_slice(&0u64.to_le_bytes());
    bytes[ph1 + 32..ph1 + 40].copy_from_slice(&image_len.to_le_bytes());
    bytes[ph1 + 40..ph1 + 48].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[ph1 + 48..ph1 + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes
}

fn word(page: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(page[offset..offset + 8].try_into().unwrap())
}

fn auxv_value(auxv: &[(u64, u64)], kind: u64) -> Option<u64> {
    auxv.iter()
        .find_map(|(candidate, value)| (*candidate == kind).then_some(*value))
}

fn encoded_auxv<const N: usize>(
    plan: &UserLoadPlan<N>,
    spec: LinuxInitialStackSpec<'_>,
) -> Vec<(u64, u64)> {
    let stack = plan.stack();
    let last_page = stack.stack_pages() - 1;
    let page_start = stack.stack_start() + (last_page as u64 * PAGE_SIZE);
    let mut page = [0u8; PAGE_SIZE as usize];
    let layout = initialize_linux_stack_page(stack, spec, last_page, &mut page).unwrap();
    let mut cursor = usize::try_from(layout.initial_sp() - page_start).unwrap();

    assert_eq!(word(&page, cursor), 1);
    cursor += 4 * 8; // argc, argv[0], argv terminator, envp terminator

    let mut auxv = Vec::new();
    loop {
        let kind = word(&page, cursor);
        let value = word(&page, cursor + 8);
        cursor += 16;
        if kind == AT_NULL {
            assert_eq!(value, 0);
            break;
        }
        auxv.push((kind, value));
    }
    auxv
}

#[test]
fn et_dyn_metadata_flows_into_current_linux_auxv_without_fabricating_at_base() {
    let bytes = dynamic_aarch64_elf();
    let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
    let headers = image.program_header_table().unwrap();
    let plan = UserLoadPlan::<4>::from_image(&image, LoadPolicy::default()).unwrap();

    assert_eq!(plan.load_bias(), DEFAULT_DYN_LOAD_BIAS);
    assert_eq!(plan.entry(), DEFAULT_DYN_LOAD_BIAS + 0x100);
    assert_eq!(headers.virtual_addr(), ELF64_EHDR_SIZE as u64);

    let program_headers = plan.load_bias() + headers.virtual_addr();
    let random = [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
        0x0f,
    ];
    let spec = LinuxInitialStackSpec {
        argv0: b"/bin/step31-dynamic",
        argv_tail: &[],
        envp: &[],
        program_headers,
        program_header_entry_size: headers.entry_size() as u64,
        program_header_count: headers.entry_count() as u64,
        interpreter_base: 0,
        entry: plan.entry(),
        uid: 0,
        euid: 0,
        gid: 0,
        egid: 0,
        secure: false,
        random,
    };

    let stack = plan.stack();
    let last_page = stack.stack_pages() - 1;
    let page_start = stack.stack_start() + (last_page as u64 * PAGE_SIZE);
    let mut page = [0u8; PAGE_SIZE as usize];
    let layout = initialize_linux_stack_page(stack, spec, last_page, &mut page).unwrap();
    let auxv = encoded_auxv(&plan, spec);
    assert_eq!(auxv.len(), 13);

    assert_eq!(auxv_value(&auxv, AT_PHDR), Some(program_headers));
    assert_eq!(
        auxv_value(&auxv, AT_PHENT),
        Some(headers.entry_size() as u64)
    );
    assert_eq!(
        auxv_value(&auxv, AT_PHNUM),
        Some(headers.entry_count() as u64)
    );
    assert_eq!(auxv_value(&auxv, AT_PAGESZ), Some(PAGE_SIZE));
    assert_eq!(auxv_value(&auxv, AT_BASE), Some(0));
    assert_eq!(auxv_value(&auxv, AT_ENTRY), Some(plan.entry()));
    assert_eq!(auxv_value(&auxv, AT_UID), Some(0));
    assert_eq!(auxv_value(&auxv, AT_EUID), Some(0));
    assert_eq!(auxv_value(&auxv, AT_GID), Some(0));
    assert_eq!(auxv_value(&auxv, AT_EGID), Some(0));
    assert_eq!(auxv_value(&auxv, AT_SECURE), Some(0));
    assert_eq!(auxv_value(&auxv, AT_RANDOM), Some(layout.random()));
    assert_eq!(auxv_value(&auxv, AT_EXECFN), Some(layout.argv0()));

    let random_offset = usize::try_from(layout.random() - page_start).unwrap();
    assert_eq!(&page[random_offset..random_offset + random.len()], &random);
}

#[test]
fn custom_et_dyn_load_bias_is_preserved_in_auxv_metadata() {
    let bytes = dynamic_aarch64_elf();
    let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
    let headers = image.program_header_table().unwrap();
    let custom_bias = DEFAULT_DYN_LOAD_BIAS + 0x20_0000;
    let policy = LoadPolicy {
        dynamic_load_bias: custom_bias,
        ..LoadPolicy::default()
    };
    let plan = UserLoadPlan::<4>::from_image(&image, policy).unwrap();

    assert_eq!(plan.load_bias(), custom_bias);
    assert_eq!(plan.entry(), custom_bias + 0x100);

    let program_headers = custom_bias + headers.virtual_addr();
    let spec = LinuxInitialStackSpec {
        argv0: b"/bin/step31-custom-bias",
        argv_tail: &[],
        envp: &[],
        program_headers,
        program_header_entry_size: headers.entry_size() as u64,
        program_header_count: headers.entry_count() as u64,
        interpreter_base: DEFAULT_INTERP_LOAD_BIAS,
        entry: plan.entry(),
        uid: 0,
        euid: 0,
        gid: 0,
        egid: 0,
        secure: false,
        random: [0x5a; 16],
    };
    let auxv = encoded_auxv(&plan, spec);

    assert_eq!(auxv_value(&auxv, AT_PHDR), Some(program_headers));
    assert_eq!(auxv_value(&auxv, AT_ENTRY), Some(custom_bias + 0x100));
    assert_eq!(auxv_value(&auxv, AT_BASE), Some(DEFAULT_INTERP_LOAD_BIAS));
}

#[test]
fn identity_and_secure_auxv_entries_match_step31_contract() {
    let bytes = dynamic_aarch64_elf();
    let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
    let headers = image.program_header_table().unwrap();
    let plan = UserLoadPlan::<4>::from_image(&image, LoadPolicy::default()).unwrap();
    let spec = LinuxInitialStackSpec {
        argv0: b"/bin/step31-identity-auxv",
        argv_tail: &[],
        envp: &[],
        program_headers: plan.load_bias() + headers.virtual_addr(),
        program_header_entry_size: headers.entry_size() as u64,
        program_header_count: headers.entry_count() as u64,
        interpreter_base: 0,
        entry: plan.entry(),
        uid: 1000,
        euid: 1001,
        gid: 2000,
        egid: 2001,
        secure: true,
        random: [0xa5; 16],
    };
    let auxv = encoded_auxv(&plan, spec);

    assert_eq!(auxv_value(&auxv, AT_UID), Some(1000));
    assert_eq!(auxv_value(&auxv, AT_EUID), Some(1001));
    assert_eq!(auxv_value(&auxv, AT_GID), Some(2000));
    assert_eq!(auxv_value(&auxv, AT_EGID), Some(2001));
    assert_eq!(auxv_value(&auxv, AT_SECURE), Some(1));
}

#[test]
fn all_zero_at_random_is_rejected_by_step31_stack_contract() {
    let bytes = dynamic_aarch64_elf();
    let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
    let headers = image.program_header_table().unwrap();
    let plan = UserLoadPlan::<4>::from_image(&image, LoadPolicy::default()).unwrap();
    let spec = LinuxInitialStackSpec {
        argv0: b"/bin/step31-zero-random",
        argv_tail: &[],
        envp: &[],
        program_headers: plan.load_bias() + headers.virtual_addr(),
        program_header_entry_size: headers.entry_size() as u64,
        program_header_count: headers.entry_count() as u64,
        interpreter_base: 0,
        entry: plan.entry(),
        uid: 0,
        euid: 0,
        gid: 0,
        egid: 0,
        secure: false,
        random: [0; 16],
    };

    let stack = plan.stack();
    let last_page = stack.stack_pages() - 1;
    let mut page = [0xa5u8; PAGE_SIZE as usize];
    assert_eq!(
        plan_linux_initial_stack(stack, spec),
        Err(LinuxStackError::AllZeroRandom)
    );
    assert_eq!(
        initialize_linux_stack_page(stack, spec, last_page, &mut page),
        Err(LinuxStackError::AllZeroRandom)
    );
    assert!(page.iter().all(|byte| *byte == 0xa5));
}

#[test]
fn dynamic_load_plan_composes_executable_with_pt_interp_and_et_dyn_interpreter() {
    let exec_bytes = dynamic_aarch64_elf_with_interp();
    let interp_bytes = dynamic_aarch64_elf();
    let exec_image = Image::parse_for_machine(&exec_bytes, Machine::Aarch64).unwrap();
    let interp_image = Image::parse_for_machine(&interp_bytes, Machine::Aarch64).unwrap();

    let composed = DynamicUserLoadPlan::<4>::from_images(
        &exec_image,
        &interp_image,
        DynamicLoadPolicy::default(),
    )
    .unwrap();

    assert_eq!(composed.executable().load_bias(), DEFAULT_DYN_LOAD_BIAS);
    assert_eq!(composed.interpreter_base(), DEFAULT_INTERP_LOAD_BIAS);
    assert_eq!(composed.program_entry(), DEFAULT_DYN_LOAD_BIAS + 0x180);
    assert_eq!(composed.initial_pc(), DEFAULT_INTERP_LOAD_BIAS + 0x100);
}

#[test]
fn dynamic_load_plan_rejects_overlap_nested_interp_and_et_exec_interpreter() {
    let exec_bytes = dynamic_aarch64_elf_with_interp();
    let interp_bytes = dynamic_aarch64_elf();
    let exec_image = Image::parse_for_machine(&exec_bytes, Machine::Aarch64).unwrap();
    let interp_image = Image::parse_for_machine(&interp_bytes, Machine::Aarch64).unwrap();

    let overlapping = DynamicLoadPolicy {
        executable: LoadPolicy::default(),
        interpreter_load_bias: DEFAULT_DYN_LOAD_BIAS,
    };
    assert_eq!(
        DynamicUserLoadPlan::<4>::from_images(&exec_image, &interp_image, overlapping).map(|_| ()),
        Err(PlanError::InterpreterOverlap)
    );

    assert_eq!(
        DynamicUserLoadPlan::<4>::from_images(
            &exec_image,
            &exec_image,
            DynamicLoadPolicy::default()
        )
        .map(|_| ()),
        Err(PlanError::NestedInterpreterForbidden)
    );

    let mut et_exec_interp = dynamic_aarch64_elf();
    et_exec_interp[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    let et_exec_image = Image::parse_for_machine(&et_exec_interp, Machine::Aarch64).unwrap();
    assert_eq!(
        DynamicUserLoadPlan::<4>::from_images(
            &exec_image,
            &et_exec_image,
            DynamicLoadPolicy::default()
        )
        .map(|_| ()),
        Err(PlanError::InvalidInterpreterImageType)
    );
}
