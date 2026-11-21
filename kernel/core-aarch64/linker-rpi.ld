OUTPUT_FORMAT(elf64-littleaarch64)
OUTPUT_ARCH(aarch64)
ENTRY(kernal_aarch64_protected_start)

/*
 * Native Raspberry Pi 3B+ / 4B / 5 AArch64 bare-metal kernel image (`kernel8.img` / `kernel_2712.img`).
 * RAM starts at 0x00000000 and the Raspberry Pi firmware loads 64-bit kernels at 0x00080000
 * with the FDT (DTB) pointer in register x0.
 */
KERNEL_PHYS_BASE = 0x00080000;
KERNEL_VIRT_BASE = 0xffffffff80080000;
STACK_GUARD_SIZE = 0x1000;
BOOT_STACK_SIZE = 0x80000;
SECONDARY_STACK_SIZE = 0x80000;
SECONDARY_STACK_COUNT = 4;
CLONE_STACK_COUNT = 56;
SECONDARY_STACK_STRIDE = STACK_GUARD_SIZE + SECONDARY_STACK_SIZE;
SCHEDULER_WORKER_STACK_SIZE = 0x10000;
BOOT_PAGE_TABLE_COUNT = 2048;
BOOT_PAGE_TABLE_BYTES = BOOT_PAGE_TABLE_COUNT * 0x1000;
KERNEL_HEAP_SIZE = 0x2400000;

PHDRS
{
  text PT_LOAD FLAGS(5);
  rodata PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
}

SECTIONS
{
  . = KERNEL_PHYS_BASE;
  __kernel_start = .;

  .text : ALIGN(0x1000)
  {
    __text_start = .;
    KEEP(*(.text._arm64_image_header))
    KEEP(*(.text._protected_start))
    KEEP(*(.text._protected_secondary_start))
    KEEP(*(.text._start))
    KEEP(*(.text._secondary_start))
    *(.text .text.*)
    *(.plt .plt.* .iplt .iplt.*)
    . = ALIGN(0x1000);
    __text_end = .;
  } :text

  .rodata : ALIGN(0x1000)
  {
    __rodata_start = .;
    *(.rodata .rodata.*)
    . = ALIGN(0x1000);
    __rodata_end = .;
  } :rodata

  .rela.dyn : ALIGN(8)
  {
    __rela_dyn_start = .;
    *(.rela.dyn .rela.dyn.*)
    __rela_dyn_end = .;
  } :rodata

  .data : ALIGN(0x1000)
  {
    __data_start = .;
    *(.data .data.*)
    *(.got .got.*)
    *(.data.rel.ro .data.rel.ro.*)
    . = ALIGN(0x1000);
    __data_end = .;
  } :data

  .bss (NOLOAD) : ALIGN(0x1000)
  {
    __bss_start = .;
    *(.bss .bss.* COMMON)
    . = ALIGN(0x1000);
    __bss_static_end = .;

    __boot_stack_guard_start = .;
    . += STACK_GUARD_SIZE;
    __boot_stack_bottom = .;
    . += BOOT_STACK_SIZE;
    __boot_stack_top = .;

    . = ALIGN(0x1000);
    __secondary_stacks_bottom = .;
    . += SECONDARY_STACK_STRIDE * SECONDARY_STACK_COUNT;
    __secondary_boot_stacks_top = .;
    __clone_stacks_bottom = .;
    . += SECONDARY_STACK_STRIDE * CLONE_STACK_COUNT;
    __clone_stacks_top = .;
    __secondary_stacks_top = .;

    . = ALIGN(0x1000);
    __scheduler_worker_guard_start = .;
    . += STACK_GUARD_SIZE;
    __scheduler_worker_stack_bottom = .;
    . += SCHEDULER_WORKER_STACK_SIZE;
    __scheduler_worker_stack_top = .;

    . = ALIGN(0x1000);
    __kernel_heap_start = .;
    . += KERNEL_HEAP_SIZE;
    __kernel_heap_end = .;

    . = ALIGN(0x1000);
    __boot_page_tables_start = .;
    . += BOOT_PAGE_TABLE_BYTES;
    __boot_page_tables_end = .;

    . = ALIGN(0x1000);
    __bss_end = .;
  } :data

  . = ALIGN(0x1000);
  __kernel_end = .;

  __kernel_phys_base = KERNEL_PHYS_BASE;
  __kernel_virt_base = KERNEL_VIRT_BASE;
  __secondary_stack_stride = SECONDARY_STACK_STRIDE;
  __clone_stack_count = CLONE_STACK_COUNT;
  __clone_stack_stride = SECONDARY_STACK_STRIDE;
  __stack_guard_size = STACK_GUARD_SIZE;

  /DISCARD/ :
  {
    *(.eh_frame .eh_frame_hdr)
    *(.comment)
    *(.note .note.*)
  }
}
