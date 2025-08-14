/* Simplified Linker script for VOSTROX OS - Single File Kernel */
OUTPUT_FORMAT("elf64-x86-64")
ENTRY(_start)

SECTIONS {
    /* Start at 1MB (conventional for kernels) */
    . = 1M;

    /* Multiboot header first */
    .multiboot : ALIGN(4K) {
        *(.multiboot)
    }

    /* Text section - all code */
    .text : ALIGN(4K) {
        *(.text)
        *(.text.*)
    }

    /* Read-only data */
    .rodata : ALIGN(4K) {
        *(.rodata)
        *(.rodata.*)
    }

    /* Read-write data (initialized) */
    .data : ALIGN(4K) {
        *(.data)
        *(.data.*)
    }

		/* Syscall table section */
    .syscall_table : ALIGN(4K) {
        KEEP(*(.syscall_table))
    }

    /* Read-write data (uninitialized) */
    .bss : ALIGN(4K) {
        *(COMMON)
        *(.bss)
        *(.bss.*)
    }

    /* GNU stack note */
    .note.GNU-stack (NOLOAD) : {
        *(.note.GNU-stack)
    }
    
    /* Discard unnecessary sections */
    /DISCARD/ : {
        *(.comment)
        *(.note)
        *(.note.*)
        *(.eh_frame)
        *(.eh_frame_hdr)
    }
}
