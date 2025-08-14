/* FIXED: Linker script for VOSTROX ELF applications */
OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
    /* Start at a high virtual address in our paged memory range */
    /* Use 256MB (0x10000000) which is in our mapped heap area */
    . = 0x20030000;

    /* Text section - executable code */
    .text ALIGN(0x1000) : {
        *(.text)
        *(.text.*)
    }

    /* Read-only data */
    .rodata ALIGN(0x1000) : {
        *(.rodata)
        *(.rodata.*)
    }

    /* Initialized data */
    .data ALIGN(0x1000) : {
        *(.data)
        *(.data.*)
    }

    /* Uninitialized data */
    .bss ALIGN(0x1000) : {
        *(.bss)
        *(.bss.*)
        *(COMMON)
    }

    /* Discard unnecessary sections */
    /DISCARD/ : {
        *(.note.*)
        *(.comment)
        *(.eh_frame)
        *(.eh_frame_hdr)
    }
}
