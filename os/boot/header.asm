; VOSTROX OS - SAFE STACK RELOCATION
[BITS 32]

section .multiboot
align 8

header_start:
    dd 0xE85250D6                ; magic
    dd 0                         ; architecture (0 = i386)
    dd header_end - header_start  ; header length
    dd -(0xE85250D6 + 0 + (header_end - header_start)) ; checksum

; --- TAG: Framebuffer request (type 5) ---
align 8
tag_framebuffer:
    dw 5         ; type = 5 (framebuffer)
    dw 0         ; reserved
    dd 20        ; size of this tag (must be multiple of 8)
    dd 1024      ; width
    dd 768       ; height
    dd 32        ; depth (bits per pixel)

; --- TAG: End of header (type 0) ---
align 8
tag_end:
    dw 0         ; type = 0 (end tag)
    dw 0         ; reserved
    dd 8         ; size

header_end:

PAGE_PRESENT    equ 1 << 0
PAGE_WRITE      equ 1 << 1
PAGE_SIZE_2MB   equ 1 << 7

; SAFE REVERT - Don't use separate .stack section
section .bss
align 4096
pml4_table:      resb 4096
pdpt_table:      resb 4096
pd_table:        resb 4096

; Place some padding to push stack higher in .bss
padding:         resb 0x100000    ; 1MB padding

; Stack after padding - still in .bss but higher
align 16
global stack_bottom
stack_bottom:
    resb 65536                   ; 64KB stack
global stack_top
stack_top:

section .text
global _start
extern kernel_main

_start:
	mov eax, ebx
	mov dword [multiboot_info_addr], eax
	mov dword [multiboot_info_addr + 4], 0
    cli
    mov edi, ebx
    
    ; CRITICAL: Set stack to high memory location
    mov esp, stack_top
    
    ; Validate stack is properly set
    cmp esp, stack_bottom
    jbe .stack_error
    
    ; Ensure 16-byte alignment
    and esp, 0xFFFFFFF0
    
    ; Continue with existing boot process
    pushfd
    pop eax
    mov ecx, eax
    xor eax, 1 << 21
    push eax
    popfd
    pushfd
    pop eax
    push ecx
    popfd
    xor eax, ecx
    jz .no_long_mode
    
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .no_long_mode
    
    mov eax, 0x80000001
    cpuid
    test edx, 1 << 29
    jz .no_long_mode
    
    call setup_paging
    lgdt [gdt64.pointer]
    
    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax
    
    mov eax, pml4_table
    mov cr3, eax
    
    mov ecx, 0xC0000080
    rdmsr
    or eax, 1 << 8
    wrmsr
    
    mov eax, cr0
    or eax, 1 << 31
    or eax, 1
    mov cr0, eax
    
    jmp gdt64.code:long_mode_start

.stack_error:
    mov dword [0xB8000], 0x4F544F53  ; 'STK '
    mov dword [0xB8004], 0x4F524F45  ; 'ERR '
    hlt

.no_long_mode:
    mov dword [0xB8000], 0x4F524F45
    mov dword [0xB8004], 0x4F3A4F52
    mov dword [0xB8008], 0x4F204F20
    mov dword [0xB800C], 0x204F4F4E
    mov dword [0xB8010], 0x4F4F4C20
    mov dword [0xB8014], 0x204F474E
    mov dword [0xB8018], 0x4F444F4D
    mov dword [0xB801C], 0x4F452045
    hlt

; ENHANCED: Map COMPLETE memory including stack region
setup_paging:
    mov edi, pml4_table
    xor eax, eax
    mov ecx, 4096 * 3 / 4
    rep stosd
    
    mov edi, pml4_table
    mov eax, pdpt_table
    or eax, PAGE_PRESENT | PAGE_WRITE
    mov [edi], eax
    
    mov edi, pdpt_table
    mov eax, pd_table
    or eax, PAGE_PRESENT | PAGE_WRITE
    mov [edi], eax
    
    ; CRITICAL: Map CONTINUOUS memory from 0-8MB to cover stack
    mov edi, pd_table
    mov eax, 0x0
    or eax, PAGE_PRESENT | PAGE_WRITE | PAGE_SIZE_2MB
    mov [edi], eax        ; 0-2MB
    
    mov eax, 0x200000
    or eax, PAGE_PRESENT | PAGE_WRITE | PAGE_SIZE_2MB
    mov [edi + 8], eax    ; 2-4MB (STACK IS HERE!)
    
    mov eax, 0x400000
    or eax, PAGE_PRESENT | PAGE_WRITE | PAGE_SIZE_2MB
    mov [edi + 16], eax   ; 4-6MB
    
    mov eax, 0x600000
    or eax, PAGE_PRESENT | PAGE_WRITE | PAGE_SIZE_2MB
    mov [edi + 24], eax   ; 6-8MB
    
    ; CRITICAL: Add stack validation in 64-bit mode
    ; Calculate stack address and ensure it's mapped
    mov eax, stack_top
    shr eax, 21          ; Divide by 2MB to get page index
    cmp eax, 4           ; Check if within our mapped pages (0-8MB = 4 pages)
    jae .stack_mapping_error
    
    ret

.stack_mapping_error:
    ; Stack is outside mapped region - halt
    mov dword [0xB8000], 0x4F414D50  ; 'MAP '
    mov dword [0xB8004], 0x4F524F45  ; 'ERR '
    hlt

section .rodata
align 8
gdt64:
    .null: equ $ - gdt64
        dq 0
    .code: equ $ - gdt64
        dq 0x00AF9A000000FFFF
    .data: equ $ - gdt64
        dq 0x00CF92000000FFFF
    .pointer:
        dw $ - gdt64 - 1
        dq gdt64

section .bss
align 8
multiboot_info_addr: resq 1

section .text
[BITS 64]
long_mode_start:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    
    mov ax, gdt64.data
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    
    ; CRITICAL: Comprehensive stack validation
    mov rsp, stack_top
    
    ; 1. Validate stack is above bottom
    mov rax, stack_bottom
    cmp rsp, rax
    jbe .stack_error_64
    
    ; 2. Validate stack is in mapped region (0-8MB)
    cmp rsp, 0x800000    ; 8MB limit
    jae .stack_error_64
    
    ; 3. Ensure 16-byte alignment
    and rsp, ~0xF
    test rsp, 0xF
    jnz .stack_error_64
    
    ; 4. Test stack accessibility by writing/reading
    mov qword [rsp-8], 0x5A5A5A5A5A5A5A5A   ; Test write
    cmp qword [rsp-8], 0x5A5A5A5A5A5A5A5A   ; Test read
    jne .stack_error_64
    
    ; 5. Test stack growth area (allocate 1KB and test)
    sub rsp, 1024
    mov qword [rsp], 0xA5A5A5A5A5A5A5A5     ; Test deep stack write
    cmp qword [rsp], 0xA5A5A5A5A5A5A5A5     ; Test deep stack read
    jne .stack_error_64
    add rsp, 1024                            ; Restore stack
    
    ; Stack validation passed
	mov rax, [multiboot_info_addr]
	mov rdi, rax
    cld
    call kernel_main
    
    cli
    hlt
    jmp $

.stack_error_64:
    mov rax, 0xB8000
    mov qword [rax], 0x4F4B4F53      ; 'STK '
    mov qword [rax+8], 0x4F524F45    ; 'ERR '
    mov qword [rax+16], 0x4F414D50   ; 'MAP '
    hlt
