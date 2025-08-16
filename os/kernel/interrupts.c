#include "include.h"

/*
MIT License

Copyright (c) 2025 Aditya Bansal

Permission is hereby granted, free of charge, to any person obtaining 
a copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation the 
rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom 
the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be 
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/*==============================================================================================================
  COMPLETE RING 3 ISOLATION SYSTEM
================================================================================================================*/

// FIXED GDT setup with proper 64-bit descriptors
void setup_gdt_with_rings (void) {
    println("GDT: Setting up complete Ring 0/3 separation");
    
    struct gdt_entry {
        uint16_t limit_low;
        uint16_t base_low;
        uint8_t base_middle;
        uint8_t access;
        uint8_t granularity;
        uint8_t base_high;
    } __attribute__((packed));
    
    static struct gdt_entry gdt[8];
    
    // Null descriptor
    gdt[0] = (struct gdt_entry){0, 0, 0, 0, 0, 0};
    
    // FIXED: Kernel code segment (Ring 0) - 0x08
    gdt[1] = (struct gdt_entry){
        .limit_low = 0xFFFF,
        .base_low = 0,
        .base_middle = 0,
        .access = 0x9A,      // Present, Ring 0, Code, Executable, Readable
        .granularity = 0xA0, // FIXED: 64-bit L bit (bit 5) + G bit (bit 7) = 0xA0
        .base_high = 0
    };
    
    // FIXED: Kernel data segment (Ring 0) - 0x10
    gdt[2] = (struct gdt_entry){
        .limit_low = 0xFFFF,
        .base_low = 0,
        .base_middle = 0,
        .access = 0x92,      // Present, Ring 0, Data, Writable
        .granularity = 0x80, // FIXED: Only G bit for data segment
        .base_high = 0
    };
    
    // FIXED: User code segment (Ring 3) - 0x18
    gdt[3] = (struct gdt_entry){
        .limit_low = 0xFFFF,
        .base_low = 0,
        .base_middle = 0,
        .access = 0xFA,      // Present, Ring 3, Code, Executable, Readable
        .granularity = 0xA0, // FIXED: 64-bit L bit + G bit
        .base_high = 0
    };
    
    // FIXED: User data segment (Ring 3) - 0x20
    gdt[4] = (struct gdt_entry){
        .limit_low = 0xFFFF,
        .base_low = 0,
        .base_middle = 0,
        .access = 0xF2,      // Present, Ring 3, Data, Writable
        .granularity = 0x80, // FIXED: Only G bit for data segment
        .base_high = 0
    };
    
    // FIXED: TSS descriptor - proper 16-byte TSS in 64-bit mode
    uint64_t tss_base = (uint64_t)&kernel_tss;
    
    // TSS low part - 0x28
    gdt[5] = (struct gdt_entry){
        .limit_low = sizeof(tss_t) - 1,
        .base_low = tss_base & 0xFFFF,
        .base_middle = (tss_base >> 16) & 0xFF,
        .access = 0x89,      // Present, Ring 0, TSS Available
        .granularity = 0x00, // No granularity for TSS
        .base_high = (tss_base >> 24) & 0xFF
    };
    
    // FIXED: TSS high part - proper 64-bit TSS high descriptor
    gdt[6] = (struct gdt_entry){
        .limit_low = (tss_base >> 32) & 0xFFFF,  // High 32 bits of base
        .base_low = (tss_base >> 48) & 0xFFFF,   // Top 16 bits of base
        .base_middle = 0,
        .access = 0,         // Reserved
        .granularity = 0,    // Reserved
        .base_high = 0       // Reserved
    };
    
    // CRITICAL: TSS setup for Ring 3 → Ring 0 transitions
    memset(&kernel_tss, 0, sizeof(tss_t));
    kernel_tss.rsp0 = (uint64_t)kernel_stack + sizeof(kernel_stack) - 16;
    kernel_tss.iomap_base = sizeof(tss_t); // No I/O bitmap

    // Load GDT
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) gdtr = {
        .limit = sizeof(gdt) - 1,
        .base = (uint64_t)gdt
    };
    
    __asm__ volatile("lgdt %0" : : "m"(gdtr));
    
    // FIXED: Reload segment registers with proper selectors
    __asm__ volatile(
        "mov %0, %%ax\n"
        "mov %%ax, %%ds\n"
        "mov %%ax, %%es\n"
        "mov %%ax, %%fs\n"
        "mov %%ax, %%gs\n"
        "mov %%ax, %%ss\n"
        "pushq %1\n"        // Push new CS
        "pushq $1f\n"       // Push return address
        "lretq\n"           // Far return to reload CS
        "1:\n"
        :
        : "i"(KERNEL_DATA_SELECTOR), "i"(KERNEL_CODE_SELECTOR)
        : "rax"
    );
    
    // Load TSS
    __asm__ volatile("ltr %0" : : "r"((uint16_t)0x28));
    
    println("GDT: Complete Ring 0/3 separation configured");
}

// FIXED: Exception handler that finds the interrupt frame correctly
void general_exception_handler (void) {
    static int exception_count = 0;
    exception_count++;
    
    if (exception_count > 3) {
        println("EXCEPTION: Too many exceptions - halting system");
        while (1) {
            __asm__ volatile("cli; hlt");
        }
    }
    
    println("EXCEPTION: Ring 3 crash - SCANNING for interrupt frame");
    
    uint64_t current_rsp;
    __asm__ volatile("movq %%rsp, %0" : "=r"(current_rsp));
    
    print("EXCEPTION: Handler RSP: 0x");
    char hex_str[20];
    uint64_to_hex(current_rsp, hex_str);
    println(hex_str);
    
    // SCAN the stack to find the interrupt frame
    // Look for CS = 0x1B (USER_CODE_SELECTOR) in the stack
    uint64_t* stack_scan = (uint64_t*)current_rsp;
    
    println("EXCEPTION: Scanning stack for interrupt frame...");
    
    for (int offset = 0; offset < 50; offset++) {
        uint64_t potential_rip = stack_scan[offset];
        uint64_t potential_cs = stack_scan[offset + 1];
        uint64_t potential_rflags = stack_scan[offset + 2];
        uint64_t potential_rsp = stack_scan[offset + 3];
        uint64_t potential_ss = stack_scan[offset + 4];
        
        // Check if this looks like a valid Ring 3 interrupt frame
        if (potential_cs == 0x1B && potential_ss == 0x23) {
            print("EXCEPTION: Found interrupt frame at offset ");
            char offset_str[8];
            offset_str[0] = '0' + (offset / 10);
            offset_str[1] = '0' + (offset % 10);
            offset_str[2] = '\0';
            println(offset_str);
            
            print("EXCEPTION: RIP: 0x");
            uint64_to_hex(potential_rip, hex_str);
            println(hex_str);
            
            print("EXCEPTION: CS: 0x");
            uint64_to_hex(potential_cs, hex_str);
            println(hex_str);
            
            print("EXCEPTION: RFLAGS: 0x");
            uint64_to_hex(potential_rflags, hex_str);
            println(hex_str);
            
            print("EXCEPTION: RSP: 0x");
            uint64_to_hex(potential_rsp, hex_str);
            println(hex_str);
            
            print("EXCEPTION: SS: 0x");
            uint64_to_hex(potential_ss, hex_str);
            println(hex_str);
            
            // Analyze the crash
            if (potential_rip >= 0x20000000 && potential_rip < 0x40000000) {
                println("EXCEPTION: Ring 3 program was running and crashed!");

				print("EXCEPTION: Looking for segment containing RIP: 0x");
				char rip_hex[20];
				uint64_to_hex(potential_rip, rip_hex);
				println(rip_hex);
				mfs_entry_t* crash_segment = NULL;
				if (crash_segment) {
				    print("EXCEPTION: Found segment at: 0x");
				    uint64_to_hex(crash_segment->start_addr, rip_hex);
				    println(rip_hex);
				
				    print("EXCEPTION: Calculated offset: 0x");
				    uint64_to_hex(offset, rip_hex);
				    println(rip_hex);
				}
                
                // FIXED: Use MFS-safe memory reading in exception handler
				print("EXCEPTION: Crash instruction: ");
							
				// Find MFS segment containing the crash address
				for (int i = 0; i < MFS_MAX_ENTRIES; i++) {
				    mfs_entry_t* entry = &mfs_sb.entry_table[i];
				    if (entry->type == MFS_TYPE_SEGMENT && 
				        entry->magic == MFS_MAGIC &&
				        potential_rip >= entry->start_addr && 
				        potential_rip < entry->start_addr + entry->size) {
				        crash_segment = entry;
				        break;
				    }
				}
				
				if (crash_segment) {
				    // Use MFS safe read to get crash instruction
				    uint8_t crash_bytes[8];
				    size_t offset = potential_rip - crash_segment->start_addr;
				
				    if (mfs_read(crash_segment, offset, crash_bytes, 8) == 0) {
				        for (int i = 0; i < 8; i++) {
				            char hex_byte[4];
				            uint8_t byte = crash_bytes[i];
				            hex_byte[0] = (byte >> 4) < 10 ? ('0' + (byte >> 4)) : ('A' + (byte >> 4) - 10);
				            hex_byte[1] = (byte & 0xF) < 10 ? ('0' + (byte & 0xF)) : ('A' + (byte & 0xF) - 10);
				            hex_byte[2] = ' ';
				            hex_byte[3] = '\0';
				            print(hex_byte);
				        }
				    } else {
				        print("MFS READ FAILED");
				    }
				} else {
				    print("NOT IN MFS SEGMENT");
				}
				
				println("");

            } else if (potential_rip == 0) {
                println("EXCEPTION: RIP is 0 - iretq setup failed");
            } else {
                println("EXCEPTION: RIP outside user space - bad transition");
            }
            
            break;
        }
    }
    
    println("EXCEPTION: Stack scan complete");
    
    // Restore kernel and halt
    __asm__ volatile("cli");
    
    __asm__ volatile(
        "movw %0, %%ax\n"
        "movw %%ax, %%ds\n"
        "movw %%ax, %%es\n"
        "movw %%ax, %%fs\n"
        "movw %%ax, %%gs\n"
        "movw %%ax, %%ss\n"
        :
        : "i"(KERNEL_DATA_SELECTOR)
        : "rax"
    );
    
    println("EXCEPTION: Terminating Ring 3 - returning to kernel");
    
    __asm__ volatile(
        "movq %0, %%rsp\n"
        "movq %1, %%rbp\n"
        "jmp kernel_main_loop\n"
        :
        : "m"(kernel_rsp_global), "m"(kernel_rbp_global)
    );
}

// FIXED: Assembly wrapper that never returns to Ring 3
__asm__(
    ".global exception_handler_asm\n"
    ".global kernel_main_loop\n"
    "exception_handler_asm:\n"
    "cli\n"                    // Disable interrupts immediately
    
    // Save exception context
    "pushq %rax\n"
    "pushq %rbx\n"
    "pushq %rcx\n"
    "pushq %rdx\n"
    "pushq %rsi\n"
    "pushq %rdi\n"
    "pushq %r8\n"
    "pushq %r9\n"
    "pushq %r10\n"
    "pushq %r11\n"
    "pushq %r12\n"
    "pushq %r13\n"
    "pushq %r14\n"
    "pushq %r15\n"
    "pushq %rbp\n"
    
    // Switch to kernel segments
    "movw $0x10, %ax\n"
    "movw %ax, %ds\n"
    "movw %ax, %es\n"
    "movw %ax, %fs\n"
    "movw %ax, %gs\n"
    "movw %ax, %ss\n"
    
    // Call exception handler (it will jump to kernel_main_loop)
    "call general_exception_handler\n"
    
    // Should never reach here
    "hlt\n"
    
    "kernel_main_loop:\n"
    // Safe kernel loop - never return to Ring 3
    "sti\n"                    // Re-enable interrupts
    "1:\n"
    "hlt\n"                    // Wait for interrupts
    "jmp 1b\n"                 // Loop forever
);

// FIXED: Kernel continuation point after Ring 3 termination
__asm__(
    ".global kernel_continue\n"
    "kernel_continue:\n"
    "ret\n"  // Return to caller (test_ring3_setup)
);

extern void kernel_continue(void);

extern void exception_handler_asm(void);
extern void kernel_return_point(void);  // Declare the global label

/*==============================================================================================================
  PROPER INTERRUPT HANDLING SYSTEM
================================================================================================================*/

// Interrupt handler function pointers
extern void isr0();   // Division by zero
extern void isr1();   // Debug
extern void isr2();   // NMI
extern void isr3();   // Breakpoint
extern void isr4();   // Overflow
extern void isr5();   // Bound range exceeded
extern void isr6();   // Invalid opcode
extern void isr7();   // Device not available
extern void isr8();   // Double fault
extern void isr9();   // Coprocessor segment overrun
extern void isr10();  // Invalid TSS
extern void isr11();  // Segment not present
extern void isr12();  // Stack fault
extern void isr13();  // General protection fault
extern void isr14();  // Page fault
extern void isr15();  // Reserved
extern void isr16();  // x87 floating point exception
extern void isr17();  // Alignment check
extern void isr18();  // Machine check
extern void isr19();  // SIMD floating point exception

// IRQ handlers
extern void irq0();   // Timer
extern void irq1();   // Keyboard
extern void irq2();   // Cascade
extern void irq3();   // COM2
extern void irq4();   // COM1
extern void irq5();   // LPT2
extern void irq6();   // Floppy
extern void irq7();   // LPT1
extern void irq8();   // CMOS clock
extern void irq9();   // Free
extern void irq10();  // Free
extern void irq11();  // Free
extern void irq12();  // PS2 mouse
extern void irq13();  // FPU
extern void irq14();  // Primary ATA
extern void irq15();  // Secondary ATA

// Add the missing assembly interrupt stubs
__asm__(
    // Exception handlers (no error code)
    ".global isr0\n"
    "isr0:\n"
    "    pushq $0\n"      // Dummy error code
    "    pushq $0\n"      // Interrupt number
    "    jmp isr_common\n"
    
    ".global isr1\n"
    "isr1:\n"
    "    pushq $0\n"
    "    pushq $1\n"
    "    jmp isr_common\n"
    
    ".global isr2\n"
    "isr2:\n"
    "    pushq $0\n"
    "    pushq $2\n"
    "    jmp isr_common\n"
    
    ".global isr3\n"
    "isr3:\n"
    "    pushq $0\n"
    "    pushq $3\n"
    "    jmp isr_common\n"
    
    // ADD THE MISSING ONES:
    ".global isr4\n"
    "isr4:\n"
    "    pushq $0\n"
    "    pushq $4\n"
    "    jmp isr_common\n"
    
    ".global isr5\n"
    "isr5:\n"
    "    pushq $0\n"
    "    pushq $5\n"
    "    jmp isr_common\n"
    
    ".global isr6\n"
    "isr6:\n"
    "    pushq $0\n"
    "    pushq $6\n"
    "    jmp isr_common\n"
    
    ".global isr7\n"
    "isr7:\n"
    "    pushq $0\n"
    "    pushq $7\n"
    "    jmp isr_common\n"
    
    ".global isr8\n"
    "isr8:\n"
    "    pushq $8\n"      // Double fault has error code
    "    jmp isr_common\n"
    
    ".global isr9\n"
    "isr9:\n"
    "    pushq $0\n"
    "    pushq $9\n"
    "    jmp isr_common\n"
    
    ".global isr10\n"
    "isr10:\n"
    "    pushq $10\n"     // Invalid TSS has error code
    "    jmp isr_common\n"
    
    ".global isr11\n"
    "isr11:\n"
    "    pushq $11\n"     // Segment not present has error code
    "    jmp isr_common\n"
    
    ".global isr12\n"
    "isr12:\n"
    "    pushq $12\n"     // Stack fault has error code
    "    jmp isr_common\n"
    
    ".global isr13\n"
    "isr13:\n"
    "    pushq $13\n"     // GPF has error code
    "    jmp isr_common\n"
    
    ".global isr14\n"
    "isr14:\n"
    "    pushq $14\n"     // Page fault has error code
    "    jmp isr_common\n"
    
    ".global isr15\n"
    "isr15:\n"
    "    pushq $0\n"
    "    pushq $15\n"
    "    jmp isr_common\n"
    
    ".global isr16\n"
    "isr16:\n"
    "    pushq $0\n"
    "    pushq $16\n"
    "    jmp isr_common\n"
    
    ".global isr17\n"
    "isr17:\n"
    "    pushq $17\n"     // Alignment check has error code
    "    jmp isr_common\n"
    
    ".global isr18\n"
    "isr18:\n"
    "    pushq $0\n"
    "    pushq $18\n"
    "    jmp isr_common\n"
    
    ".global isr19\n"
    "isr19:\n"
    "    pushq $0\n"
    "    pushq $19\n"
    "    jmp isr_common\n"
    
    // IRQ handlers
    ".global irq0\n"
    "irq0:\n"
    "    pushq $0\n"
    "    pushq $32\n"     // IRQ 0 = interrupt 32
    "    jmp irq_common\n"
    
    ".global irq1\n"
    "irq1:\n"
    "    pushq $0\n"
    "    pushq $33\n"
    "    jmp irq_common\n"

	".global irq12\n"
    "irq12:\n"
    "    pushq $0\n"
    "    pushq $44\n"
    "    jmp irq_common\n"
    
    // Common ISR handler
    "isr_common:\n"
    "    pushq %rax\n"
    "    pushq %rbx\n"
    "    pushq %rcx\n"
    "    pushq %rdx\n"
    "    pushq %rsi\n"
    "    pushq %rdi\n"
    "    pushq %rbp\n"
    "    pushq %r8\n"
    "    pushq %r9\n"
    "    pushq %r10\n"
    "    pushq %r11\n"
    "    pushq %r12\n"
    "    pushq %r13\n"
    "    pushq %r14\n"
    "    pushq %r15\n"
    "    movq %rsp, %rdi\n"    // Pass stack pointer as argument
    "    call isr_handler\n"
    "    popq %r15\n"
    "    popq %r14\n"
    "    popq %r13\n"
    "    popq %r12\n"
    "    popq %r11\n"
    "    popq %r10\n"
    "    popq %r9\n"
    "    popq %r8\n"
    "    popq %rbp\n"
    "    popq %rdi\n"
    "    popq %rsi\n"
    "    popq %rdx\n"
    "    popq %rcx\n"
    "    popq %rbx\n"
    "    popq %rax\n"
    "    addq $16, %rsp\n"     // Remove error code and interrupt number
    "    iretq\n"
    
    // Common IRQ handler
    "irq_common:\n"
    "    pushq %rax\n"
    "    pushq %rbx\n"
    "    pushq %rcx\n"
    "    pushq %rdx\n"
    "    pushq %rsi\n"
    "    pushq %rdi\n"
    "    pushq %rbp\n"
    "    pushq %r8\n"
    "    pushq %r9\n"
    "    pushq %r10\n"
    "    pushq %r11\n"
    "    pushq %r12\n"
    "    pushq %r13\n"
    "    pushq %r14\n"
    "    pushq %r15\n"
    "    movq %rsp, %rdi\n"
    "    call irq_handler\n"
    "    popq %r15\n"
    "    popq %r14\n"
    "    popq %r13\n"
    "    popq %r12\n"
    "    popq %r11\n"
    "    popq %r10\n"
    "    popq %r9\n"
    "    popq %r8\n"
    "    popq %rbp\n"
    "    popq %rdi\n"
    "    popq %rsi\n"
    "    popq %rdx\n"
    "    popq %rcx\n"
    "    popq %rbx\n"
    "    popq %rax\n"
    "    addq $16, %rsp\n"
    "    iretq\n"
);

// Enhanced exception handler with more debugging
void isr_handler(interrupt_frame_t* frame) {
    static int exception_count = 0;
    exception_count++;
    
    // Prevent infinite loops
    if (exception_count > 10) {
        println("ISR: Too many exceptions - halting system");
        __asm__ volatile("cli; hlt");
        while (1) {}
    }
    
    print("ISR: Exception ");
    char int_str[8];
    uint64_to_hex(frame->int_no, int_str);
    print(int_str);
    print(" at RIP: ");
    char rip_str[16];
    uint64_to_hex(frame->rip, rip_str);
    println(rip_str);
    
    // Detailed debugging for Exception 6 (Invalid Opcode)
    if (frame->int_no == 6) {
        println("ISR: Invalid Opcode Exception");
        
        print("ISR: RSP: ");
        char rsp_str[16];
        uint64_to_hex(frame->rsp, rsp_str);
        println(rsp_str);
        
        print("ISR: RBP: ");
        char rbp_str[16];
        uint64_to_hex(frame->rbp, rbp_str);
        println(rbp_str);
        
        print("ISR: CS: ");
        char cs_str[16];
        uint64_to_hex(frame->cs, cs_str);
        println(cs_str);
        
        print("ISR: RFLAGS: ");
        char flags_str[16];
        uint64_to_hex(frame->rflags, flags_str);
        println(flags_str);
        
        // Try to read the invalid instruction
        if (frame->rip >= 0x100000 && frame->rip < 0x40000000) {
            uint8_t* instruction_ptr = (uint8_t*)frame->rip;
            print("ISR: Instruction bytes: ");
            for (int i = 0; i < 4; i++) {
                char byte_str[4];
                uint64_to_hex(instruction_ptr[i], byte_str);
                print(byte_str);
                print(" ");
            }
            println("");
        }
        
        println("ISR: Halting due to invalid opcode");
        __asm__ volatile("cli; hlt");
        while (1) {}
    }
    
    // Handle other exceptions
    if (frame->int_no == 8) {
        println("ISR: Double fault - system halting");
        __asm__ volatile("cli; hlt");
        while (1) {}
    }
    
    if (frame->int_no == 13) {
        print("ISR: General protection fault, error code: ");
        char err_str[16];
        uint64_to_hex(frame->err_code, err_str);
        println(err_str);
    }
    
    if (frame->int_no == 14) {
        print("ISR: Page fault, error code: ");
        char err_str[16];
        uint64_to_hex(frame->err_code, err_str);
        println(err_str);
    }
}

void irq_handler(interrupt_frame_t* frame) {
    uint32_t irq_num = frame->int_no - 32;
    if (irq_num >= 15) outb(0xA0, 0x20);
    outb(0x20, 0x20);

    if (irq_num == 0) {
        static int timer_count = 0;
        timer_count++;

        // Save current thread context snapshot (interrupt frame) to MFS
        char context_name[64];
        strcpy(context_name, "snapshot_");
        char id_str[8];
        uint64_to_hex(current_thread_id, id_str);
        strcat(context_name, id_str);
        mfs_entry_t* snapshot_segment = mfs_find(context_name, mfs_sb.root_dir);
        if (!snapshot_segment) {
            size_t frame_size = sizeof(interrupt_frame_t);
            size_t blocks_needed = (frame_size + 4095) / 4096;
            if (blocks_needed < 2) blocks_needed = 2;
            snapshot_segment = mfs_seg(context_name, blocks_needed * 4096, mfs_sb.root_dir);
        }
        if (!snapshot_segment) {
            println("IRQ: ERROR - Cannot create snapshot segment");
            while (1) { __asm__ volatile("cli; hlt"); }
        }
        if (mfs_write(snapshot_segment, 0, frame, sizeof(interrupt_frame_t)) != 0) {
            println("IRQ: ERROR - Failed to write snapshot");
            while (1) { __asm__ volatile("cli; hlt"); }
        }

        // Find next active thread (round-robin)
        uint32_t next_thread = (current_thread_id + 1) % thread_count;
        int found = 0;
        for (int i = 0; i < thread_count; ++i) {
            thread_control_block_t tcb;
            if (read_thread(next_thread, &tcb) == 0 && tcb.state != THREAD_STATE_TERMINATED) {
                found = 1;
                break;
            }
            next_thread = (next_thread + 1) % thread_count;
        }
        if (!found) {
            println("IRQ: ERROR - No runnable threads, halting");
            while (1) { __asm__ volatile("cli; hlt"); }
        }

        // Try to load next thread's snapshot (interrupt frame) from MFS
        char next_snapshot_name[64];
        strcpy(next_snapshot_name, "snapshot_");
        char next_id_str[8];
        uint64_to_hex(next_thread, next_id_str);
        strcat(next_snapshot_name, next_id_str);
        mfs_entry_t* next_snapshot_segment = mfs_find(next_snapshot_name, mfs_sb.root_dir);

        current_thread_id = next_thread;

        if (!next_snapshot_segment || mfs_read(next_snapshot_segment, 0, frame, sizeof(interrupt_frame_t)) != 0) {
            println("IRQ: No snapshot for next thread, executing from entry point");
            execute(next_thread); // This should never return
            while (1) { __asm__ volatile("cli; hlt"); }
        }
    }
	
	uint8_t mask = inb(0x21);
	mask &= ~(1 << 1); // Unmask IRQ 1 (clear bit 1)
	outb(0x21, mask);
	if (irq_num == 1) {
	    uint8_t scancode = inb(0x60);	

	    // Ignore key releases (scancode >= 0x80)
	    if (scancode & 0x80) return;	

	    char ascii = scancode_to_ascii(scancode);	

	    if (ascii) {
	        int next_head = (keyboard_buffer_head + 1) % KEYBOARD_BUFFER_SIZE;
	        if (next_head != keyboard_buffer_tail) { // buffer not full
	            keyboard_buffer[keyboard_buffer_head] = ascii;
	            keyboard_buffer_head = next_head;
	        }
	    }
	    outb(0x20, 0x20); // Send EOI
	}

	if (irq_num == 12) {
	    println("MOUSE: IRQ12 triggered!");
	    uint8_t data = inb(0x60);
	    print("MOUSE: Data=0x");
	    char hex[3];
	    hex[0] = (data >> 4) < 10 ? '0' + (data >> 4) : 'A' + (data >> 4) - 10;
	    hex[1] = (data & 0xF) < 10 ? '0' + (data & 0xF) : 'A' + (data & 0xF) - 10;
	    hex[2] = '\0';
	    println(hex);
	}
}

// Set IDT entry
void set_idt_entry(int num, uint64_t handler, uint16_t selector, uint8_t flags) {
    idt[num].offset_low = handler & 0xFFFF;
    idt[num].selector = selector;
    idt[num].ist = 0;
    idt[num].type_attr = flags;
    idt[num].offset_mid = (handler >> 16) & 0xFFFF;
    idt[num].offset_high = (handler >> 32) & 0xFFFFFFFF;
    idt[num].reserved = 0;
}

// Initialize IDT properly
void init_idt (void) {
    println("IDT: Setting up enhanced Ring 3 protection");
    
    // Clear IDT
    for (int i = 0; i < 256; i++) {
        set_idt_entry(i, 0, 0, 0);
    }
    
    // Set up exception handlers
    // ALL CPU exceptions (0-31)
    set_idt_entry(0, (uint64_t)isr0, KERNEL_CODE_SELECTOR, 0x8E);   // Division by zero
    set_idt_entry(1, (uint64_t)isr1, KERNEL_CODE_SELECTOR, 0x8E);   // Debug
    set_idt_entry(2, (uint64_t)isr2, KERNEL_CODE_SELECTOR, 0x8E);   // NMI
    set_idt_entry(3, (uint64_t)isr3, KERNEL_CODE_SELECTOR, 0x8E);   // Breakpoint
    set_idt_entry(4, (uint64_t)isr4, KERNEL_CODE_SELECTOR, 0x8E);   // Overflow
    set_idt_entry(5, (uint64_t)isr5, KERNEL_CODE_SELECTOR, 0x8E);   // Bound range
    set_idt_entry(6, (uint64_t)isr6, KERNEL_CODE_SELECTOR, 0x8E);   // Invalid opcode
    set_idt_entry(7, (uint64_t)isr7, KERNEL_CODE_SELECTOR, 0x8E);   // Device not available
    set_idt_entry(8, (uint64_t)isr8, KERNEL_CODE_SELECTOR, 0x8E);   // Double fault
    set_idt_entry(9, (uint64_t)isr9, KERNEL_CODE_SELECTOR, 0x8E);   // Coprocessor overrun
    set_idt_entry(10, (uint64_t)isr10, KERNEL_CODE_SELECTOR, 0x8E); // Invalid TSS
    set_idt_entry(11, (uint64_t)isr11, KERNEL_CODE_SELECTOR, 0x8E); // Segment not present
    set_idt_entry(12, (uint64_t)isr12, KERNEL_CODE_SELECTOR, 0x8E); // Stack fault
    set_idt_entry(13, (uint64_t)isr13, KERNEL_CODE_SELECTOR, 0x8E); // GPF
    set_idt_entry(14, (uint64_t)isr14, KERNEL_CODE_SELECTOR, 0x8E); // Page fault
    set_idt_entry(15, (uint64_t)isr15, KERNEL_CODE_SELECTOR, 0x8E); // Reserved
    set_idt_entry(16, (uint64_t)isr16, KERNEL_CODE_SELECTOR, 0x8E); // x87 FPU error
    set_idt_entry(17, (uint64_t)isr17, KERNEL_CODE_SELECTOR, 0x8E); // Alignment check
    set_idt_entry(18, (uint64_t)isr18, KERNEL_CODE_SELECTOR, 0x8E); // Machine check
    set_idt_entry(19, (uint64_t)isr19, KERNEL_CODE_SELECTOR, 0x8E); // SIMD FP exception
    
    // Set up IRQ handlers
    set_idt_entry(32, (uint64_t)irq0, KERNEL_CODE_SELECTOR, 0x8E);  // Timer
    set_idt_entry(33, (uint64_t)irq1, KERNEL_CODE_SELECTOR, 0x8E);  // Keyboard
    
    // Load IDT
    idt_descriptor_t idtr = {
        .limit = sizeof(idt) - 1,
        .base = (uint64_t)idt
    };
    
    __asm__ volatile("lidt %0" : : "m"(idtr));
    
    // Initialize PIC
    outb(0x20, 0x11);  // Initialize master PIC
    outb(0xA0, 0x11);  // Initialize slave PIC
    outb(0x21, 0x20);  // Master PIC vector offset (32)
    outb(0xA1, 0x28);  // Slave PIC vector offset (40)
    outb(0x21, 0x04);  // Tell master PIC about slave
    outb(0xA1, 0x02);  // Tell slave PIC its cascade identity
    outb(0x21, 0x01);  // 8086 mode
    outb(0xA1, 0x01);  // 8086 mode
    outb(0x21, 0xFE);  // Mask all IRQs except timer
    outb(0xA1, 0xFF);  // Mask all slave IRQs
    
    idt_initialized = 1;
    println("IDT: Enhanced Ring 3 protection installed");
}

// REPLACE exception_init() with proper IDT setup
void exception_init (void) {
    println("RING3: Testing simple ELF loader with termination handling");
    
    // Setup GDT and IDT
    setup_gdt_with_rings();
    init_idt();

	println("RING3: GDT and IDT setup completed");

	// Initialize page fault handler
    init_page_fault_handler();
	println("RING3: Page fault handler initialized");
    
    println("RING3: Loading /MODULES/APPS/TEST.ELF");
    
    // Save current context for exception return
    __asm__ volatile(
        "movq %%rsp, %0\n"
        "movq %%rbp, %1\n"
        : "=m"(kernel_rsp_global), "=m"(kernel_rbp_global)
    );
    
    // Wait for potential Ring 3 termination
    println("RING3: Waiting for Ring 3 program completion or termination...");
    
    // Call kernel continuation point to handle Ring 3 termination
    kernel_continue();
    
    println("RING3: Ring 3 program terminated - back in kernel");
}

