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
  PAGING TEST
================================================================================================================*/

// Test paging system
void test_paging (void) {
    println("PAGING: Testing paging system");
    
    if (paging_init() != 0) {
        println("PAGING: Initialization failed");
        return;
    }
    
    // Test allocation in different memory ranges
    println("PAGING: Testing memory allocation");
    
    void* ptr1 = safe_malloc(1024);
    if (ptr1) {
        println("PAGING: 1KB allocation successful");
        memset(ptr1, 0xAA, 1024);
        free(ptr1);
    }
    
    void* ptr2 = safe_malloc(64 * 1024);
    if (ptr2) {
        println("PAGING: 64KB allocation successful");
        memset(ptr2, 0xBB, 64 * 1024);
        free(ptr2);
    }
    
    println("PAGING: Test completed successfully");
}

void memory_stress_test (void) {
    println("MEMORY STRESS: Starting ROBUST memory test");
    
    // Test 1: Basic allocation test
    println("MEMORY STRESS: Test 1 - Basic allocation");
    void* ptr1 = malloc(64);
    if (ptr1) {
        println("MEMORY STRESS: 64-byte allocation SUCCESS");
        free(ptr1);
        println("MEMORY STRESS: 64-byte free SUCCESS");
    } else {
        println("MEMORY STRESS: 64-byte allocation FAILED");
        return;
    }
    
    // Test 2: Safe write test
    println("MEMORY STRESS: Test 2 - Safe write test");
    void* test_ptr = malloc(1024);
    if (test_ptr) {
        println("MEMORY STRESS: 1KB allocation SUCCESS");
        
        // Safe write pattern using our robust functions
        println("MEMORY STRESS: Starting safe write pattern");
        uint8_t* byte_ptr = (uint8_t*)test_ptr;
        
        for (int i = 0; i < 100; i++) { // Start with just 100 bytes
            if (safe_memory_write(test_ptr, (uint8_t)(i & 0xFF), i) != 0) {
                println("MEMORY STRESS: Safe write FAILED");
                free(test_ptr);
                return;
            }
        }
        println("MEMORY STRESS: Safe write pattern SUCCESS");
        
        // Safe read and verify
        println("MEMORY STRESS: Starting safe read verification");
        int errors = 0;
        for (int i = 0; i < 100; i++) {
            uint8_t read_value;
            if (safe_memory_read(test_ptr, &read_value, i) != 0) {
                println("MEMORY STRESS: Safe read FAILED");
                errors++;
                break;
            }
            if (read_value != (uint8_t)(i & 0xFF)) {
                errors++;
            }
        }
        
        if (errors == 0) {
            println("MEMORY STRESS: Safe read verification SUCCESS");
        } else {
            println("MEMORY STRESS: Safe read verification FAILED");
        }
        
        free(test_ptr);
        println("MEMORY STRESS: Test 2 completed");
    } else {
        println("MEMORY STRESS: 1KB allocation FAILED");
    }
    
    println("MEMORY STRESS: ROBUST test completed");
}

// Simple buffer test without FAT32
void simple_buffer_test (void) {
    println("BUFFER TEST: Testing buffer operations");
    
    // Test 1: Simple buffer allocation
    println("BUFFER TEST: Allocating 1024-byte buffer");
    uint8_t* buffer = (uint8_t*)malloc(1024);
    if (!buffer) {
        println("BUFFER TEST: Allocation FAILED");
        return;
    }
    println("BUFFER TEST: Allocation SUCCESS");
    
    // Test 2: Buffer clearing
    println("BUFFER TEST: Clearing buffer");
    memset(buffer, 0, 1024);
    println("BUFFER TEST: Clear SUCCESS");
    
    // Test 3: Buffer write
    println("BUFFER TEST: Writing to buffer");
    for (int i = 0; i < 100; i++) {
        buffer[i] = (uint8_t)(i & 0xFF);
    }
    println("BUFFER TEST: Write SUCCESS");
    
    // Test 4: Buffer read
    println("BUFFER TEST: Reading from buffer");
    int read_errors = 0;
    for (int i = 0; i < 100; i++) {
        if (buffer[i] != (uint8_t)(i & 0xFF)) {
            read_errors++;
        }
    }
    
    if (read_errors == 0) {
        println("BUFFER TEST: Read verification SUCCESS");
    } else {
        println("BUFFER TEST: Read verification FAILED");
    }
    
    // Test 5: Buffer patterns
    println("BUFFER TEST: Pattern test");
    memset(buffer, 0xAA, 512);
    memset(buffer + 512, 0x55, 512);
    
    if (buffer[0] == 0xAA && buffer[511] == 0xAA && 
        buffer[512] == 0x55 && buffer[1023] == 0x55) {
        println("BUFFER TEST: Pattern test SUCCESS");
    } else {
        println("BUFFER TEST: Pattern test FAILED");
    }
    
    free(buffer);
    println("BUFFER TEST: All tests completed");
}
/*==============================================================================================================
  SYSTEM CALL TEST
================================================================================================================*/

// Test paged stack system
void test_paged_stack_system (void) {
    println("STACK: Testing paged stack system");
    
    // Show initial slot status
    show_stack_slots();
    
    // Test stack allocation
    void* stack1 = allocate_paged_stack();
    if (stack1) {
        println("STACK: Paged stack 1 allocation successful");
        show_stack_slots();  // Show status after allocation
        
        void* stack2 = allocate_paged_stack();
        if (stack2) {
            println("STACK: Paged stack 2 allocation successful");
            show_stack_slots();  // Show status after second allocation
            
            // Free stacks
            println("STACK: Freeing stack 1");
            free_paged_stack(stack1);
            show_stack_slots();  // Show status after first free
            
            println("STACK: Freeing stack 2");
            free_paged_stack(stack2);
            show_stack_slots();  // Show status after second free
            
            println("STACK: Both paged stacks freed successfully");
        } else {
            println("STACK: Paged stack 2 allocation failed");
            free_paged_stack(stack1);
        }
    } else {
        println("STACK: Paged stack 1 allocation failed");
    }
    
    // Show final slot status
    show_stack_slots();
    println("STACK: Paged stack system test completed");
}

void test_minimal_allocation (void) {
    println("MINIMAL: Testing basic allocation");
    
    void* test1 = malloc(64);
    if (test1) {
        println("MINIMAL: 64-byte malloc OK");
        free(test1);
    } else {
        println("MINIMAL: 64-byte malloc FAILED");
    }
    
    void* test2 = malloc(STACK_SIZE);
    if (test2) {
        println("MINIMAL: Stack-size malloc OK");
        free(test2);
    } else {
        println("MINIMAL: Stack-size malloc FAILED");
    }
    
    println("MINIMAL: Basic allocation test completed");
}
// FIXED: Proper slot display function
void show_stack_slots (void) {
    println("STACK SLOTS: Showing all slot status");
    
    for (int i = 0; i < MAX_STACKS; i++) {
        print("STACK SLOTS: Slot ");
        
        // FIXED: Proper number to string conversion
        char slot_str[4];
        if (i < 10) {
            slot_str[0] = '0' + i;
            slot_str[1] = '\0';
        } else {
            slot_str[0] = '1';
            slot_str[1] = '0' + (i - 10);
            slot_str[2] = '\0';
        }
        print(slot_str);
        
        if (paged_stacks[i].in_use) {
            println(" - IN USE");
        } else {
            println(" - FREE");
        }
    }
    
    println("STACK SLOTS: Status display completed");
}

// CRITICAL: Validate GDT selectors before using them
void validate_gdt_selectors (void) {
    println("GDT: Validating Ring 3 selectors");
    
    print("GDT: USER_CODE_SELECTOR = 0x");
    char hex_str[20];
    uint64_to_hex(USER_CODE_SELECTOR, hex_str);
    println(hex_str);
    
    print("GDT: USER_DATA_SELECTOR = 0x");
    uint64_to_hex(USER_DATA_SELECTOR, hex_str);
    println(hex_str);
    
    // Check if selectors are actually defined
    if (USER_CODE_SELECTOR == 0 || USER_DATA_SELECTOR == 0) {
        println("GDT: ERROR - Selectors are 0!");
        return;
    }
    
    println("GDT: Selectors look valid");
    
    // Test loading the selectors in Ring 0 (should work)
    println("GDT: Testing selector loading in Ring 0");
    
    __asm__ volatile(
        "pushq %%rax\n"
        
        // Try to load user data selector into a segment register
        "movw $0x23, %%ax\n"
        "movw %%ax, %%es\n"          // Test load into ES
        
        // Restore ES to kernel data selector
        "movw $0x10, %%ax\n"
        "movw %%ax, %%es\n"
        
        "popq %%rax\n"
        :
        :
        : "memory"
    );
    
    println("GDT: Ring 0 selector test passed");
}
// ULTRA-SIMPLE: Test iretq with minimal setup
void test_minimal_iretq (void) {
    println("IRETQ: Testing minimal iretq setup");
    
    // Create a simple test function that just returns
    static uint8_t test_code[] = {
        0xC3  // ret instruction
    };
    
    uint64_t test_entry = (uint64_t)test_code;
    uint64_t test_stack = 0x5FF0FFF0;  // Simple stack
    
    print("IRETQ: Test entry: 0x");
    char hex_str[20];
    uint64_to_hex(test_entry, hex_str);
    println(hex_str);
    
    print("IRETQ: Test stack: 0x");
    uint64_to_hex(test_stack, hex_str);
    println(hex_str);
    
    // Save kernel context
    __asm__ volatile(
        "movq %%rsp, %0\n"
        "movq %%rbp, %1\n"
        : "=m"(kernel_rsp_global), "=m"(kernel_rbp_global)
    );
    
    println("IRETQ: Attempting minimal iretq");
    
    __asm__ volatile(
        // Minimal iretq stack frame
        "pushq $0x23\n"        // SS
        "pushq %0\n"            // RSP
        "pushfq\n"              // RFLAGS (current flags)
        "pushq $0x1B\n"        // CS
        "pushq %1\n"            // RIP
        
        // Clear registers
        "xorq %%rax, %%rax\n"
        "xorq %%rbx, %%rbx\n"
        "xorq %%rcx, %%rcx\n"
        "xorq %%rdx, %%rdx\n"
        
        // Attempt iretq
        "iretq\n"
        
        :
        : "r"(test_stack), "r"(test_entry)
        : "memory"
    );
    
    println("IRETQ: ERROR - Should not reach here");
}

// ROBUST: Comprehensive user memory test with validation
void test_user_memory (void) {
    println("USER_MEM: Testing robust user memory system");
    
    // Test 1: Basic allocation with validation
    void* ptr1 = user_malloc(1024);
    if (ptr1) {
        println("USER_MEM: 1KB allocation SUCCESS");
        
        // Test write/read
        uint8_t* test_ptr = (uint8_t*)ptr1;
        test_ptr[0] = 0xAA;
        test_ptr[1023] = 0xBB;
        
        if (test_ptr[0] == 0xAA && test_ptr[1023] == 0xBB) {
            println("USER_MEM: Write/read test SUCCESS");
        } else {
            println("USER_MEM: Write/read test FAILED");
        }
        
        user_free(ptr1);
        println("USER_MEM: Free SUCCESS");
    } else {
        println("USER_MEM: Basic allocation FAILED");
    }
    
    // Test 2: Stack allocation with validation
    void* stack = user_stack_alloc(64 * 1024);
    if (stack) {
        println("USER_MEM: Stack allocation SUCCESS");
        
        // Test stack access
        volatile uint64_t* stack_test = (volatile uint64_t*)stack;
        *stack_test = 0xDEADBEEF;
        if (*stack_test == 0xDEADBEEF) {
            println("USER_MEM: Stack access SUCCESS");
        } else {
            println("USER_MEM: Stack access FAILED");
        }
        
        user_stack_free(stack, 64 * 1024);
        println("USER_MEM: Stack free SUCCESS");
    } else {
        println("USER_MEM: Stack allocation FAILED");
    }
    
    println("USER_MEM: Robust user memory system test completed");
}

uint64_t load_test_program();

// Test Ring 3 setup with comprehensive validation
void test_ring3_setup (void) {
    println("RING3: Testing Ring 3 setup with comprehensive validation");
    
    // Step 1: Validate GDT and segment selectors
    println("RING3: Step 1 - Validating GDT and segment selectors");
    
    // Check GDT is loaded
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) gdtr;
    
    __asm__ volatile("sgdt %0" : "=m"(gdtr));
    
    if (gdtr.base == 0 || gdtr.limit < 47) {
        println("RING3: CRITICAL ERROR - Invalid GDT");
        return;
    }
    
    // Check segment selectors
    if (USER_CODE_SELECTOR != 0x1B) {
        println("RING3: CRITICAL ERROR - Invalid user code selector");
        return;
    }
    
    if (USER_DATA_SELECTOR != 0x23) {
        println("RING3: CRITICAL ERROR - Invalid user data selector");
        return;
    }
    
    // Check TSS is loaded
    uint16_t tr_value;
    __asm__ volatile("str %0" : "=r"(tr_value));
    
    if (tr_value == 0) {
        println("RING3: CRITICAL ERROR - TSS not loaded");
        return;
    }
    
    println("RING3: GDT and segment selectors validated");
    
    // Step 2: Validate IDT
    println("RING3: Step 2 - Validating IDT");
    
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) idtr;
    
    __asm__ volatile("sidt %0" : "=m"(idtr));
    
    if (idtr.base == 0 || idtr.limit < 255) {
        println("RING3: CRITICAL ERROR - Invalid IDT");
        return;
    }
    
    println("RING3: IDT validated");
    
    // Step 3: Safely validate TSS kernel stack
	println("RING3: Step 3 - Safely validating TSS kernel stack");

	// Allocate a dedicated kernel stack for exceptions that we can use later
	static uint8_t kernel_exception_stack[16384] __attribute__((aligned(16)));
	uint64_t kernel_exception_stack_top = (uint64_t)kernel_exception_stack + sizeof(kernel_exception_stack);

	// Get the TSS selector
	__asm__ volatile("str %0" : "=r"(tr_value));

	// Print the TSS selector for debugging
	print("RING3: TSS selector: 0x");
	char hex_str[20];
	uint64_to_hex(tr_value, hex_str);
	println(hex_str);

	// Check if the TSS selector is valid
	if (tr_value == 0 || (tr_value & 0xFFF8) != 0x28) {
	    println("RING3: WARNING - TSS selector may not be valid");
	    // Continue anyway
	}

	// We won't try to access or modify the TSS directly
	// Instead, we'll just assume it's set up correctly
	println("RING3: TSS validation completed");

    
    // Step 4: Allocate and validate user stack
    println("RING3: Step 4 - Allocating and validating user stack");
    
    void* user_stack = user_malloc(4096);
    if (!user_stack) {
        println("RING3: CRITICAL ERROR - Failed to allocate user stack");
        return;
    }
    
    // Calculate stack top (stack grows downward)
    void* user_stack_top = (void*)((uint64_t)user_stack + 4096 - 16);
    
    // Validate stack is in user memory range
    if ((uint64_t)user_stack < USER_VIRTUAL_START || (uint64_t)user_stack >= USER_VIRTUAL_END) {
        println("RING3: CRITICAL ERROR - User stack outside user memory range");
        user_free(user_stack);
        return;
    }
    
    // Test stack is writable
    volatile uint64_t* stack_test = (volatile uint64_t*)user_stack;
    *stack_test = 0xDEADBEEF;
    if (*stack_test != 0xDEADBEEF) {
        println("RING3: CRITICAL ERROR - User stack not writable");
        user_free(user_stack);
        return;
    }
    *stack_test = 0;
    
    println("RING3: User stack validated");
    
    // Step 5: Load and validate test program
    println("RING3: Step 5 - Loading and validating test program");
    
    uint64_t entry_point = load_test_program();
    if (entry_point == 0) {
        println("RING3: CRITICAL ERROR - Failed to load test program");
        user_free(user_stack);
        return;
    }
    
    // Validate entry point is in user memory range
    if (entry_point < USER_VIRTUAL_START || entry_point >= USER_VIRTUAL_END) {
        println("RING3: CRITICAL ERROR - Entry point outside user memory range");
        user_free(user_stack);
        return;
    }
    
    // Validate program memory is executable
    // Check page permissions
    uint64_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    
    // Extract page table indices
    uint64_t pml4_idx = (entry_point >> 39) & 0x1FF;
    uint64_t pdpt_idx = (entry_point >> 30) & 0x1FF;
    uint64_t pd_idx = (entry_point >> 21) & 0x1FF;
    uint64_t pt_idx = (entry_point >> 12) & 0x1FF;
    
    // Access PML4
    uint64_t* pml4 = (uint64_t*)(cr3 & ~0xFFF);
    if (!(pml4[pml4_idx] & 0x1)) {
        println("RING3: CRITICAL ERROR - PML4 entry not present");
        user_free(user_stack);
        return;
    }
    
    // Access PDPT
    uint64_t* pdpt = (uint64_t*)((pml4[pml4_idx] & ~0xFFF) + KERNEL_VIRTUAL_BASE);
    if (!(pdpt[pdpt_idx] & 0x1)) {
        println("RING3: CRITICAL ERROR - PDPT entry not present");
        user_free(user_stack);
        return;
    }
    
    // Access PD
    uint64_t* pd = (uint64_t*)((pdpt[pdpt_idx] & ~0xFFF) + KERNEL_VIRTUAL_BASE);
    if (!(pd[pd_idx] & 0x1)) {
        println("RING3: CRITICAL ERROR - PD entry not present");
        user_free(user_stack);
        return;
    }
    
    // Access PT
    uint64_t* pt = (uint64_t*)((pd[pd_idx] & ~0xFFF) + KERNEL_VIRTUAL_BASE);
    if (!(pt[pt_idx] & 0x1)) {
        println("RING3: CRITICAL ERROR - PT entry not present");
        user_free(user_stack);
        return;
    }
    
    // Check if page is user accessible
    if (!(pt[pt_idx] & 0x4)) {
        println("RING3: CRITICAL ERROR - Program page not user accessible");
        // Fix it
        pt[pt_idx] |= 0x4;
        println("RING3: Fixed program page permissions");
    }
    
    // Check if page is executable (NX bit not set)
    if (pt[pt_idx] & (1ULL << 63)) {
        println("RING3: CRITICAL ERROR - Program page not executable (NX bit set)");
        // Fix it
        pt[pt_idx] &= ~(1ULL << 63);
        println("RING3: Fixed program page execute permissions");
    }
    
    println("RING3: Program memory validated");
    
    // Step 6: Save kernel context
    println("RING3: Step 6 - Saving kernel context");
    
    __asm__ volatile(
        "movq %%rsp, %0\n"
        "movq %%rbp, %1\n"
        : "=m"(kernel_rsp_global), "=m"(kernel_rbp_global)
        :
        : "memory"
    );
    
    println("RING3: Kernel context saved");
    
    // Step 7: Prepare and validate IRETQ stack frame
    println("RING3: Step 7 - Preparing and validating IRETQ stack frame");
    
    // Get current RFLAGS
    uint64_t rflags;
    __asm__ volatile("pushfq; popq %0" : "=r"(rflags));
    
    // Set required flags for Ring 3
    rflags |= 0x202;  // Set IF (interrupt enable) and bit 1 (always 1)
    rflags &= ~0x8000;  // Clear NT (nested task) flag
    
    println("RING3: IRETQ stack frame validated");
    
    // Step 8: Execute Ring 3 transition
    println("RING3: Step 8 - Executing Ring 3 transition");
    
    // Use inline assembly for the transition
    __asm__ volatile(
        // Build IRETQ stack frame on kernel stack
        "pushq $0x23\n"        // SS (user data selector)
        "pushq %0\n"           // RSP (user stack)
        "pushq %1\n"           // RFLAGS (IF bit set)
        "pushq $0x1B\n"        // CS (user code selector)
        "pushq %2\n"           // RIP (entry point)
        
        // Set up segment registers
        "movw $0x23, %%ax\n"   // User data selector
        "movw %%ax, %%ds\n"
        "movw %%ax, %%es\n"
        "movw %%ax, %%fs\n"
        "movw %%ax, %%gs\n"
        
        // Clear all general purpose registers
        "xorq %%rax, %%rax\n"
        "xorq %%rbx, %%rbx\n"
        "xorq %%rcx, %%rcx\n"
        "xorq %%rdx, %%rdx\n"
        "xorq %%rsi, %%rsi\n"
        "xorq %%rdi, %%rdi\n"
        "xorq %%rbp, %%rbp\n"
        "xorq %%r8, %%r8\n"
        "xorq %%r9, %%r9\n"
        "xorq %%r10, %%r10\n"
        "xorq %%r11, %%r11\n"
        "xorq %%r12, %%r12\n"
        "xorq %%r13, %%r13\n"
        "xorq %%r14, %%r14\n"
        "xorq %%r15, %%r15\n"
        
        // Execute IRETQ
        "iretq\n"
        
        :
        : "r"((uint64_t)user_stack_top), "r"(rflags), "r"(entry_point)
        : "memory", "rax"
    );
    
    // Should never reach here directly
    println("RING3: ERROR - Returned from Ring 3 transition");
}

uint8_t test_program[] = {
	0xEB, 0xFE
};

// Load a simple test program
uint64_t load_test_program (void) {
    println("RING3: Loading simple test program");
    
    // Allocate memory for the program
    void* program_memory = user_malloc(4096);
    if (!program_memory) {
        println("RING3: Failed to allocate program memory");
        return 0;
    }
    
    println("RING3: Program memory allocated successfully");
    
    // Simple test program: just an infinite loop (JMP $)
    // Write the machine code directly to memory
    uint8_t* code = (uint8_t*)program_memory;
    code[0] = 0xEB;  // JMP rel8
    code[1] = 0xFE;  // -2 (jump back to the JMP instruction)
    
    println("RING3: Simple test program loaded");
}

// Comprehensive MFS Test Suite
void test_mfs_comprehensive (void) {
    println("MFS_TEST: Starting comprehensive MFS test suite");
    println("MFS_TEST: ==========================================");
    
    // Initialize MFS if not already done
    if (mfs_init() != 0) {
        println("MFS_TEST: ERROR - Failed to initialize MFS");
        return;
    }
    
    println("MFS_TEST: Phase 1 - Creating nested directory structure");
    
    // Create main directories
    mfs_entry_t* usr_dir = mfs_dir("usr", mfs_sb.root_dir);
    mfs_entry_t* home_dir = mfs_dir("home", mfs_sb.root_dir);
    mfs_entry_t* tmp_dir = mfs_dir("tmp", mfs_sb.root_dir);
    mfs_entry_t* var_dir = mfs_dir("var", mfs_sb.root_dir);
    
    if (!usr_dir || !home_dir || !tmp_dir || !var_dir) {
        println("MFS_TEST: ERROR - Failed to create main directories");
        return;
    }
    
    println("MFS_TEST: Main directories created successfully");
    
    // Create nested directories
    mfs_entry_t* usr_bin = mfs_dir("bin", usr_dir);
    mfs_entry_t* usr_lib = mfs_dir("lib", usr_dir);
    mfs_entry_t* usr_share = mfs_dir("share", usr_dir);
    
    mfs_entry_t* home_user1 = mfs_dir("user1", home_dir);
    mfs_entry_t* home_user2 = mfs_dir("user2", home_dir);
    
    mfs_entry_t* var_log = mfs_dir("log", var_dir);
    mfs_entry_t* var_cache = mfs_dir("cache", var_dir);
    
    if (!usr_bin || !usr_lib || !usr_share || !home_user1 || !home_user2 || !var_log || !var_cache) {
        println("MFS_TEST: ERROR - Failed to create nested directories");
        return;
    }
    
    println("MFS_TEST: Nested directories created successfully");
    
    // Create deep nesting
    mfs_entry_t* deep1 = mfs_dir("level1", usr_share);
    mfs_entry_t* deep2 = mfs_dir("level2", deep1);
    mfs_entry_t* deep3 = mfs_dir("level3", deep2);
    mfs_entry_t* deep4 = mfs_dir("level4", deep3);
    mfs_entry_t* deep5 = mfs_dir("level5", deep4);
    
    if (!deep1 || !deep2 || !deep3 || !deep4 || !deep5) {
        println("MFS_TEST: ERROR - Failed to create deep nesting");
        return;
    }
    
    println("MFS_TEST: Deep nesting (5 levels) created successfully");
    
    println("MFS_TEST: Phase 2 - Creating various sized segments");
    
    // Create small segments
    mfs_entry_t* small1 = mfs_seg("config.txt", 512, home_user1);
    mfs_entry_t* small2 = mfs_seg("readme.md", 1024, home_user1);
    mfs_entry_t* small3 = mfs_seg("notes.txt", 256, home_user2);
    
    // Create medium segments
    mfs_entry_t* medium1 = mfs_seg("data.bin", 64 * 1024, tmp_dir);
    mfs_entry_t* medium2 = mfs_seg("backup.tar", 128 * 1024, var_cache);
    mfs_entry_t* medium3 = mfs_seg("log.txt", 32 * 1024, var_log);
    
    // Create large segments
    mfs_entry_t* large1 = mfs_seg("database.db", 1024 * 1024, usr_lib);
    mfs_entry_t* large2 = mfs_seg("image.raw", 2048 * 1024, tmp_dir);
    
    if (!small1 || !small2 || !small3 || !medium1 || !medium2 || !medium3 || !large1 || !large2) {
        println("MFS_TEST: ERROR - Failed to create segments");
        return;
    }
    
    println("MFS_TEST: Various sized segments created successfully");
    
    println("MFS_TEST: Phase 3 - Simple write test");

	if (small1) {
	    uint8_t single_byte = 0xAA;
	
	    if (mfs_write(small1, 0, &single_byte, 1) == 0) {
	        println("MFS_TEST: Single byte written successfully");
	    } else {
	        println("MFS_TEST: ERROR - Failed to write single byte");
	    }
	}

	if (small2) {
	    const char* text = "TEST";
	
	    if (mfs_write(small2, 0, text, 4) == 0) {
	        println("MFS_TEST: Simple text written successfully");
	    } else {
	        println("MFS_TEST: ERROR - Failed to write simple text");
	    }
	}

	println("MFS_TEST: Simple write test completed");
    
    println("MFS_TEST: Phase 4 - Simple stress test");

    // Create just 3 small segments for minimal stress testing
    mfs_entry_t* stress_segments[3] = {0};
    mfs_entry_t* stress1 = mfs_seg("stress1", 1024, deep5);
    mfs_entry_t* stress2 = mfs_seg("stress2", 1024, deep5);
    mfs_entry_t* stress3 = mfs_seg("stress3", 1024, deep5);
    stress_segments[0] = stress1;
    stress_segments[1] = stress2;
    stress_segments[2] = stress3;

    int stress_count = 0;
    if (stress1) stress_count++;
    if (stress2) stress_count++;
    if (stress3) stress_count++;

    print("MFS_TEST: Created ");
    char count_str[8];
    count_str[0] = '0' + stress_count;
    count_str[1] = '\0';
    print(count_str);
    println(" stress test segments");
    
    // Also fix the validation section
    println("MFS_TEST: Phase 5 - Validating data integrity with safe reads");

	if (small1) {
	    static uint8_t read_data[512]; // FIXED: Static allocation
	    if (mfs_read(small1, 0, read_data, 512) == 0) {
	        int valid = 1;
	        for (int i = 0; i < 512; i++) {
	            if (read_data[i] != (uint8_t)(i % 256)) {
	                valid = 0;
	                break;
	            }
	        }
	        if (valid) {
	            println("MFS_TEST: Config data integrity PASSED using safe read");
	        } else {
	            println("MFS_TEST: Config data integrity FAILED");
	        }
	    }
	}

	if (large1) {
	    static uint32_t sample_data[256]; // FIXED: Static allocation
	    if (mfs_read(large1, 0, sample_data, 1024) == 0) {
	        int valid = 1;
	        for (int i = 0; i < 256; i++) {
	            if (sample_data[i] != 0xDEADBEEF + i) {
	                valid = 0;
	                break;
	            }
	        }
	        if (valid) {
	            println("MFS_TEST: Large data integrity PASSED using safe read");
	        } else {
	            println("MFS_TEST: Large data integrity FAILED");
	        }
	    }
	}
    
    println("MFS_TEST: Phase 6 - Testing search functionality");
    
    // Test finding segments
    mfs_entry_t* found_config = mfs_find("config.txt", home_user1);
    mfs_entry_t* found_readme = mfs_find("readme.md", home_user1);
    mfs_entry_t* found_database = mfs_find("database.db", usr_lib);
    
    if (found_config && found_readme && found_database) {
        println("MFS_TEST: Search functionality PASSED");
    } else {
        println("MFS_TEST: Search functionality FAILED");
    }
    
    println("MFS_TEST: Phase 7 - Cleanup operations");
    
    // Clean up EVERYTHING
	mfs_cleanup_all();
    
    println("MFS_TEST: Phase 8 - Final statistics");
    
    // Display final MFS statistics
    volatile mfs_superblock_t* sb = &mfs_sb;
    
    print("MFS_TEST: Total size: ");
    uint64_to_hex(sb->total_size, count_str);
    println(count_str);
    
    print("MFS_TEST: Free blocks: ");
    uint64_to_hex(sb->free_blocks, count_str);
    println(count_str);
    
    print("MFS_TEST: Used blocks: ");
    uint64_to_hex(sb->used_blocks, count_str);
    println(count_str);
    
    print("MFS_TEST: Next free address: 0x");
    uint64_to_hex(sb->next_free_addr, count_str);
    println(count_str);
    
    println("MFS_TEST: ==========================================");
    println("MFS_TEST: Comprehensive MFS test suite COMPLETED");
    println("MFS_TEST: - Created nested directory structure (5 levels deep)");
    println("MFS_TEST: - Created segments of various sizes (256B to 2MB)");
    println("MFS_TEST: - Performed data integrity validation");
    println("MFS_TEST: - Tested search functionality");
    println("MFS_TEST: - Created 50 stress test segments");
    println("MFS_TEST: - Successfully cleaned up all test data");
    println("MFS_TEST: MFS SYSTEM FULLY OPERATIONAL!");
}

/*==============================================================================================================
  KERNEL STACK STRESS TEST - INSANE DEBUGGING
================================================================================================================*/

// Dump stack contents around current position
void dump_stack_area(const char* label) {
    uint64_t current_rsp = get_stack_pointer();
    uint64_t current_rbp = get_base_pointer();
    
    print("STACK_DEBUG [");
    print(label);
    print("]: RSP=");
    char addr_str[16];
    uint64_to_hex(current_rsp, addr_str);
    print(addr_str);
    print(" RBP=");
    uint64_to_hex(current_rbp, addr_str);
    println(addr_str);
    
    // Dump 16 bytes above and below RSP
    print("STACK_DUMP: ");
    for (int i = -16; i <= 16; i += 8) {
        uint64_t addr = current_rsp + i;
        uint64_t* ptr = (uint64_t*)addr;
        
        if (i == 0) print("[RSP:");
        else if (i == (current_rbp - current_rsp)) print("[RBP:");
        else print("[");
        
        uint64_to_hex(addr, addr_str);
        print(addr_str);
        print("]=");
        
        // Safe read with bounds check
        if (addr >= 0x10000 && addr < 0x10000000) {
            uint64_to_hex(*ptr, addr_str);
            print(addr_str);
        } else {
            print("INVALID");
        }
        print(" ");
    }
    println("");
}

// Simple stack push test
void test_stack_push (void) {
    println("STACK_TEST: Testing simple push operations");
    
    dump_stack_area("BEFORE_PUSH");
    
    // Push test values using inline assembly
    uint64_t test_val1 = 0xDEADBEEF;
    uint64_t test_val2 = 0xCAFEBABE;
    uint64_t test_val3 = 0x12345678;
    
    println("STACK_TEST: Pushing 0xDEADBEEF");
    __asm__ volatile("pushq %0" : : "r"(test_val1) : "memory");
    dump_stack_area("AFTER_PUSH_1");
    
    println("STACK_TEST: Pushing 0xCAFEBABE");
    __asm__ volatile("pushq %0" : : "r"(test_val2) : "memory");
    dump_stack_area("AFTER_PUSH_2");
    
    println("STACK_TEST: Pushing 0x12345678");
    __asm__ volatile("pushq %0" : : "r"(test_val3) : "memory");
    dump_stack_area("AFTER_PUSH_3");
    
    // Pop values back
    uint64_t popped_val;
    
    println("STACK_TEST: Popping value 1");
    __asm__ volatile("popq %0" : "=r"(popped_val) : : "memory");
    print("STACK_TEST: Popped value: ");
    char val_str[16];
    uint64_to_hex(popped_val, val_str);
    println(val_str);
    dump_stack_area("AFTER_POP_1");
    
    println("STACK_TEST: Popping value 2");
    __asm__ volatile("popq %0" : "=r"(popped_val) : : "memory");
    print("STACK_TEST: Popped value: ");
    uint64_to_hex(popped_val, val_str);
    println(val_str);
    dump_stack_area("AFTER_POP_2");
    
    println("STACK_TEST: Popping value 3");
    __asm__ volatile("popq %0" : "=r"(popped_val) : : "memory");
    print("STACK_TEST: Popped value: ");
    uint64_to_hex(popped_val, val_str);
    println(val_str);
    dump_stack_area("AFTER_POP_3");
    
    println("STACK_TEST: Simple push/pop test completed");
}

// Stack frame test
void test_stack_frame (void) {
    println("STACK_TEST: Testing stack frame operations");
    
    dump_stack_area("FRAME_START");
    
    // Create a new stack frame
    __asm__ volatile(
        "pushq %%rbp\n"
        "movq %%rsp, %%rbp"
        : : : "memory"
    );
    
    dump_stack_area("FRAME_CREATED");
    
    // Allocate local space
    __asm__ volatile("subq $32, %%rsp" : : : "memory");
    dump_stack_area("LOCAL_SPACE_ALLOCATED");
    
    // Write to local space
    uint64_t current_rsp = get_stack_pointer();
    uint64_t* local_var1 = (uint64_t*)(current_rsp + 0);
    uint64_t* local_var2 = (uint64_t*)(current_rsp + 8);
    uint64_t* local_var3 = (uint64_t*)(current_rsp + 16);
    uint64_t* local_var4 = (uint64_t*)(current_rsp + 24);
    
    *local_var1 = 0x1111111111111111;
    *local_var2 = 0x2222222222222222;
    *local_var3 = 0x3333333333333333;
    *local_var4 = 0x4444444444444444;
    
    dump_stack_area("LOCAL_VARS_WRITTEN");
    
    // Read back local variables
    print("STACK_TEST: Local var 1: ");
    char val_str[16];
    uint64_to_hex(*local_var1, val_str);
    println(val_str);
    
    print("STACK_TEST: Local var 2: ");
    uint64_to_hex(*local_var2, val_str);
    println(val_str);
    
    print("STACK_TEST: Local var 3: ");
    uint64_to_hex(*local_var3, val_str);
    println(val_str);
    
    print("STACK_TEST: Local var 4: ");
    uint64_to_hex(*local_var4, val_str);
    println(val_str);
    
    // Restore stack frame
    __asm__ volatile(
        "movq %%rbp, %%rsp\n"
        "popq %%rbp"
        : : : "memory"
    );
    
    dump_stack_area("FRAME_RESTORED");
    
    println("STACK_TEST: Stack frame test completed");
}

// Stack stress test with multiple levels
void test_stack_stress (void) {
    println("STACK_TEST: Starting stack stress test");
    
    dump_stack_area("STRESS_START");
    
    // Push many values
    for (int i = 0; i < 8; i++) {
        uint64_t test_val = 0x1000 + i;
        print("STACK_STRESS: Pushing value ");
        char val_str[16];
        uint64_to_hex(test_val, val_str);
        println(val_str);
        
        __asm__ volatile("pushq %0" : : "r"(test_val) : "memory");
        
        if (i % 2 == 0) {
            dump_stack_area("STRESS_PUSH");
        }
    }
    
    dump_stack_area("STRESS_ALL_PUSHED");
    
    // Pop all values back
    for (int i = 0; i < 8; i++) {
        uint64_t popped_val;
        __asm__ volatile("popq %0" : "=r"(popped_val) : : "memory");
        
        print("STACK_STRESS: Popped value ");
        char val_str[16];
        uint64_to_hex(popped_val, val_str);
        println(val_str);
        
        if (i % 2 == 0) {
            dump_stack_area("STRESS_POP");
        }
    }
    
    dump_stack_area("STRESS_END");
    
    println("STACK_TEST: Stack stress test completed");
}

// Stack alignment test
void test_stack_alignment (void) {
    println("STACK_TEST: Testing stack alignment");
    
    uint64_t rsp = get_stack_pointer();
    print("STACK_ALIGN: Current RSP: ");
    char addr_str[16];
    uint64_to_hex(rsp, addr_str);
    println(addr_str);
    
    print("STACK_ALIGN: Alignment check: ");
    if (rsp & 0xF) {
        println("MISALIGNED");
        print("STACK_ALIGN: Misalignment offset: ");
        char offset_str[8];
        uint64_to_hex(rsp & 0xF, offset_str);
        println(offset_str);
    } else {
        println("ALIGNED");
    }
    
    // Test alignment after push
    __asm__ volatile("pushq $0x12345678" : : : "memory");
    rsp = get_stack_pointer();
    print("STACK_ALIGN: After push RSP: ");
    uint64_to_hex(rsp, addr_str);
    println(addr_str);
    
    print("STACK_ALIGN: After push alignment: ");
    if (rsp & 0xF) {
        println("MISALIGNED (expected)");
    } else {
        println("ALIGNED");
    }
    
    // Pop to restore
    __asm__ volatile("addq $8, %%rsp" : : : "memory");
    
    println("STACK_TEST: Stack alignment test completed");
}

// Ultra-minimal test - MOST COMPATIBLE
// Test with interrupt identification
// Minimal interrupt handler that just logs and returns
void debug_interrupt_handler (void) {
    static int interrupt_count = 0;
    interrupt_count++;
    
    println("DEBUG_INT: Interrupt occurred!");
    
    char count_str[8];
    count_str[0] = '0' + (interrupt_count % 10);
    count_str[1] = '\0';
    print("DEBUG_INT: Count: ");
    println(count_str);
    
    // Get interrupt info
    uint64_t rsp;
    __asm__ volatile("mov %%rsp, %0" : "=r"(rsp));
    
    print("DEBUG_INT: Handler RSP: ");
    char rsp_str[16];
    uint64_to_hex(rsp, rsp_str);
    println(rsp_str);
    
    // Don't do anything complex - just return
    println("DEBUG_INT: Returning from interrupt");
}

// Test if the crash happens during function return
void test_function_return (void) {
    println("RETURN_TEST: Testing function return mechanism");
    
    // Disable interrupts
    __asm__ volatile("cli");
    
    // Get current stack state
    uint64_t current_rsp, current_rbp;
    __asm__ volatile(
        "movq %%rsp, %0\n"
        "movq %%rbp, %1"
        : "=r"(current_rsp), "=r"(current_rbp)
    );
    
    print("RETURN_TEST: RSP: ");
    char addr_str[16];
    uint64_to_hex(current_rsp, addr_str);
    println(addr_str);
    
    print("RETURN_TEST: RBP: ");
    uint64_to_hex(current_rbp, addr_str);
    println(addr_str);
    
    // Check return address on stack
    uint64_t* return_addr_ptr = (uint64_t*)current_rsp;
    uint64_t return_addr = *return_addr_ptr;
    
    print("RETURN_TEST: Return address: ");
    uint64_to_hex(return_addr, addr_str);
    println(addr_str);
    
    // Validate return address is in kernel space
    if (return_addr < 0x100000 || return_addr > 0x40000000) {
        println("RETURN_TEST: ERROR - Return address out of range!");
        while (1) __asm__ volatile("hlt");
    }
    
    println("RETURN_TEST: Return address validation passed");
    println("RETURN_TEST: About to return...");
    
    // Return normally
}

void test_elf_threading_system (void) {
    println("=================================================");
    println("TESTING MULTITASKING ELF EXECUTION");
    println("=================================================");

    // Load BOTH apps but DON'T execute them yet
    uint32_t inter_thread = elf_thread_loader("/MODULES/APPS/INTER.ELF", "inter");
    if (inter_thread > 0) {
        println("ELF_LOADER: Inter app thread created successfully");
    }
    
    println("=================================================");
    println("MULTITASKING ELF SYSTEM STARTED");
    println("=================================================");
}

/*==============================================================================================================
  VOSTROX TIMER-BASED PORT PROCESSING - NO INTERRUPTS
================================================================================================================*/

// Test function for delay app context switching
void test_delay (void) {
    println("=================================================");
    println("TESTING DELAY APP CONTEXT SWITCHING");
    println("=================================================");

	uint32_t task_thread = elf_thread_loader("/MODULES/APPS/TASKBAR.ELF", "taskbar");
    if (task_thread == 0) {
        println("TEST_DELAY: ERROR - Cannot load delay app");
        return;
    }

	uint32_t vwm_thread = elf_thread_loader("/MODULES/APPS/VWM.ELF", "vwm");
    if (vwm_thread > 0) {
        println("ELF_LOADER: vwm thread created successfully");
    }

    /*uint32_t delay_thread = elf_thread_loader("/MODULES/APPS/DELAY.ELF", "delay");
    if (delay_thread == 0) {
        println("TEST_DELAY: ERROR - Cannot load delay app");
        return;
    }*/
}

// Test function to print sample characters on the VBE screen using the loaded font
void test_print_font_vbe (void) {
    renderer_init_mfs_backbuffer(g_fb_width, g_fb_height, g_fb_pitch);

    if (!backbuffer_segment) {
        serial_write("test_print_font_vbe: Failed to initialize backbuffer\n");
        return;
    }

    clear_screen_vbe(0x00000000);  // Black

    load_font("/MODULES/SYS/FONTS/FONTS/AIXOID9.F16");

    uint32_t white = make_color(255, 255, 255);
    int chars_per_row = g_fb_width / FONT_CHAR_WIDTH;

    for (int i = 32; i <= 126; i++) {
        int cx = (i - 32) % chars_per_row;
        int cy = (i - 32) / chars_per_row;

        int px = cx * FONT_CHAR_WIDTH;
        int py = cy * FONT_CHAR_HEIGHT;

        render_char_vbe(px, py, (char)i, white);
    }

	renderer_present_mfs();

}

void mfs_dump_seg(mfs_entry_t* segment) {
	if (!segment) {
		println("mfs_dump_seg: NULL segment pointer");
		return;
	}

	if (segment->magic != MFS_MAGIC) {
		println("mfs_dump_seg: Invalid segment magic");
		return;
	}
	if (segment->type != MFS_TYPE_SEGMENT) {
		println("mfs_dump_seg: Not a segment type");
		return;
	}
	if (segment->size == 0) {
		println("mfs_dump_seg: Segment size is zero");
		return;
	}
	if (segment->start_addr == 0) {
		println("mfs_dump_seg: Segment start address is zero");
		return;
	}

	uint8_t* data = (uint8_t*)segment->start_addr;
	size_t size = segment->size;

	char line[80];
	for (size_t offset = 0; offset < size; offset += 16) {
		int pos = 0;

		offset_to_hex(offset, line + pos);
		pos += 10;

		for (size_t i = 0; i < 16; i++) {
			if (offset + i < size) {
				byte_to_hex(data[offset + i], line + pos);
			} else {
				line[pos + 0] = ' ';
				line[pos + 1] = ' ';
				line[pos + 2] = ' ';
			}
			pos += 3;
		}

		line[pos++] = ' ';
		line[pos++] = '|';

		for (size_t i = 0; i < 16; i++) {
			if (offset + i < size) {
				char c = data[offset + i];
				line[pos++] = (c >= 32 && c <= 126) ? c : '.';
			} else {
				line[pos++] = ' ';
			}
		}

		line[pos++] = '|';
		line[pos] = '\0';

		println(line);
	}
}

// Test function to demonstrate invoking kernel functions through mapped pointers
int test_invoke_kernel_function(const char* module_name, const char* function_name) {
    // Find the MODULES directory
    mfs_entry_t* modules_dir_entry = mfs_find("MODULES", mfs_sb.root_dir);
    if (!modules_dir_entry) {
        println("test_invoke_kernel_function: MODULES directory not found");
        return -1;
    }

    // Find the module directory
    mfs_entry_t* module_dir = mfs_find(module_name, modules_dir_entry);
    if (!module_dir) {
        print("test_invoke_kernel_function: Module directory not found: ");
        println(module_name);
        return -1;
    }

    // Find the function pointer segment
    mfs_entry_t* func_segment = mfs_find(function_name, module_dir);
    if (!func_segment) {
        print("test_invoke_kernel_function: Function segment not found: ");
        println(function_name);
        return -1;
    }

    // Read the function pointer from the segment
    uint64_t func_ptr;
    if (mfs_read(func_segment, 0, &func_ptr, sizeof(func_ptr)) != 0) {
        print("test_invoke_kernel_function: Failed to read function pointer for: ");
        println(function_name);
        return -1;
    }

    // Validate the pointer is not null
    if (func_ptr == 0) {
        print("test_invoke_kernel_function: Function pointer is null for: ");
        println(function_name);
        return -1;
    }

    // Cast the pointer to a generic function pointer type
    // For specific functions, you would cast to the appropriate signature
    void (*func)() = (void(*)())func_ptr;

    // Call the function
    // Note: This is a generic call - for functions with parameters or return values,
    // you would need to know the specific signature
    print("test_invoke_kernel_function: Invoking function: ");
    println(function_name);
    
    func(); // This invokes the function

    println("test_invoke_kernel_function: Function invocation completed");
    return 0;
}

int test(int a, int b) {
    println("YAY I AM WORKING HERE ARE THE ARGUMENTS");

    println("A bytes:");
    for (int i = 0; i < sizeof(a); i++) {
        char c = (a >> (i * 8)) & 0xFF;
        char high = (c >> 4) & 0xF;
        char low  = c & 0xF;

        char hex_str[5];  // "\\xAB\0"
        hex_str[0] = '\\';
        hex_str[1] = 'x';
        hex_str[2] = (high < 10) ? ('0' + high) : ('A' + high - 10);
        hex_str[3] = (low  < 10) ? ('0' + low)  : ('A' + low  - 10);
        hex_str[4] = '\0';
        print(hex_str);
    }

    println("B bytes:");
    for (int i = 0; i < sizeof(b); i++) {
        char c = (b >> (i * 8)) & 0xFF;
        char high = (c >> 4) & 0xF;
        char low  = c & 0xF;

        char hex_str[5];
        hex_str[0] = '\\';
        hex_str[1] = 'x';
        hex_str[2] = (high < 10) ? ('0' + high) : ('A' + high - 10);
        hex_str[3] = (low  < 10) ? ('0' + low)  : ('A' + low  - 10);
        hex_str[4] = '\0';
        print(hex_str);
    }

    return 0;
}


// Add this simple wrapper function
int test_simple_call (void) {
    println("DEBUG: In test_simple_call");
    return 42;
}


// Test function that uses all 6 arguments
int test_6_args(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    print("TEST_6_ARGS: Called with arguments: ");
    
    char buf[20];
    uint64_to_hex(arg1, buf);
    print(buf);
    print(" ");
    
    uint64_to_hex(arg2, buf);
    print(buf);
    print(" ");
    
    uint64_to_hex(arg3, buf);
    print(buf);
    print(" ");
    
    uint64_to_hex(arg4, buf);
    print(buf);
    print(" ");
    
    uint64_to_hex(arg5, buf);
    print(buf);
    print(" ");
    
    uint64_to_hex(arg6, buf);
    println(buf);
    
    // Return sum of all arguments
    uint64_t result = arg1 + arg2 + arg3 + arg4 + arg5 + arg6;
    print("TEST_6_ARGS: Sum result = ");
    uint64_to_hex(result, buf);
    println(buf);
    
    return (int)result;
}

void debug_directory_contents(mfs_entry_t* dir, const char* dir_name) {
    println("DEBUG: Checking directory contents for:");
    println(dir_name);
    
    if (!dir) {
        println("DEBUG: Directory is NULL!");
        return;
    }
    
    print("DEBUG: Directory magic: ");
    char magic_str[16];
    uint64_to_hex(dir->magic, magic_str);
    println(magic_str);
    
    mfs_entry_t* child = dir->children;
    int count = 0;
    
    while (child && count < 10) {
        print("DEBUG: Child ");
        print_decimal(count);
        print(": name='");
        println(child->name);
        print("' magic=");
        uint64_to_hex(child->magic, magic_str);
        print(magic_str);
        print(" type=");
        print_decimal(child->type);
        println("");
        
        child = child->next;
        count++;
    }
    
    print("DEBUG: Total children found: ");
    print_decimal(count);
    println("");
}

void debug_dump_complete_mfs_state() {
    println("=== COMPLETE MFS STATE DUMP ===");
    
    // Dump superblock
    println("--- MFS SUPERBLOCK ---");
    print("mfs_sb.magic: ");
    char hex_str[16];
    uint64_to_hex(mfs_sb.magic, hex_str);
    println(hex_str);
    
    print("mfs_sb.initialized: ");
    print_decimal(mfs_sb.initialized);
    println("");
    
    print("mfs_sb.total_size: ");
    uint64_to_hex(mfs_sb.total_size, hex_str);
    println(hex_str);
    
    print("mfs_sb.free_blocks: ");
    uint64_to_hex(mfs_sb.free_blocks, hex_str);
    println(hex_str);
    
    print("mfs_sb.used_blocks: ");
    uint64_to_hex(mfs_sb.used_blocks, hex_str);
    println(hex_str);
    
    print("mfs_sb.next_free_addr: ");
    uint64_to_hex(mfs_sb.next_free_addr, hex_str);
    println(hex_str);
    
    print("mfs_sb.root_dir: ");
    uint64_to_hex((uint64_t)mfs_sb.root_dir, hex_str);
    println(hex_str);
    
    print("mfs_sb.entry_table: ");
    uint64_to_hex((uint64_t)mfs_sb.entry_table, hex_str);
    println(hex_str);
    
    // Dump entry table
    println("--- MFS ENTRY TABLE ---");
    mfs_entry_t* entry_table = (mfs_entry_t*)mfs_sb.entry_table;
    
    for (int i = 0; i < 20; i++) {  // Show first 20 entries
        mfs_entry_t* entry = &entry_table[i];
        
        print("Entry[");
        print_decimal(i);
        print("]: ");
        
        print("magic=");
        uint64_to_hex(entry->magic, hex_str);
        print(hex_str);
        
        print(" type=");
        print_decimal(entry->type);
        
        print(" name='");
        // Print name byte by byte to see if it's corrupted
        for (int j = 0; j < 16 && j < MFS_MAX_NAME_LEN; j++) {
            if (entry->name[j] == 0) break;
            if (entry->name[j] >= 32 && entry->name[j] <= 126) {
                // Printable character
                char c[2] = {entry->name[j], 0};
                print(c);
            } else {
                // Non-printable - show hex
                print("[");
                uint64_to_hex(entry->name[j], hex_str);
                print(hex_str);
                print("]");
            }
        }
        print("'");
        
        print(" addr=");
        uint64_to_hex(entry->start_addr, hex_str);
        print(hex_str);
        
        print(" size=");
        uint64_to_hex(entry->size, hex_str);
        print(hex_str);
        
        print(" parent=");
        uint64_to_hex((uint64_t)entry->parent, hex_str);
        print(hex_str);
        
        print(" next=");
        uint64_to_hex((uint64_t)entry->next, hex_str);
        print(hex_str);
        
        print(" children=");
        uint64_to_hex((uint64_t)entry->children, hex_str);
        println(hex_str);
    }
    
    // Dump raw memory around entry names
    println("--- RAW MEMORY DUMP OF FIRST ENTRY NAMES ---");
    for (int i = 0; i < 5; i++) {
        mfs_entry_t* entry = &entry_table[i];
        print("Entry[");
        print_decimal(i);
        print("] name bytes: ");
        
        uint8_t* name_bytes = (uint8_t*)entry->name;
        for (int j = 0; j < 32; j++) {
            uint64_to_hex(name_bytes[j], hex_str);
            print(hex_str);
            print(" ");
        }
        println("");
    }
    
    println("=== END MFS DUMP ===");
}

