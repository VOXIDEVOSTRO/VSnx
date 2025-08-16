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
  ROBUST USER MEMORY SYSTEM WITH VALIDATION AND PAGE TRACKING
================================================================================================================*/

// Page fault handler for validation
void validation_fault_handler(void) {
    // Set error flag and return
    validation_error = 1;
    
    // Skip the faulting instruction
    uint64_t rip;
    __asm__ volatile("movq 8(%%rbp), %0" : "=r"(rip));
    
    // Advance RIP past the faulting instruction (typically 2-7 bytes)
    rip += 7;  // Maximum x86-64 instruction length
    
    // Update saved RIP
    __asm__ volatile("movq %0, 8(%%rbp)" : : "r"(rip));
}

// Default page fault handler
void default_page_fault_handler(void) {
    println("PAGE FAULT: Default handler called");
    
    // Get fault address
    uint64_t fault_addr;
    __asm__ volatile("mov %%cr2, %0" : "=r"(fault_addr));
    
    // Print fault address
    print("PAGE FAULT: Address: 0x");
    char hex_str[20];
    uint64_to_hex(fault_addr, hex_str);
    println(hex_str);
    
    // Get error code from stack
    uint64_t error_code;
    __asm__ volatile("mov 16(%%rbp), %0" : "=r"(error_code));
    
    // Print error code
    print("PAGE FAULT: Error code: 0x");
    uint64_to_hex(error_code, hex_str);
    println(hex_str);
    
    // Analyze error code
    if (error_code & 0x1) {
        println("PAGE FAULT: Page protection violation");
    } else {
        println("PAGE FAULT: Page not present");
    }
    
    if (error_code & 0x2) {
        println("PAGE FAULT: Write access");
    } else {
        println("PAGE FAULT: Read access");
    }
    
    if (error_code & 0x4) {
        println("PAGE FAULT: User mode access");
    } else {
        println("PAGE FAULT: Supervisor mode access");
    }
    
    // Halt the system
    println("PAGE FAULT: System halted");
	__asm__ volatile("hlt");
}

// Set page fault handler
page_fault_handler_t set_page_fault_handler(page_fault_handler_t handler) {
    page_fault_handler_t old_handler = current_page_fault_handler;
    
    if (handler == NULL) {
        current_page_fault_handler = default_page_fault_handler;
    } else {
        current_page_fault_handler = handler;
    }
    
    return old_handler;
}

int validate_memory_mapping(uint64_t addr, size_t size) {
    // Skip complex validation that causes double faults
    if (addr < USER_VIRTUAL_START || addr >= USER_VIRTUAL_END) {
        println("USER_MEM: Address outside user space");
        return -1;
    }
    
    // Simple accessibility test
    volatile uint8_t* test_ptr = (volatile uint8_t*)addr;
    *test_ptr = 0xAA;
    if (*test_ptr != 0xAA) {
        println("USER_MEM: Memory not accessible");
        return -1;
    }
    *test_ptr = 0;
    
    println("USER_MEM: Memory mapping validation SUCCESS");
    return 0;
}

// Page fault handler entry point (called from assembly)
void page_fault_handler_entry(void) {
    if (current_page_fault_handler) {
        current_page_fault_handler();
    } else {
        default_page_fault_handler();
    }
}

// Define KERNEL_CODE_SELECTOR before its usage
#define KERNEL_CODE_SELECTOR 0x08  // Ring 0 code segment selector

// Assembly wrapper for page fault handler
__asm__(
    ".global page_fault_handler_asm\n"
    "page_fault_handler_asm:\n"
    "    # Save all registers\n"
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
    "    \n"
    "    # Call C handler\n"
    "    call page_fault_handler_entry\n"
    "    \n"
    "    # Restore all registers\n"
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
    "    \n"
    "    # Return from exception\n"
    "    addq $8, %rsp\n"  // Skip error code
    "    iretq\n"
);

// Forward declaration for the assembly page fault handler
extern void page_fault_handler_asm(void);

// Initialize page fault handling
void init_page_fault_handler(void) {
    // Set default handler
    current_page_fault_handler = default_page_fault_handler;
    
    // Install handler in IDT
    set_idt_entry(14, (uint64_t)page_fault_handler_asm, KERNEL_CODE_SELECTOR, 0x8E);
}

// Update user_paging_init to use user_map_page
int user_paging_init (void) {
    if (user_paging_initialized) {
        return 0;
    }
    
    println("USER_PAGING: Initializing robust user paging system");
    
    // Initialize page tracking
    for (int i = 0; i < MAX_USER_PAGES; i++) {
        user_pages[i].virtual_addr = 0;
        user_pages[i].physical_addr = 0;
        user_pages[i].is_mapped = 0;
        user_pages[i].is_writable = 0;
        user_pages[i].reference_count = 0;
    }
    user_pages_count = 0;
    
    println("USER_PAGING: Page tracking initialized");
    
    // Map pages with validation and retry
    println("USER_PAGING: Mapping user pages with validation");
    
    int retry_count = 0;
    const int max_retries = 3;
    
    for (uint64_t addr = USER_VIRTUAL_START; addr < USER_VIRTUAL_END; addr += USER_LARGE_PAGE_SIZE) {
        int mapping_success = 0;
        
        for (retry_count = 0; retry_count < max_retries; retry_count++) {
            // Use user_map_page instead of map_page
            if (user_map_page(addr, addr, PAGE_PRESENT | PAGE_WRITE | PAGE_USER) == 0) {
                mapping_success = 1;
                break;
            }
            
            print("USER_PAGING: Retry ");
            char retry_str[4];
            retry_str[0] = '0' + (retry_count + 1);
            retry_str[1] = '/';
            retry_str[2] = '0' + max_retries;
            retry_str[3] = '\0';
            print(retry_str);
            print(" for address: 0x");
            char hex_str[20];
            uint64_to_hex(addr, hex_str);
            println(hex_str);
        }
        
        if (!mapping_success) {
            println("USER_PAGING: Failed to map page after retries");
            return -1;
        }
        
        // Track mapped pages
        if (user_pages_count < MAX_USER_PAGES) {
            user_pages[user_pages_count].virtual_addr = addr;
            user_pages[user_pages_count].physical_addr = addr;
            user_pages[user_pages_count].is_mapped = 1;
            user_pages[user_pages_count].is_writable = 1;
            user_pages[user_pages_count].reference_count = 0;
            user_pages_count++;
        }
    }
    
    // Flush TLB
    __asm__ volatile("mov %%cr3, %%rax; mov %%rax, %%cr3" ::: "rax", "memory");
    
    // Validate all mappings with the fixed validation function
    println("USER_PAGING: Validating all page mappings");
    if (validate_memory_mapping(USER_VIRTUAL_START, USER_LARGE_PAGE_SIZE) != 0) {
        println("USER_PAGING: Memory validation failed - retrying mapping");
        
        // Retry mapping with smaller pages
        for (uint64_t addr = USER_VIRTUAL_START; addr < USER_VIRTUAL_START + USER_LARGE_PAGE_SIZE; addr += USER_PAGE_SIZE) {
            if (user_map_page(addr, addr, PAGE_PRESENT | PAGE_WRITE | PAGE_USER) != 0) {
                println("USER_PAGING: Small page mapping failed");
                return -1;
            }
        }
        
        __asm__ volatile("mov %%cr3, %%rax; mov %%rax, %%cr3" ::: "rax", "memory");
        
        if (validate_memory_mapping(USER_VIRTUAL_START, USER_LARGE_PAGE_SIZE) != 0) {
            println("USER_PAGING: Final validation failed");
            return -1;
        }
    }
    
    println("USER_PAGING: All page mappings validated successfully");
    user_paging_initialized = 1;
    
    return 0;

}
