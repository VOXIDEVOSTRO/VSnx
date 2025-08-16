#include "include.h"

/*==============================================================================================================
  PAGED STACK SYSTEM - USING OUR RELIABLE PAGING
================================================================================================================*/

// Initialize paged stack system
int init_paged_stack_system (void) {
    if (paged_stack_system_initialized) {
        return 0;
    }
    
    println("STACK: Initializing paged stack system");
    
    // Initialize stack entries
    for (int i = 0; i < MAX_STACKS; i++) {
        paged_stacks[i].stack_ptr = NULL;
        paged_stacks[i].in_use = 0;
    }
    
    paged_stack_system_initialized = 1;
    println("STACK: Paged stack system initialized");
    return 0;
}

void * allocate_paged_stack (void) {
    println("STACK: Starting stack allocation");
    
    if (!paged_stack_system_initialized) {
        println("STACK: System not initialized, initializing now");
        if (init_paged_stack_system() != 0) {
            println("STACK: System initialization FAILED");
            return NULL;
        }
        println("STACK: System initialization SUCCESS");
    }
    
    println("STACK: Looking for free stack slot");
    
    // Find free stack slot
    for (int i = 0; i < MAX_STACKS; i++) {
        if (!paged_stacks[i].in_use) {
            print("STACK: Found free slot ");
            
            // FIXED: Proper number display
            char slot_str[4];
            if (i < 10) {
                slot_str[0] = '0' + i;
                slot_str[1] = '\0';
            } else {
                slot_str[0] = '1';
                slot_str[1] = '0' + (i - 10);
                slot_str[2] = '\0';
            }
            println(slot_str);
            
            // Allocate stack using our reliable malloc
            println("STACK: Attempting malloc");
            void* stack_ptr = malloc(STACK_SIZE);
            if (!stack_ptr) {
                println("STACK: malloc FAILED - heap exhausted");
                return NULL;
            }
            
            println("STACK: malloc SUCCESS");
            
            // Clear the stack
            println("STACK: Clearing stack memory");
            memset(stack_ptr, 0, STACK_SIZE);
            println("STACK: Stack cleared");
            
            // Record allocation
            paged_stacks[i].stack_ptr = stack_ptr;
            paged_stacks[i].in_use = 1;
            
            println("STACK: Stack allocation completed successfully");
            return stack_ptr;
        }
    }
    
    println("STACK: No free stack slots available");
    return NULL;
}

void free_paged_stack(void* stack_ptr) {
    if (!stack_ptr) {
        println("STACK FREE: NULL pointer");
        return;
    }
    
    println("STACK FREE: Attempting to free stack");
    
    // Find the stack entry
    for (int i = 0; i < MAX_STACKS; i++) {
        if (paged_stacks[i].stack_ptr == stack_ptr && paged_stacks[i].in_use) {
            println("STACK FREE: Found matching slot");
            
            // Free using our reliable free
            free(stack_ptr);
            
            paged_stacks[i].stack_ptr = NULL;
            paged_stacks[i].in_use = 0;
            
            println("STACK FREE: Stack freed successfully");
            return;
        }
    }
    
    println("STACK FREE: Stack not found in slots - possible double free");
}

// Enhanced page permission function with comprehensive debugging
void set_page_permissions(uint64_t vaddr, uint64_t flags) {
    println("PAGE_PERM: Starting comprehensive page analysis and permission setting");
    
    // Print the address we're analyzing
    print("PAGE_PERM: Analyzing address: 0x");
    char hex_str[20];
    uint64_to_hex(vaddr, hex_str);
    println(hex_str);
    
    // Check alignment
    if (vaddr & 0xFFF) {
        println("PAGE_PERM: WARNING - Address not 4KB aligned");
    } else {
        println("PAGE_PERM: Address is 4KB aligned");
    }
    
    // Validate the virtual address is in user space
    if (vaddr < USER_VIRTUAL_START || vaddr >= USER_VIRTUAL_END) {
        println("PAGE_PERM: Address outside user space, skipping");
        return;
    }
    
    // Disable interrupts during page table analysis
    uint64_t old_flags;
    __asm__ volatile(
        "pushfq\n"
        "popq %0\n"
        "cli\n"
        : "=r"(old_flags)
        :
        : "memory"
    );
    
    uint64_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    
    print("PAGE_PERM: CR3 register: 0x");
    uint64_to_hex(cr3, hex_str);
    println(hex_str);
    
    // Validate CR3
    uint64_t pml4_phys = cr3 & ~0xFFF;
    if (pml4_phys == 0) {
        println("PAGE_PERM: Invalid CR3, skipping");
        goto restore_interrupts;
    }
    
    print("PAGE_PERM: PML4 physical address: 0x");
    uint64_to_hex(pml4_phys, hex_str);
    println(hex_str);
    
    uint64_t pml4_idx = (vaddr >> 39) & 0x1FF;
    uint64_t pdpt_idx = (vaddr >> 30) & 0x1FF;
    uint64_t pd_idx = (vaddr >> 21) & 0x1FF;
    uint64_t pt_idx = (vaddr >> 12) & 0x1FF;
    
    print("PAGE_PERM: PML4 index: ");
    uint64_to_hex(pml4_idx, hex_str);
    println(hex_str);
    
    print("PAGE_PERM: PDPT index: ");
    uint64_to_hex(pdpt_idx, hex_str);
    println(hex_str);
    
    print("PAGE_PERM: PD index: ");
    uint64_to_hex(pd_idx, hex_str);
    println(hex_str);
    
    print("PAGE_PERM: PT index: ");
    uint64_to_hex(pt_idx, hex_str);
    println(hex_str);
    
    // Access PML4 - use identity mapping assumption
    uint64_t* pml4 = (uint64_t*)pml4_phys;
    
    // Validate PML4 access
    uint64_t pml4_entry;
    __asm__ volatile(
        "movq (%1), %0\n"
        : "=r"(pml4_entry)
        : "r"(&pml4[pml4_idx])
        : "memory"
    );
    
    print("PAGE_PERM: PML4 entry raw value: 0x");
    uint64_to_hex(pml4_entry, hex_str);
    println(hex_str);
    
    // Analyze PML4 entry flags
    println("PAGE_PERM: PML4 entry flags:");
    if (pml4_entry & 0x1) println("  - Present");
    if (pml4_entry & 0x2) println("  - Writable");
    if (pml4_entry & 0x4) println("  - User accessible");
    if (pml4_entry & 0x8) println("  - Write-through");
    if (pml4_entry & 0x10) println("  - Cache disabled");
    if (pml4_entry & 0x20) println("  - Accessed");
    if (pml4_entry & 0x80) println("  - PS bit set (1GB page)");
    if (pml4_entry & (1ULL << 63)) println("  - NX bit set");
    
    if (!(pml4_entry & 0x1)) {
        println("PAGE_PERM: PML4 entry not present, skipping");
        goto restore_interrupts;
    }
    
    // Access PDPT
    uint64_t pdpt_phys = pml4_entry & ~0xFFF;
    print("PAGE_PERM: PDPT physical address: 0x");
    uint64_to_hex(pdpt_phys, hex_str);
    println(hex_str);
    
    uint64_t* pdpt = (uint64_t*)pdpt_phys;
    
    uint64_t pdpt_entry;
    __asm__ volatile(
        "movq (%1), %0\n"
        : "=r"(pdpt_entry)
        : "r"(&pdpt[pdpt_idx])
        : "memory"
    );
    
    print("PAGE_PERM: PDPT entry raw value: 0x");
    uint64_to_hex(pdpt_entry, hex_str);
    println(hex_str);
    
    // Analyze PDPT entry flags
    println("PAGE_PERM: PDPT entry flags:");
    if (pdpt_entry & 0x1) println("  - Present");
    if (pdpt_entry & 0x2) println("  - Writable");
    if (pdpt_entry & 0x4) println("  - User accessible");
    if (pdpt_entry & 0x8) println("  - Write-through");
    if (pdpt_entry & 0x10) println("  - Cache disabled");
    if (pdpt_entry & 0x20) println("  - Accessed");
    if (pdpt_entry & 0x80) println("  - PS bit set (1GB page)");
    if (pdpt_entry & (1ULL << 63)) println("  - NX bit set");
    
    if (!(pdpt_entry & 0x1)) {
        println("PAGE_PERM: PDPT entry not present, skipping");
        goto restore_interrupts;
    }
    
    // Check for 1GB pages
    if (pdpt_entry & 0x80) {
        println("PAGE_PERM: 1GB page detected - no PD or PT exists");
        goto restore_interrupts;
    }
    
    // Access PD
    uint64_t pd_phys = pdpt_entry & ~0xFFF;
    print("PAGE_PERM: PD physical address: 0x");
    uint64_to_hex(pd_phys, hex_str);
    println(hex_str);
    
    uint64_t* pd = (uint64_t*)pd_phys;
    
    uint64_t pd_entry;
    __asm__ volatile(
        "movq (%1), %0\n"
        : "=r"(pd_entry)
        : "r"(&pd[pd_idx])
        : "memory"
    );
    
    print("PAGE_PERM: PD entry raw value: 0x");
    uint64_to_hex(pd_entry, hex_str);
    println(hex_str);
    
    // Analyze PD entry flags
    println("PAGE_PERM: PD entry flags:");
    if (pd_entry & 0x1) println("  - Present");
    if (pd_entry & 0x2) println("  - Writable");
    if (pd_entry & 0x4) println("  - User accessible");
    if (pd_entry & 0x8) println("  - Write-through");
    if (pd_entry & 0x10) println("  - Cache disabled");
    if (pd_entry & 0x20) println("  - Accessed");
    if (pd_entry & 0x40) println("  - Dirty");
    if (pd_entry & 0x80) println("  - PS bit set (2MB page)");
    if (pd_entry & (1ULL << 63)) println("  - NX bit set");
    
    if (!(pd_entry & 0x1)) {
        println("PAGE_PERM: PD entry not present, skipping");
        goto restore_interrupts;
    }
    
    // Check for 2MB pages (PS bit in PD)
    if (pd_entry & 0x80) {
        println("PAGE_PERM: 2MB page detected - no PT exists");
        
        // Dump some data from the 2MB page if accessible
        println("PAGE_PERM: Attempting to dump first 64 bytes of 2MB page:");
        uint64_t page_start = vaddr & ~0x1FFFFF;  // Align to 2MB boundary
        uint8_t* page_data = (uint8_t*)page_start;
        
        for (int i = 0; i < 64; i += 16) {
            print("  ");
            uint64_to_hex(page_start + i, hex_str);
            print(hex_str);
            print(": ");
            
            for (int j = 0; j < 16 && i + j < 64; j++) {
                char byte_hex[4];
                uint8_t byte_val = page_data[i + j];
                byte_hex[0] = (byte_val >> 4) < 10 ? ('0' + (byte_val >> 4)) : ('A' + (byte_val >> 4) - 10);
                byte_hex[1] = (byte_val & 0xF) < 10 ? ('0' + (byte_val & 0xF)) : ('A' + (byte_val & 0xF) - 10);
                byte_hex[2] = ' ';
                byte_hex[3] = '\0';
                print(byte_hex);
            }
            println("");
        }
        
        // For 2MB pages, modify the PD entry directly
        uint64_t new_pd_entry = (pd_entry & ~0x8000000000000007ULL) | flags | 0x80; // Keep PS bit
        
        // Use atomic compare-and-swap to update the PD entry
        uint64_t old_entry = pd_entry;
        __asm__ volatile(
            "lock cmpxchgq %2, (%1)\n"
            : "+a"(old_entry)
            : "r"(&pd[pd_idx]), "r"(new_pd_entry)
            : "memory"
        );
        
        if (old_entry == pd_entry) {
            // Invalidate TLB for the entire 2MB region
            for (uint64_t addr = vaddr & ~0x1FFFFF; addr < (vaddr & ~0x1FFFFF) + 0x200000; addr += 0x1000) {
                __asm__ volatile("invlpg (%0)" : : "r"(addr) : "memory");
            }
            println("PAGE_PERM: 2MB page permissions set successfully");
        } else {
            println("PAGE_PERM: Failed to update 2MB page entry atomically");
        }
        
        goto restore_interrupts;
    }
    
    // Handle 4KB pages - PT exists
    println("PAGE_PERM: 4KB pages detected - PT should exist");
    
    uint64_t pt_phys = pd_entry & ~0xFFF;
    print("PAGE_PERM: PT physical address: 0x");
    uint64_to_hex(pt_phys, hex_str);
    println(hex_str);
    
    uint64_t* pt = (uint64_t*)pt_phys;
    
    uint64_t pt_entry;
    __asm__ volatile(
        "movq (%1), %0\n"
        : "=r"(pt_entry)
        : "r"(&pt[pt_idx])
        : "memory"
    );
    
    print("PAGE_PERM: PT entry raw value: 0x");
    uint64_to_hex(pt_entry, hex_str);
    println(hex_str);
    
    // Analyze PT entry flags
    println("PAGE_PERM: PT entry flags:");
    if (pt_entry & 0x1) println("  - Present");
    if (pt_entry & 0x2) println("  - Writable");
    if (pt_entry & 0x4) println("  - User accessible");
    if (pt_entry & 0x8) println("  - Write-through");
    if (pt_entry & 0x10) println("  - Cache disabled");
    if (pt_entry & 0x20) println("  - Accessed");
    if (pt_entry & 0x40) println("  - Dirty");
    if (pt_entry & (1ULL << 63)) println("  - NX bit set");
    
    if (!(pt_entry & 0x1)) {
        println("PAGE_PERM: PT entry not present, skipping");
        goto restore_interrupts;
    }
    
    // Dump some data from the 4KB page if accessible
    println("PAGE_PERM: Attempting to dump first 64 bytes of 4KB page:");
    uint64_t page_start = vaddr & ~0xFFF;  // Align to 4KB boundary
    uint8_t* page_data = (uint8_t*)page_start;
    
    for (int i = 0; i < 64; i += 16) {
        print("  ");
        uint64_to_hex(page_start + i, hex_str);
        print(hex_str);
        print(": ");
        
        for (int j = 0; j < 16 && i + j < 64; j++) {
            char byte_hex[4];
            uint8_t byte_val = page_data[i + j];
            byte_hex[0] = (byte_val >> 4) < 10 ? ('0' + (byte_val >> 4)) : ('A' + (byte_val >> 4) - 10);
            byte_hex[1] = (byte_val & 0xF) < 10 ? ('0' + (byte_val & 0xF)) : ('A' + (byte_val & 0xF) - 10);
            byte_hex[2] = ' ';
            byte_hex[3] = '\0';
            print(byte_hex);
        }
        println("");
    }
    
    uint64_t new_entry = (pt_entry & ~0x8000000000000007ULL) | flags;
    
    uint64_t old_entry = pt_entry;
    __asm__ volatile(
        "lock cmpxchgq %2, (%1)\n"
        : "+a"(old_entry)
        : "r"(&pt[pt_idx]), "r"(new_entry)
        : "memory"
    );
    
    if (old_entry == pt_entry) {
        __asm__ volatile("invlpg (%0)" : : "r"(vaddr) : "memory");
        println("PAGE_PERM: 4KB page permissions set successfully");
    } else {
        println("PAGE_PERM: Failed to update 4KB page entry atomically");
    }
    
restore_interrupts:
    // Restore interrupts
    __asm__ volatile(
        "pushq %0\n"
        "popfq\n"
        :
        : "r"(old_flags)
        : "memory"
    );
    
    println("PAGE_PERM: Comprehensive page analysis completed");
}

// Helper function to allocate a safe user stack with proper page mapping
void* allocate_safe_user_stack(size_t size) {
    println("ELF: Allocating safe user stack with 4KB pages");
    
    // Ensure size is at least 8KB (2 pages) and aligned to 4KB
    size_t aligned_size = (size + 0xFFF) & ~0xFFF;
    if (aligned_size < 8192) {
        aligned_size = 8192;  // Minimum 2 pages
    }
    
    // Use a fixed address for the stack
    uint64_t stack_addr = 0x30000000;  // 768MB mark
    
    print("ELF: Stack allocated at: 0x");
    char hex_str[20];
    uint64_to_hex(stack_addr, hex_str);
    println(hex_str);
    
    // Map each 4KB page individually with careful validation
    for (uint64_t offset = 0; offset < aligned_size; offset += 0x1000) {
        uint64_t page_addr = stack_addr + offset;
        
        print("ELF: Mapping stack page at 0x");
        uint64_to_hex(page_addr, hex_str);
        println(hex_str);
        
        // Map the page with proper permissions - ENSURE WRITABLE FLAG IS SET
        if (user_map_page(page_addr, page_addr, PAGE_PRESENT | PAGE_WRITE | PAGE_USER) != 0) {
            println("ELF: Failed to map stack page");
            return NULL;
        }
        
        // Verify the page is accessible by writing to the beginning of the page
        volatile uint64_t* test_ptr = (volatile uint64_t*)page_addr;
        *test_ptr = 0xDEADBEEF;
        if (*test_ptr != 0xDEADBEEF) {
            println("ELF: Stack page not accessible after mapping");
            return NULL;
        }
        
        // Clear the page
        memset((void*)page_addr, 0, 0x1000);
        
        print("ELF: Stack page at 0x");
        uint64_to_hex(page_addr, hex_str);
        println(" mapped and cleared");
    }
    
    println("ELF: Stack mapped with 4KB pages and cleared");
    
    // Return the stack base address
    return (void*)stack_addr;
}

// Function to walk page tables for a specific address and check permissions
void debug_walk_page_tables(uint64_t vaddr, const char* desc) {
    println("DEBUG: Walking page tables for address");
    print("DEBUG: Address: 0x");
    char hex_str[20];
    uint64_to_hex(vaddr, hex_str);
    print(hex_str);
    print(" (");
    print(desc);
    println(")");
    
    // Get CR3
    uint64_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    
    print("DEBUG: CR3: 0x");
    uint64_to_hex(cr3, hex_str);
    println(hex_str);
    
    // Extract page table indices
    uint64_t pml4_idx = (vaddr >> 39) & 0x1FF;
    uint64_t pdpt_idx = (vaddr >> 30) & 0x1FF;
    uint64_t pd_idx = (vaddr >> 21) & 0x1FF;
    uint64_t pt_idx = (vaddr >> 12) & 0x1FF;
    uint64_t page_offset = vaddr & 0xFFF;
    
    print("DEBUG: PML4 index: ");
    uint64_to_hex(pml4_idx, hex_str);
    println(hex_str);
    
    print("DEBUG: PDPT index: ");
    uint64_to_hex(pdpt_idx, hex_str);
    println(hex_str);
    
    print("DEBUG: PD index: ");
    uint64_to_hex(pd_idx, hex_str);
    println(hex_str);
    
    print("DEBUG: PT index: ");
    uint64_to_hex(pt_idx, hex_str);
    println(hex_str);
    
    print("DEBUG: Page offset: 0x");
    uint64_to_hex(page_offset, hex_str);
    println(hex_str);
    
    // Check if address is near page boundary
    if (page_offset > 0xFF0) {
        println("DEBUG: WARNING - Address is within 16 bytes of page boundary!");
        print("DEBUG: Bytes to next page: ");
        char num_str[8];
        uint64_t bytes_to_boundary = 0x1000 - page_offset;
        num_str[0] = '0' + (bytes_to_boundary / 10);
        num_str[1] = '0' + (bytes_to_boundary % 10);
        num_str[2] = '\0';
        println(num_str);
    }
    
    // Access PML4
    uint64_t pml4_phys = cr3 & ~0xFFF;
    uint64_t* pml4 = (uint64_t*)pml4_phys;
    
    print("DEBUG: PML4 entry: 0x");
    uint64_t pml4_entry = pml4[pml4_idx];
    uint64_to_hex(pml4_entry, hex_str);
    println(hex_str);
    
    // Check PML4 flags
    println("DEBUG: PML4 flags:");
    if (pml4_entry & 0x1) println("  - Present");
    if (pml4_entry & 0x2) println("  - Writable");
    if (pml4_entry & 0x4) println("  - User accessible");
    if (pml4_entry & 0x8) println("  - Write-through");
    if (pml4_entry & 0x10) println("  - Cache disabled");
    if (pml4_entry & 0x20) println("  - Accessed");
    
    if (!(pml4_entry & 0x1)) {
        println("DEBUG: PML4 entry not present - page not mapped!");
        return;
    }
    
    // Access PDPT
    uint64_t pdpt_phys = pml4_entry & ~0xFFF;
    uint64_t* pdpt = (uint64_t*)pdpt_phys;
    
    print("DEBUG: PDPT entry: 0x");
    uint64_t pdpt_entry = pdpt[pdpt_idx];
    uint64_to_hex(pdpt_entry, hex_str);
    println(hex_str);
    
    // Check PDPT flags
    println("DEBUG: PDPT flags:");
    if (pdpt_entry & 0x1) println("  - Present");
    if (pdpt_entry & 0x2) println("  - Writable");
    if (pdpt_entry & 0x4) println("  - User accessible");
    if (pdpt_entry & 0x8) println("  - Write-through");
    if (pdpt_entry & 0x10) println("  - Cache disabled");
    if (pdpt_entry & 0x20) println("  - Accessed");
    if (pdpt_entry & 0x80) println("  - PS=1 (1GB page)");
    
    if (!(pdpt_entry & 0x1)) {
        println("DEBUG: PDPT entry not present - page not mapped!");
        return;
    }
    
    // Check for 1GB page
    if (pdpt_entry & 0x80) {
        println("DEBUG: This is a 1GB page - no PD or PT entries");
        return;
    }
    
    // Access PD
    uint64_t pd_phys = pdpt_entry & ~0xFFF;
    uint64_t* pd = (uint64_t*)pd_phys;
    
    print("DEBUG: PD entry: 0x");
    uint64_t pd_entry = pd[pd_idx];
    uint64_to_hex(pd_entry, hex_str);
    println(hex_str);
    
    // Check PD flags
    println("DEBUG: PD flags:");
    if (pd_entry & 0x1) println("  - Present");
    if (pd_entry & 0x2) println("  - Writable");
    if (pd_entry & 0x4) println("  - User accessible");
    if (pd_entry & 0x8) println("  - Write-through");
    if (pd_entry & 0x10) println("  - Cache disabled");
    if (pd_entry & 0x20) println("  - Accessed");
    if (pd_entry & 0x40) println("  - Dirty");
    if (pd_entry & 0x80) println("  - PS=1 (2MB page)");
    
    if (!(pd_entry & 0x1)) {
        println("DEBUG: PD entry not present - page not mapped!");
        return;
    }
    
    // Check for 2MB page
    if (pd_entry & 0x80) {
        println("DEBUG: This is a 2MB page - no PT entry");
        
        // Check NX bit for 2MB page
        if (pd_entry & (1ULL << 63)) {
            println("DEBUG: NX=1 (not executable)");
        } else {
            println("DEBUG: NX=0 (executable)");
        }
        
        return;
    }
    
    // Access PT
    uint64_t pt_phys = pd_entry & ~0xFFF;
    uint64_t* pt = (uint64_t*)pt_phys;
    
    print("DEBUG: PT entry: 0x");
    uint64_t pt_entry = pt[pt_idx];
    uint64_to_hex(pt_entry, hex_str);
    println(hex_str);
    
    // Check PT flags
    println("DEBUG: PT flags:");
    if (pt_entry & 0x1) println("  - Present");
    if (pt_entry & 0x2) println("  - Writable");
    if (pt_entry & 0x4) println("  - User accessible");
    if (pt_entry & 0x8) println("  - Write-through");
    if (pt_entry & 0x10) println("  - Cache disabled");
    if (pt_entry & 0x20) println("  - Accessed");
    if (pt_entry & 0x40) println("  - Dirty");
    
    // Check NX bit
    if (pt_entry & (1ULL << 63)) {
        println("DEBUG: NX=1 (not executable)");
    } else {
        println("DEBUG: NX=0 (executable)");
    }
    
    if (!(pt_entry & 0x1)) {
        println("DEBUG: PT entry not present - page not mapped!");
        return;
    }
    
    // Get physical address
    uint64_t phys_addr = (pt_entry & ~0xFFF) | page_offset;
    print("DEBUG: Physical address: 0x");
    uint64_to_hex(phys_addr, hex_str);
    println(hex_str);
    
    // Dump memory at this address
    println("DEBUG: Memory dump at this address:");
    uint8_t* mem = (uint8_t*)vaddr;
    
    for (int i = 0; i < 64; i += 16) {
        print("  0x");
        uint64_to_hex(vaddr + i, hex_str);
        print(hex_str);
        print(": ");
        
        for (int j = 0; j < 16; j++) {
            char byte_hex[4];
            uint8_t byte_val;
            
            // Safely read memory
            __asm__ volatile(
                "movb (%1), %0\n"
                : "=r"(byte_val)
                : "r"(mem + i + j)
                :
            );
            
            byte_hex[0] = (byte_val >> 4) < 10 ? ('0' + (byte_val >> 4)) : ('A' + (byte_val >> 4) - 10);
            byte_hex[1] = (byte_val & 0xF) < 10 ? ('0' + (byte_val & 0xF)) : ('A' + (byte_val & 0xF) - 10);
            byte_hex[2] = ' ';
            byte_hex[3] = '\0';
            print(byte_hex);
        }
        println("");
    }
}

// Add this to your ELF loader before the IRETQ
void debug_ring3_transition(uint64_t entry_point, uint64_t user_rsp) {
    println("DEBUG: Analyzing Ring 3 transition");
    
    // Check entry point
    debug_walk_page_tables(entry_point, "Entry point");
    
    // Check stack
    debug_walk_page_tables(user_rsp, "Stack pointer");
    
    // Check stack - 8 bytes (for potential push)
    debug_walk_page_tables(user_rsp - 8, "Stack pointer - 8 bytes");
    
    // Check if stack is properly aligned
    if ((user_rsp & 0xF) != 0) {
        println("DEBUG: WARNING - Stack not 16-byte aligned!");
        print("DEBUG: Stack alignment: ");
        char align_str[4];
        align_str[0] = '0' + ((user_rsp & 0xF) / 10);
        align_str[1] = '0' + ((user_rsp & 0xF) % 10);
        align_str[2] = '\0';
        println(align_str);
    } else {
        println("DEBUG: Stack is 16-byte aligned");
    }
    
    // Check if entry point code is valid
    uint8_t* code = (uint8_t*)entry_point;
    if (code[0] == 0x48 && code[1] == 0x89 && code[2] == 0xE0) {
        println("DEBUG: Entry point code starts with 'mov %rsp, %rax' - looks valid");
    } else {
        println("DEBUG: WARNING - Entry point code doesn't match expected pattern!");
    }
    
    println("DEBUG: Ring 3 transition analysis complete");
}

// New function for 4KB page permissions
void set_page_permissions_4kb(uint64_t vaddr, uint64_t flags) {
    // Align address to 4KB boundary
    uint64_t aligned_addr = vaddr & ~0xFFF;
    
    print("PAGE_PERM: Setting 4KB page permissions for: 0x");
    char hex_str[20];
    uint64_to_hex(aligned_addr, hex_str);
    println(hex_str);
    
    // Use existing set_page_permissions but ensure 4KB alignment
    set_page_permissions(aligned_addr, flags);
}

// Modified map_page function to support both 4KB and 2MB pages
int map_page_4kb(uint64_t virt_addr, uint64_t phys_addr, uint64_t flags) {
    // Extract page table indices
    uint64_t pml4_index = (virt_addr >> 39) & 0x1FF;
    uint64_t pdpt_index = (virt_addr >> 30) & 0x1FF;
    uint64_t pd_index = (virt_addr >> 21) & 0x1FF;
    uint64_t pt_index = (virt_addr >> 12) & 0x1FF;
    
    // Ensure PML4 entry exists
    if (!(pml4_table->entries[pml4_index] & PAGE_PRESENT)) {
        uint64_t new_pdpt = alloc_page();
        pml4_table->entries[pml4_index] = new_pdpt | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    }
    
    // Get PDPT table
    page_table_t* pdpt = (page_table_t*)(pml4_table->entries[pml4_index] & ~0xFFF);
    
    // Ensure PDPT entry exists
    if (!(pdpt->entries[pdpt_index] & PAGE_PRESENT)) {
        uint64_t new_pd = alloc_page();
        pdpt->entries[pdpt_index] = new_pd | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    }
    
    // Get PD table
    page_table_t* pd = (page_table_t*)(pdpt->entries[pdpt_index] & ~0xFFF);
    
    // Check if this is already a 2MB page
    if (pd->entries[pd_index] & PAGE_SIZE_2MB) {
        println("PAGING: WARNING - Trying to map 4KB page over existing 2MB page");
        // Remove the 2MB page first
        pd->entries[pd_index] = 0;
        __asm__ volatile("invlpg (%0)" : : "r"(virt_addr & ~0x1FFFFF) : "memory");
    }
    
    // Ensure PD entry exists and points to a PT (not a 2MB page)
    if (!(pd->entries[pd_index] & PAGE_PRESENT)) {
        uint64_t new_pt = alloc_page();
        pd->entries[pd_index] = new_pt | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    }
    
    // Get PT table
    page_table_t* pt = (page_table_t*)(pd->entries[pd_index] & ~0xFFF);
    
    // Map 4KB page
    pt->entries[pt_index] = phys_addr | flags;
    
    // Invalidate TLB
    __asm__ volatile("invlpg (%0)" : : "r"(virt_addr) : "memory");
    
    return 0;
}

// Modified user memory allocator to use 4KB pages
void* user_malloc_4kb(size_t size) {
    if (size == 0 || size > 16 * 1024 * 1024) {
        return NULL;
    }
    
    // Round up to 4KB boundary
    size_t aligned_size = (size + 0xFFF) & ~0xFFF;
    
    // Allocate physical pages
    uint64_t phys_addr = alloc_page();
    if (phys_addr == 0) {
        return NULL;
    }
    
    // Find a virtual address in user space
    uint64_t next_user_vaddr = USER_VIRTUAL_START;
    uint64_t virt_addr = next_user_vaddr;
    next_user_vaddr += aligned_size;
    
    // Map each 4KB page
    for (uint64_t offset = 0; offset < aligned_size; offset += 0x1000) {
        uint64_t page_phys = (offset == 0) ? phys_addr : alloc_page();
        if (map_page_4kb(virt_addr + offset, page_phys, 
                         PAGE_PRESENT | PAGE_WRITE | PAGE_USER) != 0) {
            return NULL;
        }
    }
    
    return (void*)virt_addr;
}

// Replace your user_malloc_aligned function
void* user_malloc_aligned(size_t size, size_t alignment) {
    // For 4KB alignment, use the 4KB allocator
    if (alignment <= 0x1000) {
        return user_malloc_4kb(size);
    }
    
    // For larger alignments, fall back to the old method
    void* ptr = user_malloc_4kb(size + alignment - 1);
    if (!ptr) return NULL;
    
    uint64_t addr = (uint64_t)ptr;
    uint64_t aligned_addr = (addr + alignment - 1) & ~(alignment - 1);
    
    return (void*)aligned_addr;
}

// Final sanity checks
int verify_ring3_environment (void) {
    println("ELF: Step 9 - Final sanity checks");
    
    // Check CR3
    uint64_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    if (cr3 == 0) {
        println("ELF: CRITICAL ERROR - Invalid CR3");
        return -1;
    }
    
    // Check CR0.PG
    uint64_t cr0;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    if (!(cr0 & 0x80000000)) {
        println("ELF: CRITICAL ERROR - Paging not enabled");
        return -1;
    }
    
    // Check CR4.PAE
    uint64_t cr4;
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    if (!(cr4 & 0x20)) {
        println("ELF: CRITICAL ERROR - PAE not enabled");
        return -1;
    }
    
    // Check EFER.LME and EFER.LMA
    uint64_t efer;
    __asm__ volatile(
        "movl $0xC0000080, %%ecx\n"
        "rdmsr\n"
        "shlq $32, %%rdx\n"
        "orq %%rdx, %%rax\n"
        : "=a"(efer)
        :
        : "rcx", "rdx"
    );
    
    if (!(efer & 0x100)) {
        println("ELF: CRITICAL ERROR - Long mode not enabled");
        return -1;
    }
    
    if (!(efer & 0x400)) {
        println("ELF: CRITICAL ERROR - Long mode not active");
        return -1;
    }
    
    println("ELF: All sanity checks passed");
    return 0;
}
