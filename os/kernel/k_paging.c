#include "include.h"

/*==============================================================================================================
  PROPER PAGING SYSTEM - COMPLETE IMPLEMENTATION
================================================================================================================*/

// Get physical address from virtual address
uint64_t virt_to_phys(uint64_t virt_addr) {
    // For identity mapping, virtual == physical for kernel space
    if (virt_addr < 0x40000000) {
        return virt_addr;
    }
    return 0; // Invalid for now
}

// EDITED: Allocate a physical page with detached clearing
uint64_t alloc_page (void) {
    uint64_t page = next_free_page;
    next_free_page += PAGE_SIZE;
    
    // Use raw clearing to avoid circular dependency
    if (paging_operation_in_progress) {
        clear_page_raw(page);
    } else {
        memset((void*)page, 0, PAGE_SIZE);
    }
    
    return page;
}

// Map a virtual address to physical address
int map_page(uint64_t virt_addr, uint64_t phys_addr, uint64_t flags) {
    // Extract page table indices
    uint64_t pml4_index = (virt_addr >> 39) & 0x1FF;
    uint64_t pdpt_index = (virt_addr >> 30) & 0x1FF;
    uint64_t pd_index = (virt_addr >> 21) & 0x1FF;
    
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
    
    // FIXED: Use 4KB pages for user space, 2MB pages only for kernel
    if (virt_addr >= USER_VIRTUAL_START) {
        // For user space, use 4KB pages
        return map_page_4kb(virt_addr, phys_addr, flags);
    } else {
        // For kernel space, use 2MB pages
        pd->entries[pd_index] = phys_addr | flags | PAGE_SIZE_2MB;
    }
    
    return 0;
}

// Initialize proper paging system
int paging_init (void) {
    if (paging_initialized) {
        println("PAGING: Already initialized");
        return 0;
    }
    
    println("PAGING: Initializing proper paging system");
    
    // Get current page tables from boot loader
    uint64_t cr3_value;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3_value));
    pml4_table = (page_table_t*)cr3_value;
    
    println("PAGING: Using existing PML4 table");
    
    // Identity map first 64MB (32 x 2MB pages) for kernel
    println("PAGING: Identity mapping kernel space (64MB)");
    for (uint64_t addr = 0; addr < 0x4000000; addr += 0x200000) {
        if (map_page(addr, addr, PAGE_PRESENT | PAGE_WRITE) != 0) {
            println("PAGING: Failed to map kernel page");
            return -1;
        }
    }
    
    // Map heap area (64MB-128MB)
    println("PAGING: Mapping heap area");
    for (uint64_t addr = 0x4000000; addr < 0x8000000; addr += 0x200000) {
        if (map_page(addr, addr, PAGE_PRESENT | PAGE_WRITE) != 0) {
            println("PAGING: Failed to map heap page");
            return -1;
        }
    }
    
    // Map extended memory (128MB-512MB) - EXTENDED RANGE
    println("PAGING: Mapping extended memory (128MB-512MB)");
    for (uint64_t addr = 0x8000000; addr < 0x20000000; addr += 0x200000) {
        if (map_page(addr, addr, PAGE_PRESENT | PAGE_WRITE) != 0) {
            println("PAGING: Failed to map extended page");
            return -1;
        }
    }
    
    // Flush TLB to activate new mappings
    println("PAGING: Flushing TLB");
    __asm__ volatile("mov %%cr3, %%rax; mov %%rax, %%cr3" ::: "rax", "memory");
    
    paging_initialized = 1;
    println("PAGING: Proper paging system initialized (512MB mapped)");
    return 0;
}

// Map additional memory on demand
int paging_map_range(uint64_t start_addr, uint64_t size) {
    if (!paging_initialized) {
        println("PAGING: Not initialized");
        return -1;
    }
    
    // Align to 2MB boundaries
    uint64_t start = start_addr & ~0x1FFFFF;
    uint64_t end = (start_addr + size + 0x1FFFFF) & ~0x1FFFFF;
    
    println("PAGING: Mapping additional range");
    
    for (uint64_t addr = start; addr < end; addr += 0x200000) {
        if (map_page(addr, addr, PAGE_PRESENT | PAGE_WRITE) != 0) {
            println("PAGING: Failed to map additional page");
            return -1;
        }
    }
    
    // Flush TLB
    __asm__ volatile("mov %%cr3, %%rax; mov %%rax, %%cr3" ::: "rax", "memory");
    
    println("PAGING: Additional range mapped");
    return 0;
}

// Page fault handler (basic)
void page_fault_handler(uint64_t error_code, uint64_t fault_addr) {
    println("PAGE FAULT: Attempting to handle");
    
    print("PAGE FAULT: Address 0x");
    char hex_str[20];
    int hex_pos = 0;
    uint64_t addr = fault_addr;
    if (addr == 0) {
        hex_str[hex_pos++] = '0';
    } else {
        char temp[20];
        int temp_pos = 0;
        while (addr > 0 && temp_pos < 16) {
            uint8_t digit = addr % 16;
            temp[temp_pos++] = (digit < 10) ? ('0' + digit) : ('A' + digit - 10);
            addr /= 16;
        }
        for (int j = temp_pos - 1; j >= 0 && hex_pos < 18; j--) {
            hex_str[hex_pos++] = temp[j];
        }
    }
    hex_str[hex_pos] = '\0';
    println(hex_str);
    
    // Try to map the faulting page
    if (fault_addr < 0x40000000) { // Within reasonable kernel range
        uint64_t page_start = fault_addr & ~0x1FFFFF; // 2MB align
        if (paging_map_range(page_start, 0x200000) == 0) {
            println("PAGE FAULT: Successfully mapped page");
            return; // Continue execution
        }
    }
    
    println("PAGE FAULT: Cannot handle - halting");
    while (1) {
        __asm__ volatile("hlt");
    }
}

// Low-level page clearing function - detached from high-level memory system
void clear_page_raw(uint64_t page_addr) {
    // Direct assembly-based page clearing - no function calls
    __asm__ volatile(
        "movq %0, %%rdi\n"          // Load page address
        "xorq %%rax, %%rax\n"       // Clear rax (zero value)
        "movq $512, %%rcx\n"        // 4096 bytes / 8 = 512 qwords
        "rep stosq\n"               // Clear 8 bytes at a time
        :
        : "r"(page_addr)
        : "rdi", "rax", "rcx", "memory"
    );
}

// CRITICAL FIX: Initialize paging-based memory system
void memory_init (void) {
    if (paging_memory_initialized) {
        println("MEMORY: Already initialized");
        return;
    }
    
    println("MEMORY: Initializing paging-based memory system");
    
    // CRITICAL: Initialize paging FIRST
    if (!paging_initialized) {
        if (paging_init() != 0) {
            println("MEMORY: Paging initialization failed");
            return;
        }
    }
    
    // CRITICAL FIX: Map the heap area BEFORE using it
    println("MEMORY: Mapping heap area (256MB-512MB)");
    
    // Map heap range in 2MB chunks
    for (uint64_t addr = paging_heap_start; addr < paging_heap_end; addr += 0x200000) {
        if (map_page(addr, addr, PAGE_PRESENT | PAGE_WRITE) != 0) {
            println("MEMORY: Failed to map heap page");
            return;
        }
    }
    
    // Flush TLB after mapping heap
    __asm__ volatile("mov %%cr3, %%rax; mov %%rax, %%cr3" ::: "rax", "memory");
    
    println("MEMORY: Heap area mapped successfully");
    
    // NOW initialize first block (after mapping)
    paging_heap_head = (paging_memory_block_t*)paging_heap_start;
    paging_heap_head->size = (paging_heap_end - paging_heap_start) - sizeof(paging_memory_block_t);
    paging_heap_head->free = 1;
    paging_heap_head->next = NULL;
    paging_heap_head->magic = PAGING_BLOCK_MAGIC;
    
    paging_memory_initialized = 1;
    println("MEMORY: Paging-based memory system initialized");
}

// EDITED: Safe memory write with context awareness
int safe_memory_write(void* addr, uint8_t value, size_t offset) {
    if (!addr) {
        return -1;
    }
    
    uint64_t write_addr = (uint64_t)addr + offset;
    
    // Check if we're in a memory operation to prevent recursion
    if (memory_operation_in_progress) {
        // Direct write without additional checks
        *((uint8_t*)write_addr) = value;
        return 0;
    }
    
    // Set operation flag
    memory_operation_in_progress = 1;
    
    // Ensure mapping if needed
    if (paging_initialized && write_addr >= 0x8000000 && !paging_operation_in_progress) {
        paging_operation_in_progress = 1;
        int result = paging_map_range(write_addr & ~0x1FFFFF, 0x200000);
        paging_operation_in_progress = 0;
        
        if (result != 0) {
            memory_operation_in_progress = 0;
            return -1;
        }
    }
    
    // Perform write
    *((uint8_t*)write_addr) = value;
    
    // Clear operation flag
    memory_operation_in_progress = 0;
    return 0;
}

// EDITED: Safe memory read with context awareness
int safe_memory_read(void* addr, uint8_t* value, size_t offset) {
    if (!addr || !value) {
        return -1;
    }
    
    uint64_t read_addr = (uint64_t)addr + offset;
    
    // Check if we're in a memory operation to prevent recursion
    if (memory_operation_in_progress) {
        // Direct read without additional checks
        *value = *((uint8_t*)read_addr);
        return 0;
    }
    
    // Set operation flag
    memory_operation_in_progress = 1;
    
    // Ensure mapping if needed
    if (paging_initialized && read_addr >= 0x8000000 && !paging_operation_in_progress) {
        paging_operation_in_progress = 1;
        int result = paging_map_range(read_addr & ~0x1FFFFF, 0x200000);
        paging_operation_in_progress = 0;
        
        if (result != 0) {
            memory_operation_in_progress = 0;
            return -1;
        }
    }
    
    // Perform read
    *value = *((uint8_t*)read_addr);
    
    // Clear operation flag
    memory_operation_in_progress = 0;
    return 0;
}

// REPLACED: malloc now uses paged disk buffers for small allocations
void* malloc(size_t size) {
    
    // For larger allocations, use the old paging system
    if (!paging_memory_initialized) {
        memory_init();
        if (!paging_memory_initialized) {
            return NULL;
        }
    }
    
    if (size == 0) {
        return NULL;
    }
    
    // Align size to 8 bytes
    size = (size + 7) & ~7;
    
    // Set allocation context to prevent recursive calls
    int malloc_in_progress = 0;
    if (malloc_in_progress) {
        return NULL;
    }
    malloc_in_progress = 1;
    
    // Find suitable block
    paging_memory_block_t* current = paging_heap_head;
    int safety_counter = 0;
    
    while (current && safety_counter < 1000) {
        if (current->magic != PAGING_BLOCK_MAGIC) {
            malloc_in_progress = 0;
            return NULL;
        }
        
        if (current->free && current->size >= size) {
            // Split block if needed
            if (current->size > size + sizeof(paging_memory_block_t) + 64) {
                paging_memory_block_t* new_block = 
                    (paging_memory_block_t*)((uint8_t*)current + sizeof(paging_memory_block_t) + size);
                
                new_block->size = current->size - size - sizeof(paging_memory_block_t);
                new_block->free = 1;
                new_block->next = current->next;
                new_block->magic = PAGING_BLOCK_MAGIC;
                
                current->size = size;
                current->next = new_block;
            }
            
            current->free = 0;
            void* ptr = (uint8_t*)current + sizeof(paging_memory_block_t);
            
            malloc_in_progress = 0;
            return ptr;
        }
        
        current = current->next;
        safety_counter++;
    }
    
    malloc_in_progress = 0;
    return NULL;
}

// REPLACED: free now handles both systems
void free(void* ptr) {
    if (!ptr) {
        return;
    }
    
    uint64_t addr = (uint64_t)ptr;
    
    // Otherwise use paging system free
    if (!paging_memory_initialized) {
        return;
    }
    
    // Get block header
    paging_memory_block_t* block = 
        (paging_memory_block_t*)((uint8_t*)ptr - sizeof(paging_memory_block_t));
    
    // Validate block
    if (block->magic != PAGING_BLOCK_MAGIC) {
        return;
    }
    
    if (block->free) {
        return;
    }
    
    // Mark as free
    block->free = 1;
    
    // Coalesce with next block if it's free
    if (block->next && block->next->free && block->next->magic == PAGING_BLOCK_MAGIC) {
        block->size += block->next->size + sizeof(paging_memory_block_t);
        block->next = block->next->next;
    }
    
    // Coalesce with previous block
    paging_memory_block_t* current = paging_heap_head;
    while (current && current->next != block) {
        current = current->next;
    }
    
    if (current && current->free && current->magic == PAGING_BLOCK_MAGIC) {
        current->size += block->size + sizeof(paging_memory_block_t);
        current->next = block->next;
    }
}

// New paging-based realloc
void* realloc(void* ptr, size_t size) {
    if (!ptr) {
        return malloc(size);
    }
    
    if (size == 0) {
        free(ptr);
        return NULL;
    }
    
    // Get current block
    paging_memory_block_t* block = 
        (paging_memory_block_t*)((uint8_t*)ptr - sizeof(paging_memory_block_t));
    
    if (block->magic != PAGING_BLOCK_MAGIC) {
        return NULL;
    }
    
    // If new size fits in current block, just return it
    if (size <= block->size) {
        return ptr;
    }
    
    // Allocate new block
    void* new_ptr = malloc(size);
    if (!new_ptr) {
        return NULL;
    }
    
    // Copy data
    memcpy(new_ptr, ptr, block->size < size ? block->size : size);
    
    // Free old block
    free(ptr);
    
    return new_ptr;
}

// New paging-based calloc
void* calloc(size_t nmemb, size_t size) {
    size_t total_size = nmemb * size;
    
    // Check for overflow
    if (nmemb != 0 && total_size / nmemb != size) {
        return NULL;
    }
    
    void* ptr = malloc(total_size);
    if (ptr) {
        memset(ptr, 0, total_size);
    }
    
    return ptr;
}

// Memory allocation helpers that use paging
void* basic_malloc(size_t size) {
    return malloc(size);
}

void basic_free(void* ptr) {
    free(ptr);
}

/*==============================================================================================================
  SAFE MEMORY ALLOCATION WITH PAGING
================================================================================================================*/

// Updated safe_malloc to use new system
void* safe_malloc(size_t size) {
    if (size == 0 || size > 16 * 1024 * 1024) {
        return NULL;
    }
    
    return malloc(size); // Now uses paging-based malloc
}
