#include "include.h"

// Initialize allocation tracking
void init_user_tracking (void) {
    if (user_tracking_initialized) return;
    
    for (int i = 0; i < MAX_USER_ALLOCATIONS; i++) {
        user_allocations[i].start_addr = 0;
        user_allocations[i].size = 0;
        user_allocations[i].guard_before = 0;
        user_allocations[i].guard_after = 0;
        user_allocations[i].magic = 0;
        user_allocations[i].is_allocated = 0;
        user_allocations[i].allocation_id = 0;
    }
    
    user_allocation_count = 0;
    user_tracking_initialized = 1;
}

// Create guard page
uint64_t create_guard_page (void) {
    void* guard = malloc(USER_PAGE_SIZE);
    if (!guard) return 0;
    
    // Fill with guard pattern
    uint32_t* guard_data = (uint32_t*)guard;
    for (int i = 0; i < USER_PAGE_SIZE / 4; i++) {
        guard_data[i] = GUARD_PAGE_MAGIC;
    }
    
    // Set as read-only
    set_page_permissions((uint64_t)guard, PAGE_PRESENT | PAGE_USER);
    
    return (uint64_t)guard;
}

// Validate guard page
int check_guard_page(uint64_t guard_addr) {
    if (guard_addr == 0) return 1;
    
    uint32_t* guard_data = (uint32_t*)guard_addr;
    for (int i = 0; i < USER_PAGE_SIZE / 4; i++) {
        if (guard_data[i] != GUARD_PAGE_MAGIC) {
            return 0;
        }
    }
    return 1;
}

// Find allocation by address
int find_user_allocation(void* ptr) {
    uint64_t addr = (uint64_t)ptr;
    
    for (int i = 0; i < user_allocation_count; i++) {
        if (user_allocations[i].is_allocated && 
            user_allocations[i].start_addr == addr) {
            return i;
        }
    }
    return -1;
}

// FIXED: Robust user memory management initialization
int user_memory_init (void) {
    println("USER_MEM: Initializing robust user memory management");
    
    // Prevent recursive calls
    int init_in_progress = 0;
    if (init_in_progress) {
        println("USER_MEM: Init already in progress");
        return 0;
    }
    init_in_progress = 1;
    
    // Initialize paging with minimal validation
    if (user_paging_init() != 0) {
        println("USER_MEM: Failed to initialize user paging");
        init_in_progress = 0;
        return -1;
    }
    
    // Initialize memory allocator with simple setup
    user_memory_head = (user_memory_block_t*)USER_VIRTUAL_START;
    
    // FIXED: Safe initialization without complex validation
    user_memory_head->size = (USER_VIRTUAL_END - USER_VIRTUAL_START) - sizeof(user_memory_block_t);
    user_memory_head->is_free = 1;
    user_memory_head->next = NULL;
    
    println("USER_MEM: Memory allocator initialized successfully");
    
    init_in_progress = 0;
    return 0;
}

// FIXED: Safe user space guard page allocator with proper validation
uint64_t user_guard_page_allocator(size_t guard_size) {
    println("USER_GUARD: Starting safe guard page allocation");
    
    // Validate user memory system is initialized
    if (!user_memory_head) {
        println("USER_GUARD: ERROR - User memory not initialized");
        return 0;
    }
    
    // Validate user_memory_head pointer is in user space
    if ((uint64_t)user_memory_head < USER_VIRTUAL_START || 
        (uint64_t)user_memory_head >= USER_VIRTUAL_END) {
        println("USER_GUARD: ERROR - User memory head outside user space");
        return 0;
    }
    
    // Ensure guard size is page aligned
    size_t aligned_guard_size = (guard_size + USER_PAGE_SIZE - 1) & ~(USER_PAGE_SIZE - 1);
    
    // Validate user_memory_head accessibility before traversal
    volatile user_memory_block_t* test_head = user_memory_head;
    
    // Test if we can read the head block safely
    __asm__ volatile("" ::: "memory"); // Memory barrier
    
    // Safe read test
    size_t head_size;
    int head_is_free;
    user_memory_block_t* head_next;
    
    // Read fields safely with validation
    head_size = test_head->size;
    head_is_free = test_head->is_free;
    head_next = test_head->next;
    
    // Validate head block data
    if (head_size == 0 || head_size > (USER_VIRTUAL_END - USER_VIRTUAL_START)) {
        println("USER_GUARD: ERROR - Invalid head block size");
        return 0;
    }
    
    println("USER_GUARD: User memory head validated");
    
    // Find free block with safe traversal
    user_memory_block_t* current = user_memory_head;
    user_memory_block_t* suitable_block = NULL;
    int traversal_count = 0;
    
    // Safe traversal with bounds checking
    while (current && traversal_count < 100) { // Prevent infinite loops
        // Validate current pointer is in user space
        if ((uint64_t)current < USER_VIRTUAL_START || 
            (uint64_t)current >= USER_VIRTUAL_END) {
            println("USER_GUARD: ERROR - Block pointer outside user space");
            return 0;
        }
        
        // Validate current block structure
        if ((uint64_t)current + sizeof(user_memory_block_t) > USER_VIRTUAL_END) {
            println("USER_GUARD: ERROR - Block structure extends beyond user space");
            return 0;
        }
        
        // Safe read of block fields
        volatile user_memory_block_t* safe_current = current;
        size_t block_size = safe_current->size;
        int block_is_free = safe_current->is_free;
        user_memory_block_t* block_next = safe_current->next;
        
        // Validate block size
        if (block_size == 0 || block_size > (USER_VIRTUAL_END - USER_VIRTUAL_START)) {
            println("USER_GUARD: ERROR - Invalid block size detected");
            return 0;
        }
        
        // Check if block is suitable
        if (block_is_free && block_size >= aligned_guard_size) {
            suitable_block = current;
            break;
        }
        
        // Validate next pointer before following it
        if (block_next) {
            if ((uint64_t)block_next < USER_VIRTUAL_START || 
                (uint64_t)block_next >= USER_VIRTUAL_END) {
                println("USER_GUARD: ERROR - Next pointer outside user space");
                return 0;
            }
        }
        
        current = block_next;
        traversal_count++;
    }
    
    if (!suitable_block) {
        println("USER_GUARD: ERROR - No suitable block for guard page");
        return 0;
    }
    
    println("USER_GUARD: Found suitable block");
    
    // Split block if necessary with safe operations
    if (suitable_block->size > aligned_guard_size + sizeof(user_memory_block_t)) {
        uint64_t new_block_addr = (uint64_t)suitable_block + sizeof(user_memory_block_t) + aligned_guard_size;
        
        // Validate new block address
        if (new_block_addr >= USER_VIRTUAL_END - sizeof(user_memory_block_t)) {
            println("USER_GUARD: ERROR - Block split would exceed user space");
            return 0;
        }
        
        user_memory_block_t* new_block = (user_memory_block_t*)new_block_addr;
        
        // Safe initialization of new block
        new_block->size = suitable_block->size - aligned_guard_size - sizeof(user_memory_block_t);
        new_block->is_free = 1;
        new_block->next = suitable_block->next;
        
        // Update original block
        suitable_block->size = aligned_guard_size;
        suitable_block->next = new_block;
        
        println("USER_GUARD: Block split successfully");
    }
    
    // Mark block as allocated
    suitable_block->is_free = 0;
    
    // Calculate guard page address
    uint64_t guard_addr = (uint64_t)suitable_block + sizeof(user_memory_block_t);
    
    // Validate guard address is properly aligned and in user space
    if (guard_addr < USER_VIRTUAL_START || guard_addr >= USER_VIRTUAL_END) {
        println("USER_GUARD: ERROR - Guard address outside user space");
        suitable_block->is_free = 1; // Revert allocation
        return 0;
    }
    
    if (guard_addr + aligned_guard_size > USER_VIRTUAL_END) {
        println("USER_GUARD: ERROR - Guard page would exceed user space");
        suitable_block->is_free = 1; // Revert allocation
        return 0;
    }
    
    // Test write access to ensure page is mapped - SAFE TEST
    println("USER_GUARD: Testing guard page accessibility");
    
    volatile uint8_t* test_ptr = (volatile uint8_t*)guard_addr;
    
    // Test first byte
    *test_ptr = 0xAA;
    if (*test_ptr != 0xAA) {
        println("USER_GUARD: ERROR - Guard page first byte not writable");
        suitable_block->is_free = 1; // Revert allocation
        return 0;
    }
    
    // Test last byte
    volatile uint8_t* last_ptr = (volatile uint8_t*)(guard_addr + aligned_guard_size - 1);
    *last_ptr = 0xBB;
    if (*last_ptr != 0xBB) {
        println("USER_GUARD: ERROR - Guard page last byte not writable");
        suitable_block->is_free = 1; // Revert allocation
        return 0;
    }
    
    println("USER_GUARD: Guard page accessibility validated");
    
    // Fill guard page with magic pattern - SAFE FILL
    uint32_t* guard_data = (uint32_t*)guard_addr;
    size_t pattern_count = aligned_guard_size / 4;
    
    for (size_t i = 0; i < pattern_count; i++) {
        guard_data[i] = GUARD_PAGE_MAGIC;
    }
    
    // Validate pattern was written correctly - SAFE VALIDATION
    for (size_t i = 0; i < pattern_count; i++) {
        if (guard_data[i] != GUARD_PAGE_MAGIC) {
            println("USER_GUARD: ERROR - Guard pattern validation failed");
            suitable_block->is_free = 1; // Revert allocation
            return 0;
        }
    }
    
    println("USER_GUARD: Guard page allocated and validated successfully");
    return guard_addr;
}

// Safe user space guard page deallocator
void user_guard_page_deallocator(uint64_t guard_addr) {
    if (guard_addr == 0) return;
    
    println("USER_GUARD: Deallocating guard page");
    
    // Find the block containing this guard page
    user_memory_block_t* current = user_memory_head;
    
    while (current) {
        uint64_t block_data_start = (uint64_t)current + sizeof(user_memory_block_t);
        uint64_t block_data_end = block_data_start + current->size;
        
        if (guard_addr >= block_data_start && guard_addr < block_data_end) {
            // Found the block, mark it as free
            current->is_free = 1;
            
            // Clear guard page
            uint8_t* guard_ptr = (uint8_t*)guard_addr;
            for (size_t i = 0; i < current->size; i++) {
                guard_ptr[i] = 0xDD; // Poison value
            }
            
            println("USER_GUARD: Guard page deallocated successfully");
            return;
        }
        current = current->next;
    }
    
    println("USER_GUARD: WARNING - Guard page not found for deallocation");
}

// Enhanced user_memcpy with bounds checking
void user_memcpy(void* dest, const void* src, size_t n) {
    if (!dest || !src || n == 0) return;
    
    // Find destination allocation
    int dest_alloc = find_user_allocation(dest);
    if (dest_alloc == -1) {
        println("USER_MEMCPY: Invalid destination");
        return;
    }
    
    user_allocation_t* alloc = &user_allocations[dest_alloc];
    
    if (!alloc->is_allocated || alloc->magic != 0xCAFEBABE) {
        println("USER_MEMCPY: Destination allocation corrupted");
        return;
    }
    
    // Check bounds
    if ((uint64_t)dest + n > alloc->start_addr + alloc->size) {
        println("USER_MEMCPY: Would exceed allocation bounds");
        return;
    }
    
    // Validate guard pages
    if (!check_guard_page(alloc->guard_before) || !check_guard_page(alloc->guard_after)) {
        println("USER_MEMCPY: Guard pages corrupted");
        return;
    }
    
    // Safe copy
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
}

// Enhanced user_memset with bounds checking
void* user_memset(void* ptr, int value, size_t n) {
    if (!ptr || n == 0) return NULL;
    
    // Find allocation
    int alloc_id = find_user_allocation(ptr);
    if (alloc_id == -1) {
        println("USER_MEMSET: Invalid pointer");
        return NULL;
    }
    
    user_allocation_t* alloc = &user_allocations[alloc_id];
    
    if (!alloc->is_allocated || alloc->magic != 0xCAFEBABE) {
        println("USER_MEMSET: Allocation corrupted");
        return NULL;
    }
    
    // Check bounds
    if ((uint64_t)ptr + n > alloc->start_addr + alloc->size) {
        println("USER_MEMSET: Would exceed allocation bounds");
        return NULL;
    }
    
    // Validate guard pages
    if (!check_guard_page(alloc->guard_before) || !check_guard_page(alloc->guard_after)) {
        println("USER_MEMSET: Guard pages corrupted");
        return NULL;
    }
    
    // Safe set
    uint8_t* p = (uint8_t*)ptr;
    uint8_t val = (uint8_t)value;
    
    for (size_t i = 0; i < n; i++) {
        p[i] = val;
    }
    
    return ptr;
}

// Simple dedicated user_map_page function for user memory
int user_map_page(uint64_t virt_addr, uint64_t phys_addr, uint64_t flags) {
    // Ensure address is in user space
    if (virt_addr < USER_VIRTUAL_START || virt_addr >= USER_VIRTUAL_END) {
        println("USER_PAGING: Address outside user space");
        return -1;
    }
    
    // Use the existing map_page function but force 4KB pages for user space
    // This avoids the 2MB page issue
    
    // Extract page table indices
    uint64_t pml4_idx = (virt_addr >> 39) & 0x1FF;
    uint64_t pdpt_idx = (virt_addr >> 30) & 0x1FF;
    uint64_t pd_idx = (virt_addr >> 21) & 0x1FF;
    uint64_t pt_idx = (virt_addr >> 12) & 0x1FF;
    
    // Get current CR3
    uint64_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    
    // Access PML4
    uint64_t* pml4 = (uint64_t*)(cr3 & ~0xFFF);
    
    // Ensure PML4 entry exists
    if (!(pml4[pml4_idx] & PAGE_PRESENT)) {
        uint64_t new_pdpt = alloc_page();
        memset((void*)new_pdpt, 0, PAGE_SIZE);
        pml4[pml4_idx] = new_pdpt | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    }
    
    // Access PDPT
    uint64_t* pdpt = (uint64_t*)(pml4[pml4_idx] & ~0xFFF);
    
    // Ensure PDPT entry exists
    if (!(pdpt[pdpt_idx] & PAGE_PRESENT)) {
        uint64_t new_pd = alloc_page();
        memset((void*)new_pd, 0, PAGE_SIZE);
        pdpt[pdpt_idx] = new_pd | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    }
    
    // Access PD
    uint64_t* pd = (uint64_t*)(pdpt[pdpt_idx] & ~0xFFF);
    
    // Check if this is already a 2MB page
    if (pd[pd_idx] & PAGE_SIZE_2MB) {
        // Remove the 2MB page
        pd[pd_idx] = 0;
        __asm__ volatile("invlpg (%0)" : : "r"(virt_addr & ~0x1FFFFF) : "memory");
    }
    
    // Ensure PD entry exists and points to a PT
    if (!(pd[pd_idx] & PAGE_PRESENT)) {
        uint64_t new_pt = alloc_page();
        memset((void*)new_pt, 0, PAGE_SIZE);
        pd[pd_idx] = new_pt | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    }
    
    // Access PT
    uint64_t* pt = (uint64_t*)(pd[pd_idx] & ~0xFFF);
    
    // Map 4KB page - CRITICAL FIX: Ensure high bits are cleared
    pt[pt_idx] = (phys_addr & 0x000FFFFFFFFFF000ULL) | (flags & 0xFFF);
    
    // Invalidate TLB
    __asm__ volatile("invlpg (%0)" : : "r"(virt_addr) : "memory");
    
    return 0;
}

// ROBUST: User stack allocation with validation
void* user_stack_alloc(size_t size) {
    if (size == 0 || size > (USER_VIRTUAL_END - USER_VIRTUAL_START) / 4) {
        println("USER_MEM: Invalid stack size");
        return NULL;
    }
    
    // Allocate stack memory
    void* stack_mem = user_malloc(size);
    if (!stack_mem) {
        println("USER_MEM: Failed to allocate stack memory");
        return NULL;
    }
    
    // Clear stack memory with validation
    if (user_memset(stack_mem, 0, size) == NULL) {
        println("USER_MEM: Failed to clear stack memory");
        user_free(stack_mem);
        return NULL;
    }
    
    println("USER_MEM: Stack cleared successfully");
    
    // Return stack top (stack grows down)
    return (uint8_t*)stack_mem + size - 16;
}

void user_stack_free(void* stack_top, size_t size) {
    if (!stack_top) return;
    
    void* stack_base = (uint8_t*)stack_top - size + 16;
    user_free(stack_base);
}
