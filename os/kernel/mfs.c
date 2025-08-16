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
  MEMORY FILE SYSTEM (MFS) - PROPER MEMORY ABSTRACTION
================================================================================================================*/

// FIXED: Initialize Memory File System with massive block mapping
 
int mfs_init (void) {
    println("MFS: Initializing Memory File System");
    
    static volatile int init_in_progress = 0;
    
    if (init_in_progress) {
        println("MFS: Init already in progress");
        return 0;
    }
    
    init_in_progress = 1;
    
    volatile mfs_superblock_t* sb = &mfs_sb;
    
    if (sb->initialized) {
        println("MFS: Already initialized");
        init_in_progress = 0;
        return 0;
    }
    
    // Clear superblock with safe field-by-field initialization
    println("MFS: Initializing superblock fields");
    
    sb->magic = MFS_MAGIC;
    __asm__ volatile("" ::: "memory");
    
    sb->total_size = MFS_REGION_END - MFS_REGION_START;
    __asm__ volatile("" ::: "memory");
    
    sb->free_blocks = sb->total_size / MFS_BLOCK_SIZE;
    __asm__ volatile("" ::: "memory");
    
    sb->used_blocks = 0;
    __asm__ volatile("" ::: "memory");
    
    sb->next_free_addr = MFS_REGION_START;
    __asm__ volatile("" ::: "memory");
    
    sb->root_dir = NULL;
    __asm__ volatile("" ::: "memory");
    
    sb->entry_table = NULL;
    __asm__ volatile("" ::: "memory");
    
    println("MFS: Superblock fields initialized");
    
    // Map the massive 512MB block as MFS foundation
    if (mfs_map_massive_block() != 0) {
        println("MFS: ERROR - Failed to map massive block");
        init_in_progress = 0;
        return -1;
    }
    
    // Initialize entry table at start of MFS region
    sb->entry_table = (mfs_entry_t*)MFS_REGION_START;
    __asm__ volatile("" ::: "memory");
    
    // Clear entry table with safe access
    volatile mfs_entry_t* entry_table = (volatile mfs_entry_t*)MFS_REGION_START;
    
    println("MFS: Clearing entry table in massive block");
    
    for (int i = 0; i < MFS_MAX_ENTRIES; i++) {
        entry_table[i].magic = 0;
        entry_table[i].type = MFS_TYPE_FREE;
        entry_table[i].name[0] = '\0';
        entry_table[i].start_addr = 0;
        entry_table[i].size = 0;
        entry_table[i].blocks_used = 0;
        entry_table[i].permissions = 0;
        entry_table[i].ref_count = 0;
        entry_table[i].parent = NULL;
        entry_table[i].next = NULL;
        entry_table[i].children = NULL;
        
        // Memory barrier every 100 entries
        if ((i % 100) == 0) {
            __asm__ volatile("" ::: "memory");
        }
    }
    
    println("MFS: Entry table cleared in massive block");
    
    // Update next free address past entry table
    sb->next_free_addr = MFS_REGION_START + (MFS_MAX_ENTRIES * sizeof(mfs_entry_t));
    sb->next_free_addr = (sb->next_free_addr + MFS_BLOCK_SIZE - 1) & ~(MFS_BLOCK_SIZE - 1);
    __asm__ volatile("" ::: "memory");
    
    // Create root directory
    sb->root_dir = (mfs_entry_t*)&entry_table[0];
    __asm__ volatile("" ::: "memory");
    
    volatile mfs_entry_t* root = (volatile mfs_entry_t*)sb->root_dir;
    root->magic = MFS_MAGIC;
    root->type = MFS_TYPE_DIR;
    root->name[0] = '/';
    root->name[1] = '\0';
    root->start_addr = 0;
    root->size = 0;
    root->blocks_used = 0;
    root->permissions = 0755;
    root->ref_count = 1;
    root->parent = NULL;
    root->next = NULL;
    root->children = NULL;
    
    __asm__ volatile("" ::: "memory");
    
    // Mark as initialized
    sb->initialized = 1;
    __asm__ volatile("" ::: "memory");
    
    init_in_progress = 0;
    
    println("MFS: Memory File System with massive block foundation initialized successfully");
    return 0;
}

// Permission management functions
int mfs_chmod(mfs_entry_t* entry, uint32_t new_permissions) {
    if (!entry) return -1;
    
    volatile mfs_entry_t* safe_entry = (volatile mfs_entry_t*)entry;
    
    if (safe_entry->magic != MFS_MAGIC) return -1;
    
    safe_entry->permissions = new_permissions;
    __asm__ volatile("" ::: "memory");
    
    return 0;
}

// Check permissions
int mfs_check_permission(mfs_entry_t* entry, uint32_t required_perm) {
    if (!entry) return 0;
    
    volatile mfs_entry_t* safe_entry = (volatile mfs_entry_t*)entry;
    
    if (safe_entry->magic != MFS_MAGIC) return 0;
    
    return (safe_entry->permissions & required_perm) == required_perm;
}

// Manual massive block mapping for MFS foundation

int mfs_map_massive_block (void) {
    println("MFS: Manually mapping massive 512MB block (512MB-1GB)");
    
    // Get current CR3
    uint64_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    
    if (cr3 == 0) {
        println("MFS: ERROR - Invalid CR3");
        return -1;
    }
    
    uint64_t* pml4 = (uint64_t*)(cr3 & ~0xFFF);
    
    // Calculate how many 2MB pages we need for 512MB
    uint64_t total_size = MFS_REGION_END - MFS_REGION_START; // 512MB
    uint64_t pages_2mb_needed = total_size / 0x200000; // 256 pages of 2MB each
    
    print("MFS: Need to map ");
    char count_str[8];
    uint64_to_hex(pages_2mb_needed, count_str);
    print(count_str);
    println(" 2MB pages");
    
    // Map the entire MFS region using 2MB pages for efficiency
    for (uint64_t addr = MFS_REGION_START; addr < MFS_REGION_END; addr += 0x200000) {
        // Extract indices for this address
        uint64_t pml4_idx = (addr >> 39) & 0x1FF;
        uint64_t pdpt_idx = (addr >> 30) & 0x1FF;
        uint64_t pd_idx = (addr >> 21) & 0x1FF;
        
        // CRITICAL FIX: Update existing PML4 entry to add USER bit
        if (pml4[pml4_idx] & PAGE_PRESENT) {
            // Entry exists - ADD USER bit to existing entry
            pml4[pml4_idx] |= PAGE_USER;
        } else {
            // Create new entry with USER bit
            uint64_t new_pdpt = alloc_page();
            memset((void*)new_pdpt, 0, PAGE_SIZE);
            pml4[pml4_idx] = new_pdpt | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
        }
        
        // CRITICAL FIX: Update existing PDPT entry to add USER bit
        uint64_t* pdpt = (uint64_t*)(pml4[pml4_idx] & ~0xFFF);
        if (pdpt[pdpt_idx] & PAGE_PRESENT) {
            // Entry exists - ADD USER bit to existing entry
            pdpt[pdpt_idx] |= PAGE_USER;
        } else {
            // Create new entry with USER bit
            uint64_t new_pd = alloc_page();
            memset((void*)new_pd, 0, PAGE_SIZE);
            pdpt[pdpt_idx] = new_pd | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
        }
        
        // Access PD
        uint64_t* pd = (uint64_t*)(pdpt[pdpt_idx] & ~0xFFF);
        
        // Map 2MB page directly in PD
        pd[pd_idx] = addr | PAGE_PRESENT | PAGE_WRITE | PAGE_USER | PAGE_SIZE_2MB;
        
        // Progress indicator every 64MB
        if (((addr - MFS_REGION_START) % (64 * 1024 * 1024)) == 0) {
            print("MFS: Mapped ");
            uint64_to_hex((addr - MFS_REGION_START) / (1024 * 1024), count_str);
            print(count_str);
            println("MB");
        }
    }
    
    // Flush entire TLB to activate all mappings
    __asm__ volatile("mov %%cr3, %%rax; mov %%rax, %%cr3" ::: "rax", "memory");
    
    println("MFS: Massive block mapping completed");
    
    // Validate the mapping worked by testing key addresses
    println("MFS: Validating massive block mapping");
    
    // Test start of region
    volatile uint8_t* test_start = (volatile uint8_t*)MFS_REGION_START;
    *test_start = 0xAA;
    if (*test_start != 0xAA) {
        println("MFS: ERROR - Start of region not accessible");
        return -1;
    }
    *test_start = 0;
    
    // Test middle of region
    volatile uint8_t* test_middle = (volatile uint8_t*)(MFS_REGION_START + (total_size / 2));
    *test_middle = 0xBB;
    if (*test_middle != 0xBB) {
        println("MFS: ERROR - Middle of region not accessible");
        return -1;
    }
    *test_middle = 0;
    
    // Test near end of region (leave some safety margin)
    volatile uint8_t* test_end = (volatile uint8_t*)(MFS_REGION_END - 0x1000);
    *test_end = 0xCC;
    if (*test_end != 0xCC) {
        println("MFS: ERROR - End of region not accessible");
        return -1;
    }
    *test_end = 0;
    
    println("MFS: Massive block validation PASSED");
    
    return 0;
}

// FIXED: Find free entry in entry table with proper validation

mfs_entry_t *mfs_alloc_entry (void) {
    println("MFS: Allocating entry with validation");
    
    if (!mfs_sb.initialized) {
        println("MFS: ERROR - MFS not initialized");
        return NULL;
    }
    
    if (!mfs_sb.entry_table) {
        println("MFS: ERROR - Entry table not initialized");
        return NULL;
    }
    
    // Validate entry table pointer is in MFS region
    if ((uint64_t)mfs_sb.entry_table < MFS_REGION_START || 
        (uint64_t)mfs_sb.entry_table >= MFS_REGION_END) {
        println("MFS: ERROR - Entry table outside MFS region");
        return NULL;
    }
    
    // Use volatile access to prevent optimization issues
    volatile mfs_entry_t* entry_table = (volatile mfs_entry_t*)mfs_sb.entry_table;
    
    for (int i = 1; i < MFS_MAX_ENTRIES; i++) { // Skip root at index 0
        // Validate entry address is within bounds
        uint64_t entry_addr = (uint64_t)&entry_table[i];
        if (entry_addr + sizeof(mfs_entry_t) > MFS_REGION_END) {
            println("MFS: ERROR - Entry would exceed MFS region");
            return NULL;
        }
        
        // Check if entry is free using volatile access
        if (entry_table[i].type == MFS_TYPE_FREE) {
            // Mark as allocated and set magic
            entry_table[i].magic = MFS_MAGIC;
            entry_table[i].type = MFS_TYPE_SEGMENT; // Will be overridden by caller
            
            println("MFS: Entry allocated successfully");
            return (mfs_entry_t*)&entry_table[i];
        }
    }
    
    println("MFS: ERROR - No free entries available");
    return NULL;
}

// FIXED: Free entry in entry table with comprehensive validation
void mfs_free_entry(mfs_entry_t* entry) {
    println("MFS: Freeing entry with validation");
    
    if (!entry) {
        println("MFS: ERROR - NULL entry pointer for free");
        return;
    }
    
    // Validate entry is in MFS region
    if ((uint64_t)entry < MFS_REGION_START || (uint64_t)entry >= MFS_REGION_END) {
        println("MFS: ERROR - Entry to free outside MFS region");
        return;
    }
    
    // Use volatile access to prevent optimization issues
    volatile mfs_entry_t* safe_entry = (volatile mfs_entry_t*)entry;
    
    // Validate entry magic before freeing
    if (safe_entry->magic != MFS_MAGIC) {
        println("MFS: ERROR - Invalid entry magic for free");
        return;
    }
    
    // Validate entry is allocated
    if (safe_entry->type == MFS_TYPE_FREE) {
        println("MFS: ERROR - Entry already free");
        return;
    }
    
    println("MFS: Entry free validation PASSED");
    
    // If it's a segment, clear its data
    if (safe_entry->type == MFS_TYPE_SEGMENT && safe_entry->start_addr != 0) {
        println("MFS: Clearing segment data");
        
        // Validate data address and size
        if (safe_entry->start_addr >= MFS_REGION_START && 
            safe_entry->start_addr < MFS_REGION_END &&
            safe_entry->size > 0 &&
            safe_entry->start_addr + safe_entry->size <= MFS_REGION_END) {
            
            // Clear segment data with poison
            volatile uint8_t* data_ptr = (volatile uint8_t*)safe_entry->start_addr;
            for (size_t i = 0; i < safe_entry->size; i++) {
                data_ptr[i] = 0xDD; // Poison value
                
                // Memory barrier every 1KB
                if ((i % 1024) == 0) {
                    __asm__ volatile("" ::: "memory");
                }
            }
            
            println("MFS: Segment data cleared");
        }
    }
    
    // Clear entry fields with memory barriers
    safe_entry->magic = 0;
    __asm__ volatile("" ::: "memory");
    
    safe_entry->type = MFS_TYPE_FREE;
    __asm__ volatile("" ::: "memory");
    
    safe_entry->name[0] = '\0';
    __asm__ volatile("" ::: "memory");
    
    safe_entry->start_addr = 0;
    __asm__ volatile("" ::: "memory");
    
    safe_entry->size = 0;
    __asm__ volatile("" ::: "memory");
    
    safe_entry->blocks_used = 0;
    __asm__ volatile("" ::: "memory");
    
    safe_entry->permissions = 0;
    __asm__ volatile("" ::: "memory");
    
    safe_entry->ref_count = 0;
    __asm__ volatile("" ::: "memory");
    
    safe_entry->parent = NULL;
    __asm__ volatile("" ::: "memory");
    
    safe_entry->next = NULL;
    __asm__ volatile("" ::: "memory");
    
    safe_entry->children = NULL;
    __asm__ volatile("" ::: "memory");
    
    println("MFS: Entry freed successfully");
}

// Add this helper function to safely remove entries from parent's children list
void mfs_safe_remove_from_parent(mfs_entry_t* entry) {
    if (!entry || !entry->parent) {
        return;
    }
    
    volatile mfs_entry_t* parent = (volatile mfs_entry_t*)entry->parent;
    
    // If this entry is the first child
    if (parent->children == entry) {
        parent->children = entry->next;
        __asm__ volatile("" ::: "memory");
        return;
    }
    
    // Find the entry in the children list and remove it
    mfs_entry_t* current = (mfs_entry_t*)parent->children;
    while (current && current->next != entry) {
        current = current->next;
    }
    
    if (current) {
        current->next = entry->next;
        __asm__ volatile("" ::: "memory");
    }
}

// FIXED: Allocate blocks in MFS region with proper validation
uint64_t mfs_alloc_blocks(size_t size) {
    println("MFS: Allocating blocks with validation");
    
    if (!mfs_sb.initialized) {
        println("MFS: ERROR - MFS not initialized for block allocation");
        return 0;
    }
    
    if (size == 0) {
        println("MFS: ERROR - Zero size block allocation");
        return 0;
    }
    
    // Align size to block boundary
    size_t aligned_size = (size + MFS_BLOCK_SIZE - 1) & ~(MFS_BLOCK_SIZE - 1);
    size_t blocks_needed = aligned_size / MFS_BLOCK_SIZE;
    
    print("MFS: Need ");
    char count_str[8];
    uint64_to_hex(blocks_needed, count_str);
    print(count_str);
    println(" blocks");
    
    // Use volatile access to superblock
    volatile mfs_superblock_t* sb = &mfs_sb;
    
    if (sb->free_blocks < blocks_needed) {
        println("MFS: ERROR - Not enough free blocks");
        return 0;
    }
    
    if (sb->next_free_addr + aligned_size > MFS_REGION_END) {
        println("MFS: ERROR - Would exceed MFS region");
        return 0;
    }
    
    // Validate next_free_addr is in MFS region
    if (sb->next_free_addr < MFS_REGION_START || sb->next_free_addr >= MFS_REGION_END) {
        println("MFS: ERROR - Next free address outside MFS region");
        return 0;
    }
    
    uint64_t alloc_addr = sb->next_free_addr;
    
    print("MFS: Allocating at address: 0x");
    uint64_to_hex(alloc_addr, count_str);
    println(count_str);
    
    // Update allocation tracking with memory barriers
    sb->next_free_addr += aligned_size;
    __asm__ volatile("" ::: "memory");
    
    sb->free_blocks -= blocks_needed;
    __asm__ volatile("" ::: "memory");
    
    sb->used_blocks += blocks_needed;
    __asm__ volatile("" ::: "memory");
    
    // Clear allocated blocks with safe access
    println("MFS: Clearing allocated blocks");
    volatile uint8_t* clear_ptr = (volatile uint8_t*)alloc_addr;
    
    for (size_t i = 0; i < aligned_size; i++) {
        clear_ptr[i] = 0;
        
        // Memory barrier every 1KB to prevent issues
        if ((i % 1024) == 0) {
            __asm__ volatile("" ::: "memory");
        }
    }
    
    println("MFS: Blocks allocated and cleared successfully");
    
    return alloc_addr;
}

mfs_entry_t* mfs_find(const char* name, mfs_entry_t* dir);

// FIXED: Create directory with comprehensive validation (matching mfs_seg robustness)
mfs_entry_t* mfs_dir(const char* name, mfs_entry_t* parent) {
    println("MFS: Creating directory with validation");
    
    if (!mfs_sb.initialized) {
        println("MFS: ERROR - MFS not initialized");
        return NULL;
    }
    
    if (!name || !parent) {
        println("MFS: ERROR - Invalid parameters for directory creation");
        return NULL;
    }
    
    // Validate parent is a directory
    volatile mfs_entry_t* safe_parent = (volatile mfs_entry_t*)parent;
    if (safe_parent->type != MFS_TYPE_DIR) {
        println("MFS: ERROR - Parent is not a directory");
        return NULL;
    }
    
    if (safe_parent->magic != MFS_MAGIC) {
        println("MFS: ERROR - Parent has invalid magic");
        return NULL;
    }
    
    // Validate parent pointer is in MFS region
    if ((uint64_t)parent < MFS_REGION_START || (uint64_t)parent >= MFS_REGION_END) {
        println("MFS: ERROR - Parent pointer outside MFS region");
        return NULL;
    }
    
    // Validate name length
    int name_len = 0;
    while (name[name_len] && name_len < MFS_MAX_NAME_LEN - 1) {
        name_len++;
    }
    
    if (name_len == 0) {
        println("MFS: ERROR - Empty directory name");
        return NULL;
    }
    
    // Check for invalid characters in name
    for (int i = 0; i < name_len; i++) {
        char c = name[i];
        if (c == '/' || c == '\\' || c == '\0' || c < 32 || c > 126) {
            println("MFS: ERROR - Invalid character in directory name");
            return NULL;
        }
    }
    
    println("MFS: Directory parameters validated");
    
    // Check if directory already exists in parent
    mfs_entry_t* existing = mfs_find(name, parent);
    if (existing) {
        println("MFS: ERROR - Directory already exists");
        return NULL;
    }
    
    println("MFS: Directory name uniqueness validated");
    
    // Allocate entry with validation
    mfs_entry_t* dir_entry = mfs_alloc_entry();
    if (!dir_entry) {
        println("MFS: ERROR - Failed to allocate entry for directory");
        return NULL;
    }
    
    // Validate allocated entry is in MFS region
    if ((uint64_t)dir_entry < MFS_REGION_START || (uint64_t)dir_entry >= MFS_REGION_END) {
        println("MFS: ERROR - Allocated entry outside MFS region");
        dir_entry->type = MFS_TYPE_FREE;
        dir_entry->magic = 0;
        return NULL;
    }
    
    println("MFS: Entry allocated for directory");
    
    // Initialize directory entry with volatile access and validation
    volatile mfs_entry_t* safe_dir = (volatile mfs_entry_t*)dir_entry;
    
    // Set type first
    safe_dir->type = MFS_TYPE_DIR;
    __asm__ volatile("" ::: "memory");
    
    // Copy name safely with bounds checking
    for (int i = 0; i < name_len; i++) {
        safe_dir->name[i] = name[i];
    }
    safe_dir->name[name_len] = '\0';
    __asm__ volatile("" ::: "memory");
    
    // Validate name was copied correctly
    int name_valid = 1;
    for (int i = 0; i < name_len; i++) {
        if (safe_dir->name[i] != name[i]) {
            name_valid = 0;
            break;
        }
    }
    if (!name_valid || safe_dir->name[name_len] != '\0') {
        println("MFS: ERROR - Name copy validation failed");
        safe_dir->type = MFS_TYPE_FREE;
        safe_dir->magic = 0;
        return NULL;
    }
    
    // Set directory-specific fields
    safe_dir->start_addr = 0;  // Directories don't have data blocks
    __asm__ volatile("" ::: "memory");
    
    safe_dir->size = 0;  // Directories don't have size
    __asm__ volatile("" ::: "memory");
    
    safe_dir->blocks_used = 0;  // Directories don't use data blocks
    __asm__ volatile("" ::: "memory");
    
    safe_dir->permissions = 0755;  // Standard directory permissions
    __asm__ volatile("" ::: "memory");
    
    safe_dir->ref_count = 1;
    __asm__ volatile("" ::: "memory");
    
    safe_dir->parent = parent;
    __asm__ volatile("" ::: "memory");
    
    // Add to parent's children list (atomic operation)
    safe_dir->next = safe_parent->children;
    __asm__ volatile("" ::: "memory");
    
    safe_dir->children = NULL;  // New directory has no children
    __asm__ volatile("" ::: "memory");
    
    // Atomically update parent's children list
    safe_parent->children = dir_entry;
    __asm__ volatile("" ::: "memory");
    
    // Final validation of the created directory
    if (safe_dir->type != MFS_TYPE_DIR) {
        println("MFS: ERROR - Directory type validation failed");
        return NULL;
    }
    
    if (safe_dir->magic != MFS_MAGIC) {
        println("MFS: ERROR - Directory magic validation failed");
        return NULL;
    }
    
    if (safe_dir->parent != parent) {
        println("MFS: ERROR - Directory parent validation failed");
        return NULL;
    }
    
    // Validate the directory can be found in parent
    mfs_entry_t* validation_find = mfs_find(name, parent);
    if (validation_find != dir_entry) {
        println("MFS: ERROR - Directory not found in parent after creation");
        return NULL;
    }
    
    println("MFS: Directory created and validated successfully");
    return dir_entry;
}

// FIXED: Create segment with comprehensive validation
mfs_entry_t* mfs_seg(const char* name, size_t size, mfs_entry_t* parent) {
    println("MFS: Creating segment with validation");
    
    if (!mfs_sb.initialized) {
        println("MFS: ERROR - MFS not initialized");
        return NULL;
    }
    
    if (!name || !parent || size == 0) {
        println("MFS: ERROR - Invalid parameters for segment creation");
        return NULL;
    }
    
    if (size > 16 * 1024 * 1024) {
        println("MFS: ERROR - Segment size too large");
        return NULL;
    }
    
    // Validate parent is a directory
    volatile mfs_entry_t* safe_parent = (volatile mfs_entry_t*)parent;
    if (safe_parent->type != MFS_TYPE_DIR) {
        println("MFS: ERROR - Parent is not a directory");
        return NULL;
    }
    
    if (safe_parent->magic != MFS_MAGIC) {
        println("MFS: ERROR - Parent has invalid magic");
        return NULL;
    }
    
    // Validate name length
    int name_len = 0;
    while (name[name_len] && name_len < MFS_MAX_NAME_LEN - 1) {
        name_len++;
    }
    
    if (name_len == 0) {
        println("MFS: ERROR - Empty segment name");
        return NULL;
    }
    
    println("MFS: Segment parameters validated");
    
    // Allocate entry with validation
    mfs_entry_t* seg_entry = mfs_alloc_entry();
    if (!seg_entry) {
        println("MFS: ERROR - Failed to allocate entry");
        return NULL;
    }
    
    println("MFS: Entry allocated for segment");
    
    // Allocate blocks for segment with validation
    uint64_t seg_addr = mfs_alloc_blocks(size);
    if (seg_addr == 0) {
        println("MFS: ERROR - Failed to allocate blocks for segment");
        // Free the entry
        seg_entry->type = MFS_TYPE_FREE;
        seg_entry->magic = 0;
        return NULL;
    }
    
    println("MFS: Blocks allocated for segment");
    
    // Initialize segment entry with volatile access
    volatile mfs_entry_t* safe_seg = (volatile mfs_entry_t*)seg_entry;
    
    safe_seg->type = MFS_TYPE_SEGMENT;
    __asm__ volatile("" ::: "memory");
    
    // Copy name safely
    for (int i = 0; i < name_len; i++) {
        safe_seg->name[i] = name[i];
    }
    safe_seg->name[name_len] = '\0';
    __asm__ volatile("" ::: "memory");
    
    safe_seg->start_addr = seg_addr;
    __asm__ volatile("" ::: "memory");
    
    safe_seg->size = size;
    __asm__ volatile("" ::: "memory");
    
    safe_seg->blocks_used = (size + MFS_BLOCK_SIZE - 1) / MFS_BLOCK_SIZE;
    __asm__ volatile("" ::: "memory");
    
    safe_seg->permissions = 0644;
    __asm__ volatile("" ::: "memory");
    
    safe_seg->ref_count = 1;
    __asm__ volatile("" ::: "memory");
    
    safe_seg->parent = parent;
    __asm__ volatile("" ::: "memory");
    
    safe_seg->next = safe_parent->children;
    __asm__ volatile("" ::: "memory");
    
    safe_seg->children = NULL;
    __asm__ volatile("" ::: "memory");
    
    // Add to parent's children list
    safe_parent->children = seg_entry;
    __asm__ volatile("" ::: "memory");
    
    println("MFS: Segment created successfully");
    return seg_entry;
}

// Create MFS segment at specific address
mfs_entry_t* mfs_seg_at(const char* name, size_t size, uint64_t specific_addr, mfs_entry_t* parent) {
    println("MFS: Creating segment at specific address");
    
    if (!name || size == 0 || !parent) {
        println("MFS: ERROR - Invalid parameters for mfs_seg_at");
        return NULL;
    }
    
    // Validate specific address is in MFS region
    if (specific_addr < MFS_REGION_START || specific_addr >= MFS_REGION_END) {
        println("MFS: ERROR - Specific address outside MFS region");
        return NULL;
    }
    
    // Validate address alignment (4KB aligned)
    if (specific_addr & 0xFFF) {
        println("MFS: ERROR - Address not 4KB aligned");
        return NULL;
    }
    
    // Check if address range is free
    if (specific_addr + size > MFS_REGION_END) {
        println("MFS: ERROR - Segment would exceed MFS region");
        return NULL;
    }
    
    // TODO: Check if address range conflicts with existing segments
    
    // Allocate entry from entry table
    mfs_entry_t* entry = mfs_alloc_entry();
    if (!entry) {
        println("MFS: ERROR - Cannot allocate entry");
        return NULL;
    }
    
    // Initialize entry
    entry->magic = MFS_MAGIC;
    entry->type = MFS_TYPE_SEGMENT;
    entry->start_addr = specific_addr;  // Use specific address
    entry->size = size;
    entry->parent = (uint64_t)parent;
    
    // Copy name
    int i = 0;
    while (name[i] && i < MFS_MAX_NAME_LEN - 1) {
        entry->name[i] = name[i];
        i++;
    }
    entry->name[i] = '\0';
    
    // Clear the memory at specific address
    volatile uint8_t* segment_data = (volatile uint8_t*)specific_addr;
    for (size_t j = 0; j < size; j++) {
        segment_data[j] = 0;
    }
    
    print("MFS: Created segment at specific address ");
    char addr_str[16];
    uint64_to_hex(specific_addr, addr_str);
    println(addr_str);
    
    return entry;
}

// Helper function to find MFS segment containing an address
mfs_entry_t* find_segment_by_address(uint64_t addr) {
    mfs_entry_t* entry_table = (mfs_entry_t*)mfs_sb.entry_table;
    
    for (int i = 0; i < MFS_MAX_ENTRIES; i++) {
        if (entry_table[i].magic == MFS_MAGIC && 
            entry_table[i].type == MFS_TYPE_SEGMENT &&
            addr >= entry_table[i].start_addr &&
            addr < entry_table[i].start_addr + entry_table[i].size) {
            return &entry_table[i];
        }
    }
    return NULL;
}

// Complete MFS cleanup - removes ALL entries and directories
void mfs_cleanup_all (void) {
    println("MFS_CLEANUP: Starting complete MFS cleanup");
    
    if (!mfs_sb.initialized) {
        println("MFS_CLEANUP: MFS not initialized");
        return;
    }
    
    volatile mfs_superblock_t* sb = &mfs_sb;
    volatile mfs_entry_t* entry_table = (volatile mfs_entry_t*)sb->entry_table;
    
    // Clear all entries except root (index 0)
    for (int i = 1; i < MFS_MAX_ENTRIES; i++) {
        if (entry_table[i].type != MFS_TYPE_FREE) {
            // Clear segment data if it's a segment
            if (entry_table[i].type == MFS_TYPE_SEGMENT && entry_table[i].start_addr != 0) {
                volatile uint8_t* data_ptr = (volatile uint8_t*)entry_table[i].start_addr;
                for (size_t j = 0; j < entry_table[i].size; j++) {
                    data_ptr[j] = 0xDD; // Poison
                }
            }
            
            // Clear entry
            entry_table[i].magic = 0;
            entry_table[i].type = MFS_TYPE_FREE;
            entry_table[i].name[0] = '\0';
            entry_table[i].start_addr = 0;
            entry_table[i].size = 0;
            entry_table[i].blocks_used = 0;
            entry_table[i].permissions = 0;
            entry_table[i].ref_count = 0;
            entry_table[i].parent = NULL;
            entry_table[i].next = NULL;
            entry_table[i].children = NULL;
        }
    }
    
    // Reset root directory to clean state
    volatile mfs_entry_t* root = (volatile mfs_entry_t*)sb->root_dir;
    root->children = NULL; // Remove all children
    root->ref_count = 1;
    
    // Reset superblock counters
    sb->free_blocks = sb->total_size / MFS_BLOCK_SIZE;
    sb->used_blocks = 0;
    sb->next_free_addr = MFS_REGION_START + (MFS_MAX_ENTRIES * sizeof(mfs_entry_t));
    sb->next_free_addr = (sb->next_free_addr + MFS_BLOCK_SIZE - 1) & ~(MFS_BLOCK_SIZE - 1);
    
    __asm__ volatile("" ::: "memory");
    
    println("MFS_CLEANUP: Complete cleanup finished - MFS reset to initial state");
}

// FIXED: Get segment data pointer with safe return
void* mfs_get_data(mfs_entry_t* entry) {
    println("MFS: Getting segment data with validation");
    
    if (!entry) {
        println("MFS: ERROR - NULL entry pointer");
        return NULL;
    }
    
    // Validate entry is in MFS region
    if ((uint64_t)entry < MFS_REGION_START || (uint64_t)entry >= MFS_REGION_END) {
        println("MFS: ERROR - Entry pointer outside MFS region");
        return NULL;
    }
    
    // Use volatile access to prevent optimization issues
    volatile mfs_entry_t* safe_entry = (volatile mfs_entry_t*)entry;
    
    // Validate entry magic
    if (safe_entry->magic != MFS_MAGIC) {
        println("MFS: ERROR - Invalid entry magic");
        return NULL;
    }
    
    // Validate entry type
    if (safe_entry->type != MFS_TYPE_SEGMENT) {
        println("MFS: ERROR - Entry is not a segment");
        return NULL;
    }
    
    // Validate start address
    if (safe_entry->start_addr == 0) {
        println("MFS: ERROR - Segment has no data address");
        return NULL;
    }
    
    // Validate start address is in MFS region
    if (safe_entry->start_addr < MFS_REGION_START || safe_entry->start_addr >= MFS_REGION_END) {
        println("MFS: ERROR - Segment data address outside MFS region");
        return NULL;
    }
    
    // Validate size
    if (safe_entry->size == 0) {
        println("MFS: ERROR - Segment has zero size");
        return NULL;
    }
    
    // Validate data doesn't exceed MFS region
    if (safe_entry->start_addr + safe_entry->size > MFS_REGION_END) {
        println("MFS: ERROR - Segment data exceeds MFS region");
        return NULL;
    }
    
    // Test data accessibility
    volatile uint8_t* test_ptr = (volatile uint8_t*)safe_entry->start_addr;
    uint8_t test_byte = *test_ptr;
    *test_ptr = test_byte; // Write back to test write access
    
    println("MFS: Segment data validation PASSED");
    
    // FIXED: Safe return without volatile cast issues
    uint64_t data_addr = safe_entry->start_addr;
    __asm__ volatile("" ::: "memory"); // Memory barrier
    
    return (void*)data_addr;
}

// FIXED: Get segment size with comprehensive validation
size_t mfs_get_size(mfs_entry_t* entry) {
    println("MFS: Getting segment size with validation");
    
    if (!entry) {
        println("MFS: ERROR - NULL entry pointer");
        return 0;
    }
    
    // Validate entry is in MFS region
    if ((uint64_t)entry < MFS_REGION_START || (uint64_t)entry >= MFS_REGION_END) {
        println("MFS: ERROR - Entry pointer outside MFS region");
        return 0;
    }
    
    // Use volatile access to prevent optimization issues
    volatile mfs_entry_t* safe_entry = (volatile mfs_entry_t*)entry;
    
    // Validate entry magic
    if (safe_entry->magic != MFS_MAGIC) {
        println("MFS: ERROR - Invalid entry magic");
        return 0;
    }
    
    // Validate entry type
    if (safe_entry->type != MFS_TYPE_SEGMENT) {
        println("MFS: ERROR - Entry is not a segment");
        return 0;
    }
    
    // Validate size is reasonable
    if (safe_entry->size == 0 || safe_entry->size > 16 * 1024 * 1024) {
        println("MFS: ERROR - Invalid segment size");
        return 0;
    }
    
    println("MFS: Segment size validation PASSED");
    return safe_entry->size;
}

// FIXED: Find entry by name in directory with comprehensive validation
mfs_entry_t* mfs_find(const char* name, mfs_entry_t* dir) {
    
    if (!name || !dir) {
        println("MFS: ERROR - NULL parameters for find");
        return NULL;
    }
    
    // Validate directory is in MFS region
    if ((uint64_t)dir < MFS_REGION_START || (uint64_t)dir >= MFS_REGION_END) {
        println("MFS: ERROR - Directory pointer outside MFS region");
        return NULL;
    }
    
    // Use volatile access to prevent optimization issues
    volatile mfs_entry_t* safe_dir = (volatile mfs_entry_t*)dir;
    
    // Validate directory magic
    if (safe_dir->magic != MFS_MAGIC) {
        println("MFS: ERROR - Invalid directory magic");
        return NULL;
    }
    
    // Validate directory type
    if (safe_dir->type != MFS_TYPE_DIR) {
        println("MFS: ERROR - Entry is not a directory");
        return NULL;
    }
    
    // Validate name length
    int name_len = 0;
    while (name[name_len] && name_len < MFS_MAX_NAME_LEN) {
        name_len++;
    }
    
    if (name_len == 0) {
        println("MFS: ERROR - Empty search name");
        return NULL;
    }
    
    // Search through children with safe traversal
    mfs_entry_t* current = (mfs_entry_t*)safe_dir->children;
    int traversal_count = 0;
    
    while (current && traversal_count < MFS_MAX_ENTRIES) {
        // Validate current entry is in MFS region
        if ((uint64_t)current < MFS_REGION_START || (uint64_t)current >= MFS_REGION_END) {
            println("MFS: ERROR - Child entry outside MFS region");
            return NULL;
        }
        
        // Use volatile access for current entry
        volatile mfs_entry_t* safe_current = (volatile mfs_entry_t*)current;
        
        // Validate current entry magic
        if (safe_current->magic == MFS_MAGIC) {
            // Compare names safely
            int match = 1;
            for (int i = 0; i < name_len && i < MFS_MAX_NAME_LEN; i++) {
                if (safe_current->name[i] != name[i]) {
                    match = 0;
                    break;
                }
                if (safe_current->name[i] == '\0') {
                    break;
                }
            }
            
            // Check if name ends correctly
            if (match && safe_current->name[name_len] == '\0') {
                return current;
            }
        }
        
        // Move to next entry with validation
        mfs_entry_t* next = (mfs_entry_t*)safe_current->next;
        if (next && ((uint64_t)next < MFS_REGION_START || (uint64_t)next >= MFS_REGION_END)) {
            println("MFS: ERROR - Next entry pointer outside MFS region");
            return NULL;
        }
        
        current = next;
        traversal_count++;
    }
    
    println("MFS: Entry not found");
    return NULL;
}

// FIXED: Safe MFS write function with comprehensive validation
int mfs_write(mfs_entry_t* entry, size_t offset, const void* data, size_t size) {
    
    if (!entry || !data || size == 0) {
        println("MFS: ERROR - Invalid write parameters");
        return -1;
    }
    
    // Validate entry is in MFS region
    if ((uint64_t)entry < MFS_REGION_START || (uint64_t)entry >= MFS_REGION_END) {
        println("MFS: ERROR - Entry outside MFS region");
        return -1;
    }
    
    volatile mfs_entry_t* safe_entry = (volatile mfs_entry_t*)entry;
    
    // Validate entry
    if (safe_entry->magic != MFS_MAGIC || safe_entry->type != MFS_TYPE_SEGMENT) {
        println("MFS: ERROR - Invalid segment for write");
        return -1;
    }
    
    // Validate write bounds
    if (offset >= safe_entry->size || offset + size > safe_entry->size) {
        println("MFS: ERROR - Write would exceed segment bounds");
        return -1;
    }
    
    // Validate segment data address
    if (safe_entry->start_addr < MFS_REGION_START || safe_entry->start_addr >= MFS_REGION_END) {
        println("MFS: ERROR - Segment data address invalid");
        return -1;
    }
    
    // Calculate write address
    uint64_t write_addr = safe_entry->start_addr + offset;
    
    // Validate write address and range
    if (write_addr + size > MFS_REGION_END) {
        println("MFS: ERROR - Write would exceed MFS region");
        return -1;
    }
    
    // Perform safe write with validation
    volatile uint8_t* dest = (volatile uint8_t*)write_addr;
    const uint8_t* src = (const uint8_t*)data;
    
    for (size_t i = 0; i < size; i++) {
        dest[i] = src[i];
        
        // Memory barrier every 256 bytes
        if ((i % 256) == 0) {
            __asm__ volatile("" ::: "memory");
        }
    }
    
    // Final memory barrier
    __asm__ volatile("" ::: "memory");
    
    return 0;
}

// FIXED: Safe MFS read function with comprehensive validation
int mfs_read(mfs_entry_t* entry, size_t offset, void* data, size_t size) {
    
    if (!entry || !data || size == 0) {
        println("MFS: ERROR - Invalid read parameters");
        return -1;
    }
    
    // Validate entry is in MFS region
    if ((uint64_t)entry < MFS_REGION_START || (uint64_t)entry >= MFS_REGION_END) {
        println("MFS: ERROR - Entry outside MFS region");
        return -1;
    }
    
    volatile mfs_entry_t* safe_entry = (volatile mfs_entry_t*)entry;
    
    // Validate entry
    if (safe_entry->magic != MFS_MAGIC || safe_entry->type != MFS_TYPE_SEGMENT) {
        println("MFS: ERROR - Invalid segment for read");
        return -1;
    }
    
    // Validate read bounds
    if (offset >= safe_entry->size || offset + size > safe_entry->size) {
        println("MFS: ERROR - Read would exceed segment bounds");
        return -1;
    }
    
    // Validate segment data address
    if (safe_entry->start_addr < MFS_REGION_START || safe_entry->start_addr >= MFS_REGION_END) {
        println("MFS: ERROR - Segment data address invalid");
        return -1;
    }
    
    // Calculate read address
    uint64_t read_addr = safe_entry->start_addr + offset;
    
    // Validate read address and range
    if (read_addr + size > MFS_REGION_END) {
        println("MFS: ERROR - Read would exceed MFS region");
        return -1;
    }
    
    // Perform safe read with validation
    volatile uint8_t* src = (volatile uint8_t*)read_addr;
    uint8_t* dest = (uint8_t*)data;
    
    for (size_t i = 0; i < size; i++) {
        dest[i] = src[i];
        
        // Memory barrier every 256 bytes
        if ((i % 256) == 0) {
            __asm__ volatile("" ::: "memory");
        }
    }
    
    // Final memory barrier
    __asm__ volatile("" ::: "memory");

    return 0;
}

void* user_malloc(size_t size) {
    println("USER_MALLOC: Using MFS-based allocation");
    
    if (!mfs_sb.initialized) {
        if (mfs_init() != 0) {
            println("USER_MALLOC: ERROR - MFS initialization failed");
            return NULL;
        }
    }

	// Validate root directory exists
    if (!mfs_sb.root_dir) {
        println("USER_MALLOC: ERROR - Root directory not initialized");
        return NULL;
    }
    
    // Create unique segment name
    static int alloc_counter = 0;
    char seg_name[32];
    seg_name[0] = 'a';
    seg_name[1] = 'l';
    seg_name[2] = 'l';
    seg_name[3] = 'o';
    seg_name[4] = 'c';
    seg_name[5] = '_';
    
    // Convert counter to string
    int counter = alloc_counter++;
    int pos = 6;
    if (counter == 0) {
        seg_name[pos++] = '0';
    } else {
        char temp[16];
        int temp_pos = 0;
        while (counter > 0) {
            temp[temp_pos++] = '0' + (counter % 10);
            counter /= 10;
        }
        for (int i = temp_pos - 1; i >= 0; i--) {
            seg_name[pos++] = temp[i];
        }
    }
    seg_name[pos] = '\0';
    
    // Create segment
    mfs_entry_t* seg = mfs_seg(seg_name, size, mfs_sb.root_dir);
    if (!seg) {
        println("USER_MALLOC: ERROR - Failed to create segment");
        return NULL;
    }
    
    println("USER_MALLOC: MFS allocation successful");
    return mfs_get_data(seg);
}

// Replace user_free with MFS-based deallocation
void user_free(void* ptr) {
    println("USER_FREE: Using MFS-based deallocation");
    
    if (!ptr) return;
    
    // Find segment containing this pointer
    for (int i = 0; i < MFS_MAX_ENTRIES; i++) {
        mfs_entry_t* entry = &mfs_sb.entry_table[i];
        if (entry->type == MFS_TYPE_SEGMENT && 
            entry->magic == MFS_MAGIC &&
            entry->start_addr == (uint64_t)ptr) {
            
            // Clear segment data
            uint8_t* data = (uint8_t*)ptr;
            for (size_t j = 0; j < entry->size; j++) {
                data[j] = 0xDD; // Poison
            }
            
            mfs_safe_remove_from_parent(entry);
            mfs_free_entry(entry);
            
            println("USER_FREE: MFS deallocation successful");
            return;
        }
    }
    
    println("USER_FREE: WARNING - Pointer not found in MFS");
}

void debug_mfs_state_after_threading() {
    println("DEBUG: Checking MFS state after threading init");
    
    print("DEBUG: mfs_sb.initialized = ");
    print_decimal(mfs_sb.initialized);
    println("");
    
    print("DEBUG: mfs_sb.root_dir = ");
    char addr_str[16];
    uint64_to_hex((uint64_t)mfs_sb.root_dir, addr_str);
    println(addr_str);
    
    if (mfs_sb.root_dir) {
        print("DEBUG: root_dir->magic = ");
        uint64_to_hex(mfs_sb.root_dir->magic, addr_str);
        println(addr_str);
        
        print("DEBUG: root_dir->children = ");
        uint64_to_hex((uint64_t)mfs_sb.root_dir->children, addr_str);
        println(addr_str);
    }
}

