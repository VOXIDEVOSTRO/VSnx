#include "include.h"

/*==============================================================================================================
  STACK-SAFE MFS-BASED THREADING SYSTEM - PURE NAME-BASED ACCESS
================================================================================================================*/

// Helper function to find thread table in THREADS directory
mfs_entry_t * find_thread_table (void) {
    // First find the THREADS directory
    mfs_entry_t* threads_dir = mfs_find("THREADS", mfs_sb.root_dir);
    if (!threads_dir) {
        println("THREAD: ERROR - Cannot find THREADS directory");
        return NULL;
    }
    
    // Now find THREAD_TABLE inside THREADS directory
    mfs_entry_t* table_segment = mfs_find("THREAD_TABLE", threads_dir);
    if (!table_segment) {
        println("THREAD: ERROR - Cannot find THREAD_TABLE in THREADS directory");
        return NULL;
    }
    
    return table_segment;
}

// Read thread from MFS table by ID - FIXED PATH RESOLUTION
int read_thread(uint32_t thread_id, thread_control_block_t* thread_buffer) {
    if (thread_id >= 64 || !thread_buffer) {
        return -1;
    }
    
    // Find the thread table segment using proper path
    mfs_entry_t* table_segment = find_thread_table();
    if (!table_segment) {
        return -1;
    }
    
    // Calculate offset in the table segment
    size_t offset = thread_id * sizeof(thread_control_block_t);
    
    // Use correct MFS read function
    if (mfs_read(table_segment, offset, thread_buffer, sizeof(thread_control_block_t)) != 0) {
        println("THREAD: ERROR - Failed to read thread data");
        return -1;
    }
    
    return 0;
}

// Write thread to MFS table by ID - FIXED PATH RESOLUTION
int write_thread(uint32_t thread_id, const thread_control_block_t* thread_data) {
    if (thread_id >= 64 || !thread_data) {
        return -1;
    }
    
    // Find the thread table segment using proper path
    mfs_entry_t* table_segment = find_thread_table();
    if (!table_segment) {
        return -1;
    }
    
    // Calculate offset in the table segment
    size_t offset = thread_id * sizeof(thread_control_block_t);
    
    // Use correct MFS write function
    if (mfs_write(table_segment, offset, thread_data, sizeof(thread_control_block_t)) != 0) {
        println("THREAD: ERROR - Failed to write thread data");
        return -1;
    }
    
    return 0;
}

// Find thread ID by module name
uint32_t find_thread_by_name(const char* module_name) {
    mfs_entry_t* threads_dir = mfs_find("THREADS", mfs_sb.root_dir);
    if (!threads_dir) return 0;
    
    mfs_entry_t* thread_table = mfs_find("THREAD_TABLE", threads_dir);
    if (!thread_table) return 0;
    
    // Search thread table
    for (int i = 1; i < 64; i++) {
        thread_control_block_t thread;
        if (mfs_read(thread_table, i * sizeof(thread), &thread, sizeof(thread)) == 0) {
            if (thread.magic == 0x54485244 && strcmp(thread.name, module_name) == 0) {
                return i;
            }
        }
    }
    
    return 0;  // Not found
}

// Initialize threading system - NO LARGE STACK STRUCTURES
void init_threading_system (void) {
    println("THREAD: Initializing stack-safe MFS-based threading");
    
    // CRITICAL: Disable interrupts during initialization
    __asm__ volatile("cli");
    println("THREAD: Interrupts disabled for safe initialization");
    
    // Create threads directory
    mfs_entry_t* threads_dir = mfs_dir("THREADS", mfs_sb.root_dir);
    if (!threads_dir) {
        println("THREAD: ERROR - Failed to create threads directory");
        __asm__ volatile("sti");
        return;
    }
    
    // Create thread table in MFS
    size_t table_size = sizeof(thread_control_block_t) * 64;
    mfs_entry_t* table_segment = mfs_seg("THREAD_TABLE", table_size, threads_dir);
    if (!table_segment) {
        println("THREAD: ERROR - Failed to create thread table");
        __asm__ volatile("sti");
        return;
    }
    
    println("THREAD: Thread table segment created successfully");
    
    // CRITICAL: Initialize table using direct MFS writes - NO STACK STRUCTURES
    println("THREAD: Initializing table with zero bytes");
    
    // Clear entire table to zero using MFS write
    #define CHUNK_SIZE 64
	static uint8_t zero_block[CHUNK_SIZE] = {0};

	for (size_t i = 0; i < table_size; i += CHUNK_SIZE) {
	    size_t write_len = (table_size - i < CHUNK_SIZE) ? (table_size - i) : CHUNK_SIZE;

	    if (mfs_write(table_segment, i, zero_block, write_len) != 0) {
	        println("[MFS:CLEAR] ERROR at offset %lu → write fault");
	        return;
	    }
	}
    
    println("THREAD: Thread table zeroed successfully");
    
    // Create main thread entry using minimal stack usage
    println("THREAD: Creating main thread entry");
    
    // Write main thread fields one by one - NO LARGE STRUCTURES
    uint32_t magic = 0x54485244; // 'THRD'
    uint32_t thread_id = 0;
    uint32_t state = THREAD_STATE_RUNNING;
    uint32_t priority = 10;
    uint64_t time_slice = 1000;
    
    // Write main thread data directly to MFS
    size_t main_thread_offset = 0; // Thread 0
    
    if (mfs_write(table_segment, main_thread_offset + offsetof(thread_control_block_t, magic), &magic, sizeof(magic)) != 0 ||
        mfs_write(table_segment, main_thread_offset + offsetof(thread_control_block_t, thread_id), &thread_id, sizeof(thread_id)) != 0 ||
        mfs_write(table_segment, main_thread_offset + offsetof(thread_control_block_t, state), &state, sizeof(state)) != 0 ||
        mfs_write(table_segment, main_thread_offset + offsetof(thread_control_block_t, priority), &priority, sizeof(priority)) != 0 ||
        mfs_write(table_segment, main_thread_offset + offsetof(thread_control_block_t, time_slice), &time_slice, sizeof(time_slice)) != 0) {
        println("THREAD: ERROR - Failed to write main thread data");
        __asm__ volatile("sti");
        return;
    }
    
    // Write main thread name directly
    char main_name[5] = {'m', 'a', 'i', 'n', '\0'};
    if (mfs_write(table_segment, main_thread_offset + offsetof(thread_control_block_t, name), main_name, 5) != 0) {
        println("THREAD: ERROR - Failed to write main thread name");
        __asm__ volatile("sti");
        return;
    }
    
    // Get current CPU state using register variables
    uint64_t current_rsp, current_rbp, current_rflags;
    __asm__ volatile(
        "movq %%rsp, %0\n"
        "movq %%rbp, %1\n"
        "pushfq\n"
        "popq %2"
        : "=r"(current_rsp), "=r"(current_rbp), "=r"(current_rflags)
    );
    
    // Write CPU state directly to MFS
    if (mfs_write(table_segment, main_thread_offset + offsetof(thread_control_block_t, rsp), &current_rsp, sizeof(current_rsp)) != 0 ||
        mfs_write(table_segment, main_thread_offset + offsetof(thread_control_block_t, rbp), &current_rbp, sizeof(current_rbp)) != 0 ||
        mfs_write(table_segment, main_thread_offset + offsetof(thread_control_block_t, rflags), &current_rflags, sizeof(current_rflags)) != 0) {
        println("THREAD: ERROR - Failed to write main thread CPU state");
        __asm__ volatile("sti");
        return;
    }
    
    current_thread_id = 0;
    thread_count = 1;
    
    println("THREAD: Main thread created using direct MFS writes");
    println("THREAD: Stack-safe threading system initialized");
    
    // CRITICAL: Re-enable interrupts after initialization
    __asm__ volatile("sti");
    println("THREAD: Interrupts re-enabled after initialization");
}

// Create new thread - FIXED PATH RESOLUTION
uint32_t create_thread(const char* code_segment_name, const char* thread_name, uint32_t priority, uint32_t stack_size) {
    // CRITICAL: Disable interrupts during thread creation
    __asm__ volatile("cli");
    
    if (thread_count >= 64) {
        println("THREAD: ERROR - Maximum threads reached");
        __asm__ volatile("sti");
        return 0;
    }
    
    // Find thread table using proper path
    mfs_entry_t* table_segment = find_thread_table();
    if (!table_segment) {
        __asm__ volatile("sti");
        return 0;
    }
    
    // Find free slot by checking magic field only
    uint32_t thread_id = 0;
    for (int i = 1; i < 64; i++) {
        uint32_t test_magic;
        size_t magic_offset = i * sizeof(thread_control_block_t) + offsetof(thread_control_block_t, magic);
        
        if (mfs_read(table_segment, magic_offset, &test_magic, sizeof(test_magic)) == 0 && 
            test_magic != 0x54485244) {
            thread_id = i;
            break;
        }
    }
    
    if (thread_id == 0) {
        println("THREAD: ERROR - No free thread slots");
        __asm__ volatile("sti");
        return 0;
    }
    
    println("THREAD: Found free thread slot");
    
    // Calculate thread offset in table
    size_t thread_offset = thread_id * sizeof(thread_control_block_t);
    
    // Write thread fields directly to MFS - NO LARGE STRUCTURES
    uint32_t magic = 0x54485244;
    uint32_t state = THREAD_STATE_READY;
    uint64_t time_slice = 1000;
    uint64_t total_time = 0;
    uint64_t rflags = 0x202; // Enable interrupts
    uint64_t rip = 0; // Will be set when code segment is loaded
    
    // Write basic thread data
    if (mfs_write(table_segment, thread_offset + offsetof(thread_control_block_t, magic), &magic, sizeof(magic)) != 0 ||
        mfs_write(table_segment, thread_offset + offsetof(thread_control_block_t, thread_id), &thread_id, sizeof(thread_id)) != 0 ||
        mfs_write(table_segment, thread_offset + offsetof(thread_control_block_t, state), &state, sizeof(state)) != 0 ||
        mfs_write(table_segment, thread_offset + offsetof(thread_control_block_t, priority), &priority, sizeof(priority)) != 0 ||
        mfs_write(table_segment, thread_offset + offsetof(thread_control_block_t, time_slice), &time_slice, sizeof(time_slice)) != 0 ||
        mfs_write(table_segment, thread_offset + offsetof(thread_control_block_t, total_time), &total_time, sizeof(total_time)) != 0 ||
        mfs_write(table_segment, thread_offset + offsetof(thread_control_block_t, rflags), &rflags, sizeof(rflags)) != 0 ||
        mfs_write(table_segment, thread_offset + offsetof(thread_control_block_t, rip), &rip, sizeof(rip)) != 0 ||
        mfs_write(table_segment, thread_offset + offsetof(thread_control_block_t, stack_size), &stack_size, sizeof(stack_size)) != 0) {
        println("THREAD: ERROR - Failed to write thread basic data");
        __asm__ volatile("sti");
        return 0;
    }
    
    // Write thread name directly
    if (mfs_write(table_segment, thread_offset + offsetof(thread_control_block_t, name), thread_name, 32) != 0) {
        println("THREAD: ERROR - Failed to write thread name");
        __asm__ volatile("sti");
        return 0;
    }
    
    // Write code segment name directly
    if (mfs_write(table_segment, thread_offset + offsetof(thread_control_block_t, code_segment_name), code_segment_name, 32) != 0) {
        println("THREAD: ERROR - Failed to write code segment name");
        __asm__ volatile("sti");
        return 0;
    }
    
    // Create MFS-based stack segment name
    char stack_name[32];
    int pos = 0;
    
    // Build stack segment name
    for (int i = 0; thread_name[i] && pos < 25; i++) {
        stack_name[pos++] = thread_name[i];
    }
    stack_name[pos++] = '_'; stack_name[pos++] = 's'; stack_name[pos++] = 't'; 
    stack_name[pos++] = 'k'; stack_name[pos] = '\0';
    
    // Write stack segment name directly
    if (mfs_write(table_segment, thread_offset + offsetof(thread_control_block_t, stack_segment_name), stack_name, 32) != 0) {
        println("THREAD: ERROR - Failed to write stack segment name");
        __asm__ volatile("sti");
        return 0;
    }
    
    // Create stack segment in MFS
    mfs_entry_t* threads_dir = mfs_find("THREADS", mfs_sb.root_dir);
    if (!threads_dir) {
        println("THREAD: ERROR - Cannot find threads directory");
        __asm__ volatile("sti");
        return 0;
    }
    
    mfs_entry_t* stack_segment = mfs_seg(stack_name, stack_size, threads_dir);
    if (!stack_segment) {
        println("THREAD: ERROR - Failed to create thread stack");
        __asm__ volatile("sti");
        return 0;
    }
    
    // Set up thread stack pointer
    uint64_t thread_rsp = stack_segment->start_addr + stack_segment->size - 16;
	uint64_t thread_rbp = thread_rsp;
    
    // Write stack pointers directly
    if (mfs_write(table_segment, thread_offset + offsetof(thread_control_block_t, rsp), &thread_rsp, sizeof(thread_rsp)) != 0 ||
        mfs_write(table_segment, thread_offset + offsetof(thread_control_block_t, rbp), &thread_rbp, sizeof(thread_rbp)) != 0) {
        println("THREAD: ERROR - Failed to write thread stack pointers");
        __asm__ volatile("sti");
        return 0;
    }
    
    thread_count++;
    
    print("THREAD: Created thread ");
    char id_str[8];
    uint64_to_hex(thread_id, id_str);
    print(id_str);
    print(" (");
    print(thread_name);
    print(") with code segment: ");
    println(code_segment_name);

	// AUTO-REGISTER FOR PREEMPTIVE MULTITASKING
    if (preemptive_enabled && thread_id > 0 && thread_id < 64) {
        thread_states[thread_id].thread_id = thread_id;
        thread_states[thread_id].is_active = 1;
        
        print("PREEMPT: Auto-registered thread ");
        char id_str[8];
        uint64_to_hex(thread_id, id_str);
        print(id_str);
        print(" (");
        print(thread_name);
        println(") for preemptive execution");
    }
    
    // CRITICAL: Re-enable interrupts after thread creation
    __asm__ volatile("sti");
    
    return thread_id;
}

// Execute thread by loading its code segment
void execute_thread(uint32_t thread_id) {
    println("THREAD: Attempting to execute thread");
    
    // Read thread data
    thread_control_block_t thread_data;
    if (read_thread(thread_id, &thread_data) != 0) {
        println("THREAD: ERROR - Cannot read thread data");
        return;
    }
    
    print("THREAD: Executing thread: ");
    println(thread_data.name);
    
    print("THREAD: Code segment: ");
    println(thread_data.code_segment_name);
    
    // Find the code segment
    mfs_entry_t* threads_dir = mfs_find("THREADS", mfs_sb.root_dir);
    if (!threads_dir) {
        println("THREAD: ERROR - Cannot find threads directory");
        return;
    }
    
    mfs_entry_t* code_segment = mfs_find(thread_data.code_segment_name, threads_dir);
    if (!code_segment) {
        println("THREAD: ERROR - Cannot find code segment");
        return;
    }
    
    // Read function pointer from code segment
    uint64_t func_ptr;
    if (mfs_read(code_segment, 0, &func_ptr, sizeof(func_ptr)) != 0) {
        println("THREAD: ERROR - Cannot read function pointer");
        return;
    }
    
    print("THREAD: Function pointer: ");
    char ptr_str[16];
    uint64_to_hex(func_ptr, ptr_str);
    println(ptr_str);
    
    // Update thread state to running
    thread_data.state = THREAD_STATE_RUNNING;
    thread_data.rip = func_ptr;
    
    if (write_thread(thread_id, &thread_data) != 0) {
        println("THREAD: ERROR - Cannot update thread state");
        return;
    }
    
    // Switch to the thread
    current_thread_id = thread_id;
    
    println("THREAD: Switching to thread...");
    
    // Call the thread function directly (simplified approach)
    void (*thread_func)() = (void(*)())func_ptr;
    thread_func();
    
    println("THREAD: Thread execution completed");
}

// Real thread code that will be copied to MFS segment
const uint8_t real_thread_code[] = {
    0xB8, 0x01, 0x00, 0x00, 0x00,     // mov eax, 1      ; dummy value
    0x90,                             // nop             ; do nothing
    0x90,                             // nop             ; do nothing
    0xEB, 0xFE                        // jmp $           ; infinite loop
};

const char thread_message[] = "REAL THREAD!\n";

// Create REAL executable code segment
void create_thread_code_segment (void) {
    println("THREAD: Creating REAL executable code segment");
    
    mfs_entry_t* threads_dir = mfs_find("THREADS", mfs_sb.root_dir);
    if (!threads_dir) {
        println("THREAD: ERROR - Cannot find threads directory");
        return;
    }
    
    // Create code segment large enough for real code
    size_t code_size = 4096;
    mfs_entry_t* code_segment = mfs_seg("real_thread_code", code_size, threads_dir);
    if (!code_segment) {
        println("THREAD: ERROR - Failed to create code segment");
        return;
    }
    
    println("THREAD: Writing real machine code to segment");
    
    // Write the real machine code
    if (mfs_write(code_segment, 0, real_thread_code, sizeof(real_thread_code)) != 0) {
        println("THREAD: ERROR - Failed to write machine code");
        return;
    }
    
    // Write the message string after the code
    size_t message_offset = 256; // Place message at offset 256
    if (mfs_write(code_segment, message_offset, thread_message, sizeof(thread_message)) != 0) {
        println("THREAD: ERROR - Failed to write message");
        return;
    }
    
    print("THREAD: Real code segment created at: ");
    char addr_str[16];
    uint64_to_hex(code_segment->start_addr, addr_str);
    println(addr_str);
    
    println("THREAD: Real executable code segment created successfully");
}

// Add page table inspection function
void dump_page_permissions(uint64_t virt_addr) {
    print("PAGE_DEBUG: Checking permissions for address ");
    char addr_str[16];
    uint64_to_hex(virt_addr, addr_str);
    println(addr_str);
    
    // Get current CR3
    uint64_t cr3;
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    
    uint64_t* pml4 = (uint64_t*)(cr3 & ~0xFFF);
    uint64_t pml4_idx = (virt_addr >> 39) & 0x1FF;
    uint64_t pdpt_idx = (virt_addr >> 30) & 0x1FF;
    uint64_t pd_idx = (virt_addr >> 21) & 0x1FF;
    
    print("PAGE_DEBUG: PML4[");
    uint64_to_hex(pml4_idx, addr_str);
    print(addr_str);
    print("] = ");
    uint64_to_hex(pml4[pml4_idx], addr_str);
    print(addr_str);
    
    if (pml4[pml4_idx] & PAGE_USER) {
        print(" [USER]");
    } else {
        print(" [KERNEL]");
    }
    println("");
    
    if (!(pml4[pml4_idx] & PAGE_PRESENT)) {
        println("PAGE_DEBUG: PML4 entry not present!");
        return;
    }
    
    uint64_t* pdpt = (uint64_t*)(pml4[pml4_idx] & ~0xFFF);
    print("PAGE_DEBUG: PDPT[");
    uint64_to_hex(pdpt_idx, addr_str);
    print(addr_str);
    print("] = ");
    uint64_to_hex(pdpt[pdpt_idx], addr_str);
    print(addr_str);
    
    if (pdpt[pdpt_idx] & PAGE_USER) {
        print(" [USER]");
    } else {
        print(" [KERNEL]");
    }
    println("");
    
    if (!(pdpt[pdpt_idx] & PAGE_PRESENT)) {
        println("PAGE_DEBUG: PDPT entry not present!");
        return;
    }
    
    uint64_t* pd = (uint64_t*)(pdpt[pdpt_idx] & ~0xFFF);
    print("PAGE_DEBUG: PD[");
    uint64_to_hex(pd_idx, addr_str);
    print(addr_str);
    print("] = ");
    uint64_to_hex(pd[pd_idx], addr_str);
    print(addr_str);
    
    if (pd[pd_idx] & PAGE_USER) {
        print(" [USER]");
    } else {
        print(" [KERNEL]");
    }
    
    if (pd[pd_idx] & PAGE_SIZE_2MB) {
        print(" [2MB_PAGE]");
    }
    println("");
}

void dump_gdt_info (void) {
    println("GDT_DEBUG: Checking GDT setup");
    
    // Get the current GDT
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) gdtr;
    
    __asm__ volatile("sgdt %0" : "=m"(gdtr));
    
    print("GDT_DEBUG: GDT Base: ");
    char addr_str[16];
    uint64_to_hex(gdtr.base, addr_str);
    println(addr_str);
    
    print("GDT_DEBUG: GDT Limit: ");
    uint64_to_hex(gdtr.limit, addr_str);
    println(addr_str);
    
    // Read from the actual loaded GDT
    struct gdt_entry {
        uint16_t limit_low;
        uint16_t base_low;
        uint8_t base_middle;
        uint8_t access;
        uint8_t granularity;
        uint8_t base_high;
    } __attribute__((packed));
    
    struct gdt_entry* actual_gdt = (struct gdt_entry*)gdtr.base;
    
    // Check the actual GDT entries
    for (int i = 0; i < 5; i++) {
        print("GDT_DEBUG: Entry ");
        char idx_str[2] = {'0' + i, '\0'};
        print(idx_str);
        print(" - Access: ");
        char access_str[4];
        uint64_to_hex(actual_gdt[i].access, access_str);
        print(access_str);
        print(" Gran: ");
        uint64_to_hex(actual_gdt[i].granularity, access_str);
        println(access_str);
    }
    
    // Check segment selectors
    uint16_t cs, ds, ss;
    __asm__ volatile(
        "movw %%cs, %0\n"
        "movw %%ds, %1\n"
        "movw %%ss, %2"
        : "=r"(cs), "=r"(ds), "=r"(ss)
    );
    
    print("GDT_DEBUG: Current CS=");
    char seg_str[8];
    uint64_to_hex(cs, seg_str);
    print(seg_str);
    print(" DS=");
    uint64_to_hex(ds, seg_str);
    print(seg_str);
    print(" SS=");
    uint64_to_hex(ss, seg_str);
    println(seg_str);
    
    // Calculate Ring 3 selectors
    print("GDT_DEBUG: Ring 3 Code should be: ");
    uint64_to_hex(0x18 | 3, seg_str);
    print(seg_str);
    print(" (");
    uint64_to_hex(0x1B, seg_str);
    print(seg_str);
    println(")");
    
    print("GDT_DEBUG: Ring 3 Data should be: ");
    uint64_to_hex(0x20 | 3, seg_str);
    print(seg_str);
    print(" (");
    uint64_to_hex(0x23, seg_str);
    print(seg_str);
    println(")");
}

// REAL OS-LEVEL CONTEXT SWITCH USING ROBUST SAVE/RESTORE FUNCTIONS
void real_context_switch(uint32_t thread_id, interrupt_frame_t* frame) {
    println("THREAD: Performing context switch using robust save/restore");
    
    // UPDATE CURRENT THREAD ID
    current_thread_id = thread_id;
    
    print("THREAD: Switching to thread ");
    char id_str[8];
    uint64_to_hex(thread_id, id_str);
    println(id_str);
    
    // RESTORE TARGET THREAD'S CONTEXT
    execute(thread_id);
    
    // Should not reach here - execute jumps to target
    println("THREAD: ERROR - Returned from execute");
}

// Thread termination handler
// Thread termination handler
// Thread termination handler
void thread_terminate(uint32_t thread_id) {
    println("THREAD: Termination called!");
    thread_control_block_t tcb;
    if (read_thread(thread_id, &tcb) != 0) {
        return;
    }
    
    tcb.state = THREAD_STATE_TERMINATED;
    write_thread(thread_id, &tcb);
    
    char thread_name[32];
    strcpy(thread_name, tcb.name);
    
    // Find /MODULES directory
    mfs_entry_t* modules_dir = mfs_find("MODULES", mfs_sb.root_dir);
    if (modules_dir) {
        // Find thread's function pointer directory: /MODULES/(thread_name)/
        mfs_entry_t* thread_func_dir = mfs_find(thread_name, modules_dir);
        if (thread_func_dir) {
            mfs_safe_remove_from_parent(thread_func_dir);
            mfs_free_entry(thread_func_dir);
        }
    }
    
    // Clean up thread segments
    char code_segment_name[64];
    strcpy(code_segment_name, thread_name);
    strcat(code_segment_name, "_code");
    
    mfs_entry_t* code_segment = mfs_find(code_segment_name, mfs_sb.root_dir);
    if (code_segment) {
        mfs_safe_remove_from_parent(code_segment);
        mfs_free_entry(code_segment);
    }
    
    char mem_segment_name[64];
    strcpy(mem_segment_name, thread_name);
    strcat(mem_segment_name, "_mem");
    
    mfs_entry_t* mem_segment = mfs_find(mem_segment_name, mfs_sb.root_dir);
    if (mem_segment) {
        mfs_safe_remove_from_parent(mem_segment);
        mfs_free_entry(mem_segment);
    }
    
    char snapshot_name[64];
    strcpy(snapshot_name, "snapshot_");
    char id_str[8];
    uint64_to_hex(thread_id, id_str);
    strcat(snapshot_name, id_str);
    
    mfs_entry_t* snapshot = mfs_find(snapshot_name, mfs_sb.root_dir);
    if (snapshot) {
        mfs_safe_remove_from_parent(snapshot);
        mfs_free_entry(snapshot);
    }

    println("THREAD: Cleanup completed");
    
    if (thread_id == current_thread_id) {
        __asm__ volatile("int $32");
    }
}

// Register thread for preemptive execution
void register_preemptive_thread(uint32_t thread_id) {
    if (active_thread_count < 16) {
        thread_states[active_thread_count].thread_id = thread_id;
        thread_states[active_thread_count].is_active = 1;
        
        print("PREEMPT: Registered thread ");
        char id_str[8];
        uint64_to_hex(thread_id, id_str);
        print(id_str);
        print(" at index ");
        uint64_to_hex(active_thread_count, id_str);
        println(id_str);
        
        active_thread_count++;
    }
}

/*==============================================================================================================
  ROBUST CONTEXT SWITCH - MFS-BASED CPU STATE STORAGE
================================================================================================================*/

void execute(uint32_t thread_id) {
    char context_name[64];
    strcpy(context_name, "context_");
    char id_str[8];
    uint64_to_hex(thread_id, id_str);
    strcat(context_name, id_str);
	// Find context segment
    mfs_entry_t* context_segment = mfs_find(context_name, mfs_sb.root_dir);
    if (!context_segment) {
        println("CONTEXT: ERROR - Context not found, using entry point");
	
        // Get thread's entry point for first run
        mfs_entry_t* table_segment = find_thread_table();
        if (!table_segment) {
            println("CONTEXT: ERROR - Cannot find thread table");
            return;
        }
	
        char code_segment_name[32];
        char stack_segment_name[32];
	
        size_t thread_offset = thread_id * sizeof(thread_control_block_t);
	
        if (mfs_read(table_segment, thread_offset + offsetof(thread_control_block_t, code_segment_name), code_segment_name, 32) != 0) {
            println("CONTEXT: ERROR - Cannot read code segment name");
            return;
        }
	
        if (mfs_read(table_segment, thread_offset + offsetof(thread_control_block_t, stack_segment_name), stack_segment_name, 32) != 0) {
            println("CONTEXT: ERROR - Cannot read stack segment name");
            return;
        }
	
        mfs_entry_t* threads_dir = mfs_find("THREADS", mfs_sb.root_dir);
        if (!threads_dir) {
            println("CONTEXT: ERROR - Cannot find THREADS directory");
            return;
        }
	
        mfs_entry_t* code_segment = mfs_find(code_segment_name, threads_dir);
        mfs_entry_t* stack_segment = mfs_find(stack_segment_name, threads_dir);
	
        if (!code_segment) {
            println("CONTEXT: ERROR - Cannot find code segment");
            return;
        }
	
        if (!stack_segment) {
            println("CONTEXT: ERROR - Cannot find stack segment");
            return;
        }
	
        uint64_t entry_rip = code_segment->start_addr;
        uint64_t stack_top = stack_segment->start_addr + stack_segment->size - 16;
	
        print("CONTEXT: Using entry point ");
        char addr_str[16];
        uint64_to_hex(entry_rip, addr_str);
        print(addr_str);
        print(" with stack ");
        uint64_to_hex(stack_top, addr_str);
        println(addr_str);

		print("ELF_LOADER: Instructions at entry point: ");
    	uint8_t* entry_ptr = (uint8_t*)(entry_rip);
    	for (int i = 0; i < 8; i++) {
    	    uint64_to_hex(entry_ptr[i], addr_str);
    	    print(addr_str); print(" ");
    	}
    	println("");
	
        // Jump to entry point with clean state
        // Clean jump with preloaded rbp from stack_top
		__asm__ volatile(
		    "movw $0x23, %%ax\n"
		    "movw %%ax, %%ds\n"
		    "movw %%ax, %%es\n"
		    "movw %%ax, %%fs\n"
		    "movw %%ax, %%gs\n"
		
		    // Setup userland stack and code
		    "pushq $0x23\n"
		    "pushq %0\n"        // stack_top
		    "pushq $0x202\n"
		    "pushq $0x1B\n"
		    "pushq %1\n"        // entry_rip
		
		    // Zero registers
		    "xorq %%rax, %%rax\n"
		    "xorq %%rbx, %%rbx\n"
		    "xorq %%rcx, %%rcx\n"
		    "xorq %%rdx, %%rdx\n"
		    "xorq %%rsi, %%rsi\n"
		    "xorq %%rdi, %%rdi\n"
		    "xorq %%r8, %%r8\n"
		    "xorq %%r9, %%r9\n"
		    "xorq %%r10, %%r10\n"
		    "xorq %%r11, %%r11\n"
		    "xorq %%r12, %%r12\n"
		    "xorq %%r13, %%r13\n"
		    "xorq %%r14, %%r14\n"
		    "xorq %%r15, %%r15\n"
		
		    // ⚠️ NEW: preload RBP with known safe stack value
		    "movq %0, %%rbp\n"
		
		    // Jump to userland
		    "iretq\n"
		    :
		    : "r"(stack_top), "r"(entry_rip)
		    : "memory"
		);
        return;
    }
}

// Install context restoration interrupt
void init_context_restoration_interrupt (void) {
    println("CONTEXT_INT: Installing context restoration interrupt (0x77)");
    
    extern void context_restore_interrupt_entry();
    set_idt_entry(0x77, (uint64_t)context_restore_interrupt_entry, KERNEL_CODE_SELECTOR, 0xEE);
    
    println("CONTEXT_INT: Context restoration interrupt ready");
}

// Context restoration interrupt handler
void context_restore_interrupt_handler (void) {
    if (pending_restore_thread_id == 0) {
        println("CONTEXT_INT: No pending restoration");
        return;
    }
    
    println("CONTEXT_INT: Performing context restoration in clean environment");
    
    uint32_t target_thread = pending_restore_thread_id;
    pending_restore_thread_id = 0;  // Clear pending
    
    // Now we're in a clean interrupt context - do the restoration
    execute(target_thread);
}

// Assembly wrapper for context restoration interrupt
__asm__(
    ".global context_restore_interrupt_entry\n"
    "context_restore_interrupt_entry:\n"
    "    call context_restore_interrupt_handler\n"
    "    iretq\n"
);
