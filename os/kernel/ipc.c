#include "include.h"


// Unified function for invoking kernel functions with proper signature handling
int invoke_kernel_function_unified(const char* module_name, const char* function_name, 
                                   int param_count, uint64_t* params, int* result) {
    // Allocate safe memory for string parameters
    char* safe_module_name = (char*)safe_malloc(64);
    char* safe_function_name = (char*)safe_malloc(64);
    uint64_t* safe_params = NULL;
    int* safe_result = NULL;
    
    if (!safe_module_name || !safe_function_name) {
        println("ERROR: Failed to allocate safe memory for strings");
        if (safe_module_name) basic_free(safe_module_name);
        if (safe_function_name) basic_free(safe_function_name);
        return -1;
    }
    
    // Copy strings to safe memory
    strcpy(safe_module_name, module_name);
    strcpy(safe_function_name, function_name);
    
    // Allocate safe memory for params if needed
    if (params && param_count > 0) {
        safe_params = (uint64_t*)safe_malloc(sizeof(uint64_t) * param_count);
        if (!safe_params) {
            println("ERROR: Failed to allocate safe memory for params");
            basic_free(safe_module_name);
            basic_free(safe_function_name);
            return -1;
        }
        
        // Copy parameters
        for (int i = 0; i < param_count; i++) {
            safe_params[i] = params[i];
        }
    }
    
    // Allocate safe memory for result if needed
    if (result) {
        safe_result = (int*)safe_malloc(sizeof(int));
        if (!safe_result) {
            println("ERROR: Failed to allocate safe memory for result");
            basic_free(safe_module_name);
            basic_free(safe_function_name);
            if (safe_params) basic_free(safe_params);
            return -1;
        }
    }
    
    println("DEBUG: Safe memory allocated, calling function");
    
    // Call the original function with safe parameters
    int ret = invoke_kernel_function_unified(safe_module_name, safe_function_name, 
                                           param_count, safe_params, safe_result);
    
    println("DEBUG: Function call completed");
    
    // Copy result back if needed
    if (result && safe_result) {
        *result = *safe_result;
    }
    
    // Clean up safe memory
    basic_free(safe_module_name);
    basic_free(safe_function_name);
    if (safe_params) basic_free(safe_params);
    if (safe_result) basic_free(safe_result);
    
    return ret;
}

// Function to declare module, function, and arg count
int declare_kernel_function(const char* module_name, const char* function_name, int arg_count) {
    if (!module_name || !function_name || arg_count < 0 || arg_count > 6) {
        return -1;
    }
    
    strcpy(predeclared_call.module_name, module_name);
    strcpy(predeclared_call.function_name, function_name);
    predeclared_call.arg_count = arg_count;
    predeclared_call.is_set = 1;
    
    return 0;
}

// Modified call_kernel_function to use all 6 args when predeclared
int call_kernel_function(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    if (!predeclared_call.is_set) {
        return -1;
    }
    
    // Find the function pointer
    mfs_entry_t* modules_dir = mfs_find("MODULES", mfs_sb.root_dir);
    if (!modules_dir) return -1;
    
    mfs_entry_t* module_dir = mfs_find(predeclared_call.module_name, modules_dir);
    if (!module_dir) return -1;
    
    mfs_entry_t* func_segment = mfs_find(predeclared_call.function_name, module_dir);
    if (!func_segment) return -1;
    
    uint64_t func_ptr;
    if (mfs_read(func_segment, 0, &func_ptr, sizeof(func_ptr)) != 0) return -1;
    if (func_ptr == 0) return -1;
    
    int result = 0;
    int argc = predeclared_call.arg_count;
    
    // Call with all 6 arguments based on predeclared count
    switch (argc) {
        case 0:
            __asm__ volatile("call *%1" : "=a" (result) : "r" (func_ptr) : "memory", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");
            break;
        case 1:
            __asm__ volatile("movq %2, %%rdi\ncall *%1" : "=a" (result) : "r" (func_ptr), "r" (arg1) : "memory", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");
            break;
        case 2:
            __asm__ volatile("movq %2, %%rdi\nmovq %3, %%rsi\ncall *%1" : "=a" (result) : "r" (func_ptr), "r" (arg1), "r" (arg2) : "memory", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");
            break;
        case 3:
            __asm__ volatile("movq %2, %%rdi\nmovq %3, %%rsi\nmovq %4, %%rdx\ncall *%1" : "=a" (result) : "r" (func_ptr), "r" (arg1), "r" (arg2), "r" (arg3) : "memory", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");
            break;
        case 4:
            __asm__ volatile("movq %2, %%rdi\nmovq %3, %%rsi\nmovq %4, %%rdx\nmovq %5, %%rcx\ncall *%1" : "=a" (result) : "r" (func_ptr), "r" (arg1), "r" (arg2), "r" (arg3), "r" (arg4) : "memory", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");
            break;
        case 5:
            __asm__ volatile("movq %2, %%rdi\nmovq %3, %%rsi\nmovq %4, %%rdx\nmovq %5, %%rcx\nmovq %6, %%r8\ncall *%1" : "=a" (result) : "r" (func_ptr), "r" (arg1), "r" (arg2), "r" (arg3), "r" (arg4), "r" (arg5) : "memory", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");
            break;
        case 6:
   			__asm__ volatile("movq %2, %%rdi\nmovq %3, %%rsi\nmovq %4, %%rdx\nmovq %5, %%rcx\nmovq %6, %%r8\nmovq %7, %%r9\ncall *%1" : "=a" (result) : "r" (func_ptr), "r" (arg1), "r" (arg2), "r" (arg3), "r" (arg4), "r" (arg5), "r" (arg6) : "memory", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");
            break;
        default:
            return -1;
    }
    
    return result;
}

// Universal print wrapper - handles any type
// Universal print function - accepts ANY type as uint64_t
int printun(uint64_t arg) {
    print("WRAPPER DEBUG: Received arg=");
    char buf[16];
    uint64_to_hex(arg, buf);
    println(buf);
    
    print("WRAPPER DEBUG: Checking pointer validity...");
    if (arg > 0x1000 && arg < 0x7FFFFFFFFFFF) {
        println("VALID RANGE");
        
        print("WRAPPER DEBUG: First 4 chars: ");
        const char* str = (const char*)arg;
        for (int i = 0; i < 4; i++) {
            char c = str[i];
            if (c >= 32 && c <= 126) {
                print(&c);
            } else {
                print("?");
            }
        }
        println("");
        
        print("WRAPPER DEBUG: Calling print with: ");
        print((const char*)arg);
        println("");
    } else {
        println("INVALID RANGE");
    }
    
    return 0;
}

// Syscall handler using syscall instruction
// Syscall interrupt handler for interrupt 0x69

void syscall_interrupt_handler (void) {
    char* module_name;
    char* function_name;
    int argc;
    uint64_t arg0, arg1, arg2;
    
    // Save registers immediately on entry
    __asm__ volatile(
        "movq %%rdi, %0\n"
        "movq %%rsi, %1\n"
        "movl %%edx, %2\n"
        "movq %%rcx, %3\n"
        "movq %%r8, %4\n"
        "movq %%r9, %5\n"
        : "=m"(module_name), "=m"(function_name), "=m"(argc),
          "=m"(arg0), "=m"(arg1), "=m"(arg2)
        :
        : "memory"
    );
    
    // Debug output
    print("SYSCALL DEBUG: module_name ptr=");
    char buf[16];
    uint64_to_hex((uint64_t)module_name, buf);
    println(buf);
    
    print("SYSCALL DEBUG: function_name ptr=");
    uint64_to_hex((uint64_t)function_name, buf);
    println(buf);
    
    print("SYSCALL DEBUG: argc=");
    itoa(argc, buf, 10);
    println(buf);
    
    // Check if pointers are valid before using them
    if (module_name && function_name) {
        print("SYSCALL DEBUG: module=");
        print(module_name);
        print(" function=");
        println(function_name);
        
        int result = call_kernel_function(module_name, function_name, argc,
            argc > 0 ? (void*)arg0 : 0,
            argc > 1 ? (void*)arg1 : 0,
            argc > 2 ? (void*)arg2 : 0);
        
        __asm__ volatile("movl %0, %%eax" : : "r"(result) : "rax");
    } else {
        println("SYSCALL DEBUG: NULL pointers received!");
        __asm__ volatile("movl $-1, %%eax" : : : "rax");
    }
}

void syscall_0x80_handler (void) {
    char* module_name;
    char* function_name;
    int argc;
    uint64_t arg0, arg1, arg2;
    
    __asm__ volatile(
        "movq %%rdi, %0\n"
        "movq %%rsi, %1\n"
        "movl %%edx, %2\n"
        "movq %%rcx, %3\n"
        "movq %%r8, %4\n"
        "movq %%r9, %5\n"
        : "=m"(module_name), "=m"(function_name), "=m"(argc),
          "=m"(arg0), "=m"(arg1), "=m"(arg2)
    );
    
    int result = call_kernel_function(module_name, function_name, argc,
        argc > 0 ? (void*)arg0 : 0,
        argc > 1 ? (void*)arg1 : 0,
        argc > 2 ? (void*)arg2 : 0);
    
    __asm__ volatile("movl %0, %%eax" : : "r"(result) : "rax");
}

void init_direct_syscall (void) {
    set_idt_entry(0x80, (uint64_t)syscall_0x80_handler, KERNEL_CODE_SELECTOR, 0x8E | 0x60);
    println("DIRECT SYSCALL: Initialized on interrupt 0x80");
}

#define FIXED_CALL_KERNEL_ADDR 0x20900000  // Fixed address for call_kernel_function

int extract_call (void) {
    println("EXTRACT_CALL: Looking for call_kernel_function pointer");
    
    // Find MODULES directory
    mfs_entry_t* modules_dir = mfs_find("MODULES", mfs_sb.root_dir);
    if (!modules_dir) {
        println("EXTRACT_CALL: ERROR - Cannot find MODULES directory");
        return -1;
    }
    
    // Find SYSTEM directory
    mfs_entry_t* system_dir = mfs_find("SYSTEM", modules_dir);
    if (!system_dir) {
        println("EXTRACT_CALL: ERROR - Cannot find SYSTEM directory");
        return -1;
    }
    
    // Find call_kernel_function segment
    mfs_entry_t* func_segment = mfs_find("call_kernel_function", system_dir);
    if (!func_segment) {
        println("EXTRACT_CALL: ERROR - Cannot find call_kernel_function segment");
        return -1;
    }
    
    // Read the function pointer
    uint64_t func_ptr;
    if (mfs_read(func_segment, 0, &func_ptr, sizeof(func_ptr)) != 0) {
        println("EXTRACT_CALL: ERROR - Cannot read function pointer");
        return -1;
    }
    
    print("EXTRACT_CALL: Found call_kernel_function at: ");
    char addr_str[16];
    uint64_to_hex(func_ptr, addr_str);
    println(addr_str);
    
    // Create MFS segment at fixed address
    mfs_entry_t* fixed_segment = mfs_seg_at("call_kernel_fixed", sizeof(uint64_t), FIXED_CALL_KERNEL_ADDR ,mfs_sb.root_dir);
    if (!fixed_segment) {
        println("EXTRACT_CALL: ERROR - Cannot create fixed address segment");
        return -1;
    }
    
    // Write function pointer to fixed address
    if (mfs_write(fixed_segment, 0, &func_ptr, sizeof(func_ptr)) != 0) {
        println("EXTRACT_CALL: ERROR - Cannot write to fixed address");
        return -1;
    }
    
    print("EXTRACT_CALL: Mapped call_kernel_function to fixed address: ");
    uint64_to_hex(FIXED_CALL_KERNEL_ADDR, addr_str);
    println(addr_str);
    
    return 0;
}

void syscall_0x81_handler (void) {
    int syscall_num;
    uint64_t arg1, arg2, arg3, arg4;
    
    __asm__ volatile(
        "movl %%edi, %0\n"
        "movq %%rsi, %1\n"
        "movq %%rdx, %2\n"
        "movq %%rcx, %3\n"
        "movq %%r8, %4\n"
        : "=m"(syscall_num), "=m"(arg1), "=m"(arg2), "=m"(arg3), "=m"(arg4)
        : : "memory"
    );
    
    int result = -1;
    
    if (syscall_num == 1) {
        char* function = (char*)arg2;
        int argc = (int)arg3;
        uint64_t* args = (uint64_t*)arg4;
        
        // Check function name without debug prints
        if (function && function[0] == 'p' && function[1] == 'r' && function[2] == 'i' && 
            function[3] == 'n' && function[4] == 't' && function[5] == 'l' && function[6] == 'n') {
            if (argc > 0) println((char*)args[0]);
            result = 0;
        }
    }
    
    __asm__ volatile("movl %0, %%eax" : : "r"(result) : "rax");
}

__asm__(
    ".global syscall_global_enrty\n"
    "syscall_global_entry:\n"
    "    call syscall_0x81_handler\n"
    "    iretq\n"
);

extern void syscall_global_entry();

// Use interrupt 0x81 instead of 0x69
void init_syscall_system (void) {
    // Set IDT entry for interrupt 0x81 with DPL=3 for Ring 3 access
    set_idt_entry(0x81, (uint64_t)syscall_global_entry, KERNEL_CODE_SELECTOR, 0x8E | 0x60);
    println("SYSCALL: Direct function call system initialized on interrupt 0x81");
}

/*==============================================================================================================
  MAILBOX IPC
================================================================================================================*/
void init_mfs_mailbox (void) {
    mfs_entry_t* mailbox = mfs_seg_at("mailbox", MAILBOX_SIZE, MAILBOX_ADDR, mfs_sb.root_dir);
    if (!mailbox) {
        println("ERROR: Cannot create MFS mailbox");
        return;
    }
    
    mfs_mailbox_t* mb = (mfs_mailbox_t*)MAILBOX_ADDR;
    mb->magic = 0xDEADBEEF;
    mb->status = 0;
    
    println("MFS MAILBOX: Initialized at 0x21000000");
}

void process_mfs_mailbox (void) {
    mfs_mailbox_t* mb = (mfs_mailbox_t*)MAILBOX_ADDR;
    
    if (mb->magic != 0xDEADBEEF || mb->status != 1) return;
    
    switch(mb->function_id) {
        case 1: // println
            if (mb->argc > 0) {
                println((char*)mb->args[0]);
                mb->result = 0;
            } else {
                mb->result = -1;
            }
            break;
        default:
            mb->result = -1;
    }
    
    mb->status = 2; // Response ready
}

/*==============================================================================================================
  SYSCALLS
================================================================================================================*/
// Forward declarations for syscall handlers
int64_t sys_printf_handler(uint64_t str, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_mfs_find_handler(uint64_t name, uint64_t parent, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_mfs_read_handler(uint64_t entry, uint64_t offset, uint64_t buffer, uint64_t size, uint64_t arg5, uint64_t arg6);
int64_t sys_mfs_write_handler(uint64_t entry, uint64_t offset, uint64_t buffer, uint64_t size, uint64_t arg5, uint64_t arg6);
int64_t sys_mfs_seg_handler(uint64_t name, uint64_t size, uint64_t parent, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_mfs_dir_handler(uint64_t name, uint64_t parent, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_get_mfs_sb_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_get_mfs_table_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_get_root_dir_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_get_ports_dir_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_malloc_handler(uint64_t size, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_free_handler(uint64_t ptr, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_get_uptime_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_show_uptime_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_fs_open_handler(uint64_t path, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_fs_close_handler(uint64_t fd, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_fs_read_handler(uint64_t fd, uint64_t buffer, uint64_t size, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_fs_ls_handler(uint64_t path, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_getchar_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_clear_screen_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_vga_write_handler(uint64_t x, uint64_t y, uint64_t c, uint64_t color, uint64_t arg5, uint64_t arg6);
int64_t sys_execute_handler(uint64_t thread_id, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
int64_t sys_elf_loader_handler(uint64_t path, uint64_t name, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);

// Syscall handler implementations
// Use in syscall handler:
// MFS-compliant lookup in syscall handler

int64_t sys_printf_handler(uint64_t str, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    println("DEBUG: sys_printf_handler called");
    
    if (!str) {
        println("DEBUG: str is NULL");
        return -1;
    }
    
    print("DEBUG: str address = 0x");
    char addr_str[20];
    uint64_to_hex(str, addr_str);
    println(addr_str);
    
    char kernel_buffer[256];
    int copy_result = copy_string_from_user(str, kernel_buffer, sizeof(kernel_buffer));
    
    print("DEBUG: copy_string_from_user returned ");
    char result_str[4];
    result_str[0] = '0' + copy_result;
    result_str[1] = '\0';
    println(result_str);
    
    if (copy_result != 0) {
        println("DEBUG: copy_string_from_user failed");
        return -1;
    }
    
    print("DEBUG: kernel_buffer contains: '");
    print(kernel_buffer);
    println("'");
    
    println("DEBUG: About to call print()");
    print(kernel_buffer);
    println("DEBUG: print() completed");
    
    return 0;
}


// New syscall handler for direct calls
int64_t sys_call_function_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    return call_kernel_function(arg1, arg2, arg3, arg4, arg5, arg6);
}

int64_t sys_declare_function_handler(uint64_t module, uint64_t function, uint64_t arg_count, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    return declare_kernel_function((const char*)module, (const char*)function, (int)arg_count);
}

int64_t sys_mfs_find_handler(uint64_t name, uint64_t parent, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    if (!name || !parent) return 0;
    mfs_entry_t* result = mfs_find((const char*)name, (mfs_entry_t*)parent);
    return (int64_t)result;
}

int64_t sys_mfs_read_handler(uint64_t entry, uint64_t offset, uint64_t buffer, uint64_t size, uint64_t arg5, uint64_t arg6) {
    if (!entry || !buffer) return -1;
    return mfs_read((mfs_entry_t*)entry, (size_t)offset, (void*)buffer, (size_t)size);
}

int64_t sys_mfs_write_handler(uint64_t entry, uint64_t offset, uint64_t buffer, uint64_t size, uint64_t arg5, uint64_t arg6) {
    if (!entry || !buffer) return -1;
    return mfs_write((mfs_entry_t*)entry, (size_t)offset, (const void*)buffer, (size_t)size);
}

int64_t sys_mfs_seg_handler(uint64_t name, uint64_t size, uint64_t parent, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    if (!name || !parent) return 0;
    mfs_entry_t* result = mfs_seg((const char*)name, (size_t)size, (mfs_entry_t*)parent);
    return (int64_t)result;
}

int64_t sys_mfs_dir_handler(uint64_t name, uint64_t parent, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    if (!name || !parent) return 0;
    mfs_entry_t* result = mfs_dir((const char*)name, (mfs_entry_t*)parent);
    return (int64_t)result;
}

int64_t sys_get_mfs_sb_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    return (int64_t)&mfs_sb;
}

int64_t sys_get_mfs_table_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    return (int64_t)mfs_sb.entry_table;
}

int64_t sys_get_root_dir_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    return (int64_t)mfs_sb.root_dir;
}

int64_t sys_get_ports_dir_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    mfs_entry_t* ports_directory = mfs_find("PORTS", mfs_sb.root_dir);
    return (int64_t)ports_directory;
}

int64_t sys_malloc_handler(uint64_t size, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    return (int64_t)malloc((size_t)size);
}

int64_t sys_free_handler(uint64_t ptr, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    if (ptr) free((void*)ptr);
    return 0;
}

int64_t sys_get_uptime_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    return (int64_t)get_uptime_seconds();
}

int64_t sys_show_uptime_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    show_uptime();
    return 0;
}

int64_t sys_fs_open_handler(uint64_t path, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    if (!path) return -1;
    return (int64_t)fs_open((const char*)path);
}

int64_t sys_fs_close_handler(uint64_t fd, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    return (int64_t)fs_close((int)fd);
}

int64_t sys_fs_read_handler(uint64_t fd, uint64_t buffer, uint64_t size, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    if (!buffer) return -1;
    return (int64_t)fs_read((int)fd, (void*)buffer, (size_t)size);
}

int64_t sys_fs_ls_handler(uint64_t path, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    if (!path) return -1;
    return (int64_t)fs_ls((const char*)path);
}

int64_t sys_getchar_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    // Implement keyboard input
    return 0; // Placeholder
}

int64_t sys_clear_screen_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    clear_screen();
    return 0;
}

int64_t sys_vga_write_handler(uint64_t x, uint64_t y, uint64_t c, uint64_t color, uint64_t arg5, uint64_t arg6) {
    vga_write_safe((int)x, (int)y, (char)c, (unsigned char)color);
    return 0;
}

int64_t sys_execute_handler(uint64_t thread_id, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    // Implement thread execution
    return 0; // Placeholder
}

int64_t sys_elf_loader_handler(uint64_t path, uint64_t name, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    // Implement ELF loading
    return 0; // Placeholder
}

// Main syscall dispatcher
void syscall_handler(uint64_t syscall_num, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    if (syscall_num >= MAX_SYSCALLS || syscall_table[syscall_num].handler == NULL) {
        __asm__ volatile("movq $-1, %%rax" : : : "rax");
        return;
    }
    
    int64_t result = syscall_table[syscall_num].handler(arg1, arg2, arg3, arg4, arg5, arg6);
    __asm__ volatile("movq %0, %%rax" : : "r"(result) : "rax");
}

// Assembly syscall entry point
// Replace the assembly syscall entry point with this corrected version:
__asm__(
    ".global syscall_entry\n"
    "syscall_entry:\n"
    "    # Save all registers\n"
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
    "    # Arguments are in registers:\n"
    "    # RAX = syscall number\n"
    "    # RDI = arg1, RSI = arg2, RDX = arg3\n"
    "    # R10 = arg4, R8 = arg5, R9 = arg6\n"
    "    \n"
    "    # Save original args before overwriting\n"
    "    movq %rdi, %rbx    # Save arg1\n"
    "    movq %rsi, %r11    # Save arg2\n"
    "    movq %rdx, %r12    # Save arg3\n"
    "    movq %r10, %r13    # Save arg4\n"
    "    movq %r8, %r14     # Save arg5\n"
    "    movq %r9, %r15     # Save arg6\n"
    "    \n"
    "    # Set up call to syscall_handler(syscall_num, arg1, arg2, arg3, arg4, arg5, arg6)\n"
    "    movq %rax, %rdi    # syscall_num -> RDI\n"
    "    movq %rbx, %rsi    # arg1 -> RSI\n"
    "    movq %r11, %rdx    # arg2 -> RDX\n"
    "    movq %r12, %rcx    # arg3 -> RCX\n"
    "    movq %r13, %r8     # arg4 -> R8\n"
    "    movq %r14, %r9     # arg5 -> R9\n"
    "    pushq %r15         # arg6 -> stack\n"
    "    \n"
    "    call syscall_handler\n"
    "    addq $8, %rsp      # Clean up pushed arg6\n"
    "    \n"
    "    # Restore all registers except RAX (contains return value)\n"
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
    "    \n"
    "    # Return to userspace\n"
    "    iretq\n"
);
void init_syscalls (void) {
    println("SYSCALL: Initializing syscall system");
    
    // Initialize syscall table
    syscall_table[0].handler = NULL;
    syscall_table[0].name = "invalid";
    syscall_table[0].arg_count = 0;
    
    syscall_table[SYS_PRINTF].handler = sys_printf_handler;
    syscall_table[SYS_PRINTF].name = "printf";
    syscall_table[SYS_PRINTF].arg_count = 1;
    
    syscall_table[SYS_MFS_FIND].handler = sys_mfs_find_handler;
    syscall_table[SYS_MFS_FIND].name = "mfs_find";
    syscall_table[SYS_MFS_FIND].arg_count = 2;
    
    syscall_table[SYS_MFS_READ].handler = sys_mfs_read_handler;
    syscall_table[SYS_MFS_READ].name = "mfs_read";
    syscall_table[SYS_MFS_READ].arg_count = 4;
    
    syscall_table[SYS_MFS_WRITE].handler = sys_mfs_write_handler;
    syscall_table[SYS_MFS_WRITE].name = "mfs_write";
    syscall_table[SYS_MFS_WRITE].arg_count = 4;
    
    syscall_table[SYS_MFS_SEG].handler = sys_mfs_seg_handler;
    syscall_table[SYS_MFS_SEG].name = "mfs_seg";
    syscall_table[SYS_MFS_SEG].arg_count = 3;
    
    syscall_table[SYS_MFS_DIR].handler = sys_mfs_dir_handler;
    syscall_table[SYS_MFS_DIR].name = "mfs_dir";
    syscall_table[SYS_MFS_DIR].arg_count = 2;
    
    syscall_table[SYS_GET_MFS_SB].handler = sys_get_mfs_sb_handler;
    syscall_table[SYS_GET_MFS_SB].name = "get_mfs_superblock";
    syscall_table[SYS_GET_MFS_SB].arg_count = 0;
    
    syscall_table[SYS_GET_MFS_TABLE].handler = sys_get_mfs_table_handler;
    syscall_table[SYS_GET_MFS_TABLE].name = "get_mfs_entry_table";
    syscall_table[SYS_GET_MFS_TABLE].arg_count = 0;
    
    syscall_table[SYS_GET_ROOT_DIR].handler = sys_get_root_dir_handler;
    syscall_table[SYS_GET_ROOT_DIR].name = "get_root_dir";
    syscall_table[SYS_GET_ROOT_DIR].arg_count = 0;
    
    syscall_table[SYS_GET_PORTS_DIR].handler = sys_get_ports_dir_handler;
    syscall_table[SYS_GET_PORTS_DIR].name = "get_ports_dir";
    syscall_table[SYS_GET_PORTS_DIR].arg_count = 0;
    
    syscall_table[SYS_MALLOC].handler = sys_malloc_handler;
    syscall_table[SYS_MALLOC].name = "malloc";
    syscall_table[SYS_MALLOC].arg_count = 1;
    
    syscall_table[SYS_FREE].handler = sys_free_handler;
    syscall_table[SYS_FREE].name = "free";
    syscall_table[SYS_FREE].arg_count = 1;
    
    syscall_table[SYS_GET_UPTIME].handler = sys_get_uptime_handler;
    syscall_table[SYS_GET_UPTIME].name = "get_uptime";
    syscall_table[SYS_GET_UPTIME].arg_count = 0;
    
    syscall_table[SYS_SHOW_UPTIME].handler = sys_show_uptime_handler;
    syscall_table[SYS_SHOW_UPTIME].name = "show_uptime";
    syscall_table[SYS_SHOW_UPTIME].arg_count = 0;
    
    syscall_table[SYS_FS_OPEN].handler = sys_fs_open_handler;
    syscall_table[SYS_FS_OPEN].name = "fs_open";
    syscall_table[SYS_FS_OPEN].arg_count = 1;
    
    syscall_table[SYS_FS_CLOSE].handler = sys_fs_close_handler;
    syscall_table[SYS_FS_CLOSE].name = "fs_close";
    syscall_table[SYS_FS_CLOSE].arg_count = 1;
    
    syscall_table[SYS_FS_READ].handler = sys_fs_read_handler;
    syscall_table[SYS_FS_READ].name = "fs_read";
    syscall_table[SYS_FS_READ].arg_count = 3;
    
    syscall_table[SYS_FS_LS].handler = sys_fs_ls_handler;
    syscall_table[SYS_FS_LS].name = "fs_ls";
    syscall_table[SYS_FS_LS].arg_count = 1;
    
    syscall_table[SYS_GETCHAR].handler = sys_getchar_handler;
    syscall_table[SYS_GETCHAR].name = "getchar";
    syscall_table[SYS_GETCHAR].arg_count = 0;
    
    syscall_table[SYS_CLEAR_SCREEN].handler = sys_clear_screen_handler;
    syscall_table[SYS_CLEAR_SCREEN].name = "clear_screen";
    syscall_table[SYS_CLEAR_SCREEN].arg_count = 0;
    
    syscall_table[SYS_VGA_WRITE].handler = sys_vga_write_handler;
    syscall_table[SYS_VGA_WRITE].name = "vga_write";
    syscall_table[SYS_VGA_WRITE].arg_count = 4;
    
    syscall_table[SYS_EXECUTE].handler = sys_execute_handler;
    syscall_table[SYS_EXECUTE].name = "execute";
    syscall_table[SYS_EXECUTE].arg_count = 1;
    
    syscall_table[SYS_ELF_LOADER].handler = sys_elf_loader_handler;
    syscall_table[SYS_ELF_LOADER].name = "elf_loader";
    syscall_table[SYS_ELF_LOADER].arg_count = 2;

	syscall_table[SYS_DECLARE_FUNCTION].handler = sys_declare_function_handler;
    syscall_table[SYS_DECLARE_FUNCTION].name = "declare_function";
    syscall_table[SYS_DECLARE_FUNCTION].arg_count = 3;

	syscall_table[SYS_CALL_FUNCTION].handler = sys_call_function_handler;
	syscall_table[SYS_CALL_FUNCTION].name = "call_function";
	syscall_table[SYS_CALL_FUNCTION].arg_count = 6;  // module, function, arg_count, arg1, arg2, arg3
    
    // Install syscall handler at interrupt 0x80 with DPL=3 for Ring 3 access
    extern void syscall_entry(void);
    set_idt_entry(0x80, (uint64_t)syscall_entry, KERNEL_CODE_SELECTOR, 0xEE); // 0xEE = DPL=3
    
    println("SYSCALL: System call interface initialized");
}
