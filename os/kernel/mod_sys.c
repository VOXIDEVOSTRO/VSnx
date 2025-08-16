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
  DYNAMIC MODULE LOADER SYSTEM
================================================================================================================*/
// Initialize module system
void init_module_system (void) {
    println("MODULE: Starting system initialization");
    
    if (!mfs_sb.initialized) {
        println("MODULE: ERROR - MFS not initialized");
        return;
    }
    
    if (!modules_dir) {
        println("MODULE: Creating MODULES directory");
        modules_dir = mfs_dir("MODULES", mfs_sb.root_dir);
        
        if (!modules_dir) {
            println("MODULE: ERROR - Failed to create MODULES directory");
            return;
        }
        
        println("MODULE: MODULES directory created successfully");
    }
    
    println("MODULE: System initialized");
}

// REWRITTEN: ELF-based module loader
int load_module(const char* module_name) {
    init_module_system();
    
    if (module_count >= MAX_MODULES) {
        println("MODULE: Too many modules loaded");
        return -1;
    }
    
    // Build .so file path - support subdirectories
    char module_path[64];
    int pos = 0;
    module_path[pos++] = '/';
    module_path[pos++] = 'M';
    module_path[pos++] = 'O';
    module_path[pos++] = 'D';
    module_path[pos++] = 'U';
    module_path[pos++] = 'L';
    module_path[pos++] = 'E';
    module_path[pos++] = 'S';
    module_path[pos++] = '/';
    
    // Copy module name (can include subdirectories)
    for (int i = 0; module_name[i] && pos < 60; i++) {
        module_path[pos++] = module_name[i];
    }
    module_path[pos++] = '.';
    module_path[pos++] = 's';
    module_path[pos++] = 'o';
    module_path[pos] = '\0';
    
    // Load ELF file
    int fd = fs_open(module_path);
    if (fd < 0) {
        println("MODULE: Failed to open ELF file");
        return -1;
    }
    
    uint8_t* elf_buffer = (uint8_t*)user_malloc(1024 * 1024);
    if (!elf_buffer) {
        fs_close(fd);
        return -1;
    }
    
    int file_size = fs_read(fd, elf_buffer, 1024 * 1024);
    fs_close(fd);
    
    if (file_size <= 0) {
        user_free(elf_buffer);
        return -1;
    }
    
    // Create MFS segment and copy ELF
    mfs_entry_t* module_segment = mfs_seg(module_name, file_size, modules_dir);
    if (!module_segment) {
        user_free(elf_buffer);
        return -1;
    }
    
    if (mfs_write(module_segment, 0, elf_buffer, file_size) != 0) {
        user_free(elf_buffer);
        return -1;
    }
    
    // Parse ELF header
    elf64_header_t* elf_header = (elf64_header_t*)elf_buffer;
    
    // Validate ELF magic
    if (elf_header->e_ident[0] != 0x7F || elf_header->e_ident[1] != 'E' ||
        elf_header->e_ident[2] != 'L' || elf_header->e_ident[3] != 'F') {
        println("MODULE: Invalid ELF magic");
        user_free(elf_buffer);
        return -1;
    }
    
    println("MODULE: Valid ELF file detected");
    
    // Register module
    module_t* mod = &loaded_modules[module_count];
    for (int i = 0; module_name[i] && i < 31; i++) {
        mod->name[i] = module_name[i];
        mod->name[i + 1] = '\0';
    }
    mod->segment = module_segment;
    mod->function_count = 0;
    
    // Parse sections to find symbol table
    elf64_section_t* sections = (elf64_section_t*)(elf_buffer + elf_header->e_shoff);
    
    for (int i = 0; i < elf_header->e_shnum; i++) {
        if (sections[i].sh_type == 2) { // SHT_SYMTAB
            elf64_symbol_t* symbols = (elf64_symbol_t*)(elf_buffer + sections[i].sh_offset);
            int symbol_count = sections[i].sh_size / sizeof(elf64_symbol_t);
            
            // Find string table
            char* string_table = (char*)(elf_buffer + sections[sections[i].sh_link].sh_offset);
            
            // Extract function symbols AND create ports
            for (int j = 0; j < symbol_count && mod->function_count < MAX_FUNCTIONS_PER_MODULE; j++) {
                if ((symbols[j].st_info & 0xF) == 2) { // STT_FUNC
                    char* func_name = string_table + symbols[j].st_name;
                    
                    // Copy function name
                    for (int k = 0; k < 31 && func_name[k]; k++) {
                        mod->functions[mod->function_count].name[k] = func_name[k];
                        mod->functions[mod->function_count].name[k + 1] = '\0';
                    }
                    
                    mod->functions[mod->function_count].address = module_segment->start_addr + symbols[j].st_value;
                    mod->functions[mod->function_count].size = symbols[j].st_size;
                    
                    print("MODULE: Found function: ");
                    println(mod->functions[mod->function_count].name);
                    
                    // CREATE PORT FOR THIS FUNCTION
                    char port_name[64];
                    int pos = 0;
                    
                    // Build port name: module_function
                    // Copy module name (skip "SYS/" prefix if present)
                    const char* clean_module_name = module_name;
                    if (module_name[0] == 'S' && module_name[1] == 'Y' && module_name[2] == 'S' && module_name[3] == '/') {
                        clean_module_name = module_name + 4;
                    }
                    
                    for (int k = 0; clean_module_name[k] && pos < 50; k++) {
                        port_name[pos++] = clean_module_name[k];
                    }
                    port_name[pos++] = '_';
                    
                    // Copy function name
                    for (int k = 0; func_name[k] && pos < 62; k++) {
                        port_name[pos++] = func_name[k];
                    }
                    port_name[pos] = '\0';
                    
                    // Create the port
                    if (create_port(port_name) == 0) {
                        print("MODULE: Created port for function: ");
                        println(port_name);
                    } else {
                        print("MODULE: Failed to create port for: ");
                        println(port_name);
                    }
                    
                    mod->function_count++;
                }
            }
            break;
        }
    }
    
    user_free(elf_buffer);
    module_count++;
    
    print("MODULE: Loaded ELF module ");
    print(module_name);
    print(" with ");
    char count_str[8];
    uint64_to_hex(mod->function_count, count_str);
    print(count_str);
    println(" functions and corresponding ports");
    
    return module_count - 1;
}

// Call module function
int call_module_function(const char* module_name, const char* function_name) {
    // Find module
    module_t* mod = NULL;
    for (int i = 0; i < module_count; i++) {
        if (strcmp(loaded_modules[i].name, module_name) == 0) {
            mod = &loaded_modules[i];
            break;
        }
    }
    
    if (!mod) {
        println("MODULE: Module not found");
        return -1;
    }
    
    // Find function
    module_function_t* func = NULL;
    for (int i = 0; i < mod->function_count; i++) {
        if (strcmp(mod->functions[i].name, function_name) == 0) {
            func = &mod->functions[i];
            break;
        }
    }
    
    if (!func) {
        println("MODULE: Function not found");
        return -1;  // Return error, don't call invalid address
    }
    
    // FIXED: Don't call if address is invalid
    if (func->address == 0 || func->address == 0xFFFFFFFFFFFFFFFF) {
        println("MODULE: Invalid function address");
        return -1;
    }
    
    // Call function using assembly wrapper
    uint64_t result;
    __asm__ volatile(
        "call *%1"
        : "=a"(result)
        : "r"(func->address)
        : "memory"
    );
    
    return (int)result;
}

// Port-based module communication - FIXED VERSION
int call_module_via_port(const char* module_name, const char* function_name, int param1, int param2) {
    println("MODULE: Using port-based communication");
    
    // Build port name: module_function
    char port_name[64];
    int pos = 0;
    
    // Copy module name
    for (int i = 0; module_name[i] && pos < 50; i++) {
        port_name[pos++] = module_name[i];
    }
    port_name[pos++] = '_';
    
    // Copy function name
    for (int i = 0; function_name[i] && pos < 62; i++) {
        port_name[pos++] = function_name[i];
    }
    port_name[pos] = '\0';
    
    print("MODULE: Using port: ");
    println(port_name);
    
    // Find the port
    mfs_superblock_t* sb = (mfs_superblock_t*)&mfs_sb;
    mfs_entry_t* entry_table = (mfs_entry_t*)sb->entry_table;
    mfs_entry_t* port_entry = NULL;
    
    for (int i = 0; i < MFS_MAX_ENTRIES; i++) {
        if (entry_table[i].magic == MFS_MAGIC && 
            entry_table[i].type == MFS_TYPE_SEGMENT &&
            strcmp(entry_table[i].name, port_name) == 0) {
            port_entry = &entry_table[i];
            break;
        }
    }
    
    if (!port_entry) {
        println("MODULE: Port not found");
        return -1;
    }
    
    // Get port message structure
    port_message_t* port = (port_message_t*)port_entry->start_addr;
    
    // Write request to port
    port->status = PORT_STATUS_REQUEST;
    port->request_id++;
    port->data_size = 8;
    *((int*)&port->data[0]) = param1;
    *((int*)&port->data[4]) = param2;
    
    println("MODULE: Request written to port, waiting for response...");
    
    // CRITICAL FIX: Process ports while waiting
    int timeout = 1000000;
    while (port->status == PORT_STATUS_REQUEST && timeout > 0) {
        timeout--;
        
        // PROCESS PORTS EVERY ITERATION
        process_ports();
        
        // Small delay to prevent busy spinning
        for (volatile int i = 0; i < 100; i++) {
            // Small delay
        }
    }
    
    if (timeout == 0) {
        println("MODULE: Port communication timeout");
        return -1;
    }
    
    // Get response
    if (port->status == PORT_STATUS_RESPONSE) {
        int result = *((int*)&port->data[0]);
        port->status = PORT_STATUS_EMPTY; // Clear port
        
        print("MODULE: Got response: ");
        char result_str[8];
        uint64_to_hex(result, result_str);
        println(result_str);
        
        return result;
    }
    
    return -1;
}

// Load modules from config during boot
void load_boot_modules (void) {
    println("MODULE: Loading boot modules");
    
    // Load essential modules
    load_module("test");

    println("MODULE: Boot modules loaded");
}
// FIXED: Write data directly without stack arrays
int load_test_module_direct (void) {
    println("MODULE: Starting direct module load");

    init_module_system();
    
    if (!modules_dir) {
        println("MODULE: ERROR - Module system not initialized");
        return -1;
    }
    
    println("MODULE: Module system ready");
    
    if (module_count >= MAX_MODULES) {
        println("MODULE: Too many modules loaded");
        return -1;
    }
    
    println("MODULE: Creating module data");
    
    // Calculate module size
    int file_size = 56; // 20 (header) + 4 (name) + 32 (code)
    
    print("MODULE: Creating direct module, size: ");
    char debug_str[20];
    uint64_to_hex(file_size, debug_str);
    println(debug_str);
    
    // Create MFS segment for module
    mfs_entry_t* module_segment = mfs_seg("test", file_size, modules_dir);
    if (!module_segment) {
        println("MODULE: Failed to create MFS segment");
        return -1;
    }
    
    println("MODULE: Segment validation passed");
    
    // Write header data one uint32_t at a time to avoid stack arrays
    uint32_t magic = 0xDEADC0DE;
    if (mfs_write(module_segment, 0, &magic, 4) != 0) {
        println("MODULE: Failed to write magic");
        return -1;
    }
    
    uint32_t func_count = 1;
    if (mfs_write(module_segment, 4, &func_count, 4) != 0) {
        println("MODULE: Failed to write func_count");
        return -1;
    }
    
    uint32_t name_offset = 20;
    if (mfs_write(module_segment, 8, &name_offset, 4) != 0) {
        println("MODULE: Failed to write name_offset");
        return -1;
    }
    
    uint32_t func_offset = 24;
    if (mfs_write(module_segment, 12, &func_offset, 4) != 0) {
        println("MODULE: Failed to write func_offset");
        return -1;
    }
    
    uint32_t func_size = 32;
    if (mfs_write(module_segment, 16, &func_size, 4) != 0) {
        println("MODULE: Failed to write func_size");
        return -1;
    }
    
    println("MODULE: Header written successfully");
    
    // Write function name one byte at a time
    uint8_t name_a = 'a';
    uint8_t name_d1 = 'd';
    uint8_t name_d2 = 'd';
    uint8_t name_null = '\0';
    
    if (mfs_write(module_segment, 20, &name_a, 1) != 0 ||
        mfs_write(module_segment, 21, &name_d1, 1) != 0 ||
        mfs_write(module_segment, 22, &name_d2, 1) != 0 ||
        mfs_write(module_segment, 23, &name_null, 1) != 0) {
        println("MODULE: Failed to write function name");
        return -1;
    }
    
    println("MODULE: Function name written successfully");
    
    // Write function code (mov rax, 42; ret)
    uint8_t code_bytes[] = {0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00, 0xC3};
    for (int i = 0; i < 8; i++) {
        if (mfs_write(module_segment, 24 + i, &code_bytes[i], 1) != 0) {
            println("MODULE: Failed to write function code");
            return -1;
        }
    }
    
    println("MODULE: Module data written successfully");
    
    // Register module
    module_t* mod = &loaded_modules[module_count];
    mod->name[0] = 't'; mod->name[1] = 'e'; mod->name[2] = 's'; mod->name[3] = 't'; mod->name[4] = '\0';
    mod->segment = module_segment;
    mod->function_count = 1;
    
    // Set function info directly
    mod->functions[0].name[0] = 'a';
    mod->functions[0].name[1] = 'd';
    mod->functions[0].name[2] = 'd';
    mod->functions[0].name[3] = '\0';
    mod->functions[0].address = module_segment->start_addr + 24;
    mod->functions[0].size = 32;
    
    module_count++;
    
    println("MODULE: Test module loaded successfully");
    
    return module_count - 1;
}

// Create module function registry in MFS
void create_module_function_registry (void) {
    mfs_entry_t* registry_segment = mfs_seg("module_function_registry", 
                                           sizeof(module_function_entry_t) * MAX_MODULE_FUNCTIONS, 
                                           mfs_sb.root_dir);
    if (registry_segment) {
        println("REGISTRY: Created module function registry");
    }
}

// Add function to registry during ELF loading
void register_module_function(const char* module_name, const char* function_name) {
    mfs_entry_t* registry = mfs_find("module_function_registry", mfs_sb.root_dir);
    if (!registry) return;
    
    // Find empty slot
    for (int i = 0; i < MAX_MODULE_FUNCTIONS; i++) {
        module_function_entry_t entry;
        if (mfs_read(registry, i * sizeof(entry), &entry, sizeof(entry)) == 0) {
            if (entry.module_name[0] == '\0') {  // Empty slot
                // Fill entry
                strcpy(entry.module_name, module_name);
                strcpy(entry.function_name, function_name);
                strcpy(entry.full_port_name, module_name);
                strcat(entry.full_port_name, "_");
                strcat(entry.full_port_name, function_name);
                
                // Write back
                mfs_write(registry, i * sizeof(entry), &entry, sizeof(entry));
                
                print("REGISTRY: Registered ");
                print(module_name);
                print(".");
                println(function_name);
                return;
            }
        }
    }

}
