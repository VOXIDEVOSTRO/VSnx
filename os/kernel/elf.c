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
  ELF THREAD LOADER - COMPLETE ELF EXECUTION IN THREADS
================================================================================================================*/

// Get symbol name from ELF string table
int get_symbol_name_from_elf(int fd, elf64_header_t* elf_header, uint32_t name_offset, char* name_buffer, size_t buffer_size) {
    if (name_offset == 0) return 0;  // No name
    
    // Find string table section
    for (int i = 0; i < elf_header->e_shnum; i++) {
        int rerrno = 0;
        if (fat_lseek(fd, elf_header->e_shoff + i * sizeof(elf64_section_t), SEEK_SET, &rerrno) < 0) {
            continue;
        }
        
        elf64_section_t sh;
        if (fs_read(fd, &sh, sizeof(sh)) != sizeof(sh)) {
            continue;
        }
        
        // Found string table (SHT_STRTAB = 3)
        if (sh.sh_type == 3) {
            // Seek to the name in the string table
            if (fat_lseek(fd, sh.sh_offset + name_offset, SEEK_SET, &rerrno) < 0) {
                continue;
            }
            
            // Read the name
            int name_len = 0;
            while (name_len < buffer_size - 1) {
                char c;
                if (fs_read(fd, &c, 1) != 1) break;
                if (c == '\0') break;
                name_buffer[name_len++] = c;
            }
            name_buffer[name_len] = '\0';
            
            return (name_len > 0) ? 1 : 0;
        }
    }
    
    return 0;  // String table not found
}

/**
 * ELF Symbol Resolver and Function Extractor
 * 
 * This function loads an ELF file, extracts all function symbols,
 * creates MFS segments for each function, and writes the function
 * code into the corresponding MFS segment.
 * 
 * Parameters:
 *   elf_path: path to the ELF file in the filesystem
 *   module_dir_name: name of the directory under /MODULES/ to create for this module
 * 
 * Returns:
 *   0 on success, -1 on failure
 */

// Remove the global array and use MFS instead
void store_elf_mapping(const char* thread_name, uint64_t elf_base, uint64_t mfs_base, size_t size) {
    // Find or create ELF_MAPPINGS directory in MFS
    mfs_entry_t* mappings_dir = mfs_find("ELF_MAPPINGS", mfs_sb.root_dir);
    if (!mappings_dir) {
        mappings_dir = mfs_dir("ELF_MAPPINGS", mfs_sb.root_dir);
        if (!mappings_dir) return;
    }
    
    // Create mapping entry for this thread
    char mapping_name[64];
    strcpy(mapping_name, thread_name);
    strcat(mapping_name, "_map");
    
    // Create MFS segment to store mapping data
    typedef struct {
        uint64_t elf_base;
        uint64_t mfs_base;
        size_t size;
        char thread_name[32];
    } mapping_data_t;
    
    mfs_entry_t* mapping_segment = mfs_seg(mapping_name, sizeof(mapping_data_t), mappings_dir);
    if (!mapping_segment) return;
    
    // Write mapping data to MFS
    mapping_data_t mapping;
    mapping.elf_base = elf_base;
    mapping.mfs_base = mfs_base;
    mapping.size = size;
    strcpy(mapping.thread_name, thread_name);
    
    mfs_write(mapping_segment, 0, &mapping, sizeof(mapping));
}

int elf_resolve_and_map_functions(const char* elf_path, const char* module_dir_name) {
    if (!elf_path || !module_dir_name) {
        println("elf_resolve_and_map_functions: Invalid parameters");
        return -1;
    }

    // Initialize module system and MFS if needed
    init_module_system();
    if (!modules_dir) {
        println("elf_resolve_and_map_functions: MODULES directory not initialized");
        return -1;
    }

    // Open ELF file
    int fd = fs_open(elf_path);
    if (fd < 0) {
        println("elf_resolve_and_map_functions: Failed to open ELF file");
        return -1;
    }

    // Read ELF header
    elf64_header_t elf_header;
    if (fs_read(fd, &elf_header, sizeof(elf_header)) != sizeof(elf_header)) {
        println("elf_resolve_and_map_functions: Failed to read ELF header");
        fs_close(fd);
        return -1;
    }

    // Validate ELF magic
    if (elf_header.e_ident[0] != 0x7F || elf_header.e_ident[1] != 'E' ||
        elf_header.e_ident[2] != 'L' || elf_header.e_ident[3] != 'F') {
        println("elf_resolve_and_map_functions: Invalid ELF magic");
        fs_close(fd);
        return -1;
    }

    // Create module directory under /MODULES/
    mfs_entry_t* module_dir = mfs_dir(module_dir_name, modules_dir);
    if (!module_dir) {
        println("elf_resolve_and_map_functions: Failed to create module directory");
        fs_close(fd);
        return -1;
    }

    // Allocate memory for section headers
    elf64_section_t* sections = (elf64_section_t*)malloc(elf_header.e_shnum * sizeof(elf64_section_t));
    if (!sections) {
        println("elf_resolve_and_map_functions: Failed to allocate memory for section headers");
        fs_close(fd);
        return -1;
    }

    // Read all section headers
    for (int i = 0; i < elf_header.e_shnum; i++) {
        int rerrno = 0;
        if (fat_lseek(fd, elf_header.e_shoff + i * sizeof(elf64_section_t), SEEK_SET, &rerrno) < 0) {
            println("elf_resolve_and_map_functions: Failed to seek to section header");
            free(sections);
            fs_close(fd);
            return -1;
        }
        if (fs_read(fd, &sections[i], sizeof(elf64_section_t)) != sizeof(elf64_section_t)) {
            println("elf_resolve_and_map_functions: Failed to read section header");
            free(sections);
            fs_close(fd);
            return -1;
        }
    }

    // Find string table section for symbol names
    elf64_section_t* strtab_section = NULL;
    for (int i = 0; i < elf_header.e_shnum; i++) {
        if (sections[i].sh_type == 3) { // SHT_STRTAB
            strtab_section = &sections[i];
            break;
        }
    }
    if (!strtab_section) {
        println("elf_resolve_and_map_functions: String table section not found");
        free(sections);
        fs_close(fd);
        return -1;
    }

    // Read string table into memory
    char* strtab = (char*)malloc(strtab_section->sh_size);
    if (!strtab) {
        println("elf_resolve_and_map_functions: Failed to allocate string table buffer");
        free(sections);
        fs_close(fd);
        return -1;
    }
    int rerrno = 0;
    if (fat_lseek(fd, strtab_section->sh_offset, SEEK_SET, &rerrno) < 0) {
        println("elf_resolve_and_map_functions: Failed to seek to string table");
        free(strtab);
        free(sections);
        fs_close(fd);
        return -1;
    }
    if (fs_read(fd, strtab, strtab_section->sh_size) != (int)strtab_section->sh_size) {
        println("elf_resolve_and_map_functions: Failed to read string table");
        free(strtab);
        free(sections);
        fs_close(fd);
        return -1;
    }

    // Find symbol table section
    elf64_section_t* symtab_section = NULL;
    for (int i = 0; i < elf_header.e_shnum; i++) {
        if (sections[i].sh_type == SHT_SYMTAB) {
            symtab_section = &sections[i];
            break;
        }
    }
    if (!symtab_section) {
        println("elf_resolve_and_map_functions: Symbol table section not found");
        free(strtab);
        free(sections);
        fs_close(fd);
        return -1;
    }

    // Number of symbols
    int num_symbols = symtab_section->sh_size / sizeof(elf64_symbol_t);

    // Process each symbol
    for (int i = 0; i < num_symbols; i++) {
        // Read symbol
        elf64_symbol_t sym;
        if (fat_lseek(fd, symtab_section->sh_offset + i * sizeof(elf64_symbol_t), SEEK_SET, &rerrno) < 0) {
            println("elf_resolve_and_map_functions: Failed to seek to symbol");
            continue;
        }
        if (fs_read(fd, &sym, sizeof(elf64_symbol_t)) != sizeof(elf64_symbol_t)) {
            println("elf_resolve_and_map_functions: Failed to read symbol");
            continue;
        }

        // Check if symbol is a function
        if ((sym.st_info & 0xF) == STT_FUNC && sym.st_size > 0) {
            // Get function name
            const char* func_name = &strtab[sym.st_name];
            if (!func_name || func_name[0] == '\0') {
                continue;
            }

            // Create MFS segment for function pointer (8 bytes for 64-bit pointer)
            mfs_entry_t* func_segment = mfs_seg(func_name, sizeof(uint64_t), module_dir);
            if (!func_segment) {
                print("elf_resolve_and_map_functions: Failed to create segment for function pointer ");
                println(func_name);
                continue;
            }

            // Calculate the virtual address where this function will be loaded
            // This assumes the ELF is loaded at a base address and we're calculating the runtime address
            uint64_t func_ptr = sym.st_value; // This would be the actual runtime address

            // Write function pointer to MFS segment
            if (mfs_write(func_segment, 0, &func_ptr, sizeof(func_ptr)) != 0) {
                print("elf_resolve_and_map_functions: Failed to write function pointer for ");
                println(func_name);
                continue;
            }

            print("elf_resolve_and_map_functions: Mapped function pointer ");
            println(func_name);
        }
    }

    free(strtab);
    free(sections);
    fs_close(fd);

    println("elf_resolve_and_map_functions: Completed symbol resolution and pointer mapping");
    return 0;
}

// COMPLETE ELF THREAD LOADER - USING CORRECT FILESYSTEM API
uint32_t elf_thread_loader(const char* elf_path, const char* thread_name) {
    println("ELF_LOADER: Starting complete ELF thread loading");
    
    print("ELF_LOADER: Loading ELF file: ");
    println(elf_path);
    
    // Open ELF file using correct fs_open
    int fd = fs_open(elf_path);
    if (fd < 0) {
        println("ELF_LOADER: ERROR - Cannot open ELF file");
        return 0;
    }
    
    println("ELF_LOADER: ELF file opened successfully");
    
    // Read ELF header
    elf64_header_t elf_header;
    if (fs_read(fd, &elf_header, sizeof(elf_header)) != sizeof(elf_header)) {
        println("ELF_LOADER: ERROR - Cannot read ELF header");
        fs_close(fd);
        return 0;
    }
    
    // Validate ELF magic
    if (*(uint32_t*)elf_header.e_ident != ELF_MAGIC) {
        println("ELF_LOADER: ERROR - Invalid ELF magic");
        fs_close(fd);
        return 0;
    }
    
    print("ELF_LOADER: ELF entry point: ");
    char addr_str[16];
    uint64_to_hex(elf_header.e_entry, addr_str);
    println(addr_str);
    
    // Create threads directory if not exists
    mfs_entry_t* threads_dir = mfs_find("THREADS", mfs_sb.root_dir);
    if (!threads_dir) {
        println("ELF_LOADER: ERROR - Cannot find threads directory");
        fs_close(fd);
        return 0;
    }
    
    // Create ELF-specific directory
    char elf_dir_name[64];
    int pos = 0;
    for (int i = 0; thread_name[i] && pos < 60; i++) {
        elf_dir_name[pos++] = thread_name[i];
    }
    elf_dir_name[pos++] = '_'; elf_dir_name[pos++] = 'e'; elf_dir_name[pos++] = 'l'; elf_dir_name[pos++] = 'f';
    elf_dir_name[pos] = '\0';
    
    mfs_entry_t* elf_dir = mfs_dir(elf_dir_name, threads_dir);
    if (!elf_dir) {
        println("ELF_LOADER: ERROR - Cannot create ELF directory");
        fs_close(fd);
        return 0;
    }
    
    println("ELF_LOADER: Created ELF directory in MFS");
    
    // Process program headers
    uint64_t code_segment_addr = 0;
    size_t total_memory_needed = 0;
    
    for (int i = 0; i < elf_header.e_phnum; i++) {
        // FIXED: Use fat_lseek with correct parameters
        int rerrno = 0;
        if (fat_lseek(fd, elf_header.e_phoff + i * sizeof(elf64_program_header_t), SEEK_SET, &rerrno) < 0) {
            println("ELF_LOADER: ERROR - Cannot seek to program header");
            fs_close(fd);
            return 0;
        }
        
        elf64_program_header_t ph;
        if (fs_read(fd, &ph, sizeof(ph)) != sizeof(ph)) {
            println("ELF_LOADER: ERROR - Cannot read program header");
            fs_close(fd);
            return 0;
        }
        
        if (ph.p_type == PT_LOAD) {
            print("ELF_LOADER: LOAD segment - VAddr: ");
            uint64_to_hex(ph.p_vaddr, addr_str);
            print(addr_str);
            print(" Size: ");
            uint64_to_hex(ph.p_memsz, addr_str);
            println(addr_str);

			// In the existing loop, modify the registration:
			if (ph.p_flags & PF_X) {
			    code_segment_addr = ph.p_vaddr;
			
			    // REGISTER WITH INTERRUPT SYSTEM
			    print("ELF_LOADER: Registering ");
			    print(thread_name);
			    println(" with interrupt system");
			    register_dynamic_port_processor(thread_name, code_segment_addr + 0x290);
			
			    // INCREMENT MODULE COUNTER
			    loaded_modules_count++;
			
			    // ACTIVATE INTERRUPT PROCESSING AFTER 2 MODULES
			    if (loaded_modules_count >= 2 && !interrupt_processing_active) {
			        println("ELF_LOADER: 2+ modules loaded - ACTIVATING interrupt processing");
			        interrupt_processing_active = 1;
			    }
			}
            
            total_memory_needed += ph.p_memsz;
        }
    }
    
    // Create unified memory segment for entire ELF
    char memory_segment_name[64];
    pos = 0;
    for (int i = 0; thread_name[i] && pos < 50; i++) {
        memory_segment_name[pos++] = thread_name[i];
    }
    memory_segment_name[pos++] = '_'; memory_segment_name[pos++] = 'm'; memory_segment_name[pos++] = 'e'; memory_segment_name[pos++] = 'm';
    memory_segment_name[pos] = '\0';
    
    // Allocate memory segment (round up to page boundary)
    size_t segment_size = (total_memory_needed + 4095) & ~4095;
    mfs_entry_t* memory_segment = mfs_seg(memory_segment_name, segment_size, elf_dir);
    if (!memory_segment) {
        println("ELF_LOADER: ERROR - Cannot create memory segment");
        fs_close(fd);
        return 0;
    }
    
    println("ELF_LOADER: Created unified memory segment");

	// DEBUG: Dump first 64 bytes of loaded memory to see what's there
	print("ELF_LOADER: Memory dump at ");
	uint64_to_hex(memory_segment->start_addr, addr_str);
	println(addr_str);

	uint8_t* mem_data = (uint8_t*)memory_segment->start_addr;
	for (int i = 0; i < 64; i += 16) {
	    print("ELF_LOADER: ");
	    uint64_to_hex(memory_segment->start_addr + i, addr_str);
	    print(addr_str);
	    print(": ");
	    for (int j = 0; j < 16 && i + j < 64; j++) {
	        char hex_str[4];
	        hex_str[0] = "0123456789ABCDEF"[mem_data[i + j] >> 4];
	        hex_str[1] = "0123456789ABCDEF"[mem_data[i + j] & 0xF];
	        hex_str[2] = ' ';
	        hex_str[3] = '\0';
	        print(hex_str);
	    }
	    println("");
	}
    
    // Load all LOAD segments into memory
    uint64_t entry_point_addr = 0;
    
    for (int i = 0; i < elf_header.e_phnum; i++) {
        // FIXED: Use fat_lseek with correct parameters
        int rerrno = 0;
        if (fat_lseek(fd, elf_header.e_phoff + i * sizeof(elf64_program_header_t), SEEK_SET, &rerrno) < 0) {
            println("ELF_LOADER: ERROR - Cannot seek to program header");
            fs_close(fd);
            return 0;
        }
        
        elf64_program_header_t ph;
        fs_read(fd, &ph, sizeof(ph));
        
        if (ph.p_type == PT_LOAD) {
            print("ELF_LOADER: Loading segment at offset ");
            uint64_to_hex(ph.p_vaddr, addr_str);
            println(addr_str);
            
            // Calculate offset in our memory segment
            uint64_t segment_offset = ph.p_vaddr - code_segment_addr;
            
            // FIXED: Use fat_lseek with correct parameters
            if (fat_lseek(fd, ph.p_offset, SEEK_SET, &rerrno) < 0) {
                println("ELF_LOADER: ERROR - Cannot seek to segment data");
                fs_close(fd);
                return 0;
            }
            
            // Read segment data in chunks
            uint8_t buffer[1024];
            size_t remaining = ph.p_filesz;
            size_t current_offset = segment_offset;
            
            while (remaining > 0) {
                size_t chunk_size = (remaining > 1024) ? 1024 : remaining;
                
                if (fs_read(fd, buffer, chunk_size) != chunk_size) {
                    println("ELF_LOADER: ERROR - Cannot read segment data");
                    fs_close(fd);
                    return 0;
                }
                
                if (mfs_write(memory_segment, current_offset, buffer, chunk_size) != 0) {
                    println("ELF_LOADER: ERROR - Cannot write to memory segment");
                    fs_close(fd);
                    return 0;
                }
                
                remaining -= chunk_size;
                current_offset += chunk_size;
            }
            
            // Calculate actual entry point address
            if (ph.p_flags & PF_X) {
                entry_point_addr = memory_segment->start_addr + (elf_header.e_entry - ph.p_vaddr);
            }
        }
    }

	// DEBUG: Check if string data exists in loaded memory
	println("ELF_LOADER: Searching for string data in loaded memory");
	uint8_t* search_data = (uint8_t*)memory_segment->start_addr;
	for (size_t i = 0; i < total_memory_needed - 12; i++) {
	    if (search_data[i] == 'H' && search_data[i+1] == 'e' && search_data[i+2] == 'l') {
	        print("ELF_LOADER: Found 'Hel' at offset ");
	        uint64_to_hex(i, addr_str);
	        println(addr_str);
	    }
	}
    
    print("ELF_LOADER: Calculated entry point: ");
    uint64_to_hex(entry_point_addr, addr_str);
    println(addr_str);

		// RELOCATE STRING POINTERS - Update hardcoded addresses in loaded code
	println("ELF_LOADER: Relocating string pointers");
    
    // CRITICAL FIX: Create the code segment name that matches what create_thread expects
    char code_segment_name[64];
	pos = 0;  // RESET pos to 0!
    for (int i = 0; thread_name[i] && pos < 50; i++) {
        code_segment_name[pos++] = thread_name[i];
    }
    code_segment_name[pos++] = '_'; 
    code_segment_name[pos++] = 'c'; 
    code_segment_name[pos++] = 'o'; 
    code_segment_name[pos++] = 'd'; 
    code_segment_name[pos++] = 'e';
    code_segment_name[pos] = '\0';
    
    println("ELF_LOADER: ELF loaded successfully into MFS");
    
    // Create the memory segment with the EXACT name the thread system expects
    mfs_entry_t* code_segment = mfs_seg(code_segment_name, segment_size, threads_dir);
    if (!code_segment) {
        println("ELF_LOADER: ERROR - Cannot create code segment");
        fs_close(fd);
        return 0;
    }

	// Calculate relocation to code_segment address
	uint64_t relocation_offset = code_segment->start_addr - code_segment_addr;
	uint8_t* loaded_data = (uint8_t*)memory_segment->start_addr;

	
	// RELOCATE 32-BIT ADDRESSES IN INSTRUCTION ENCODING
	println("ELF_LOADER: Relocating 32-bit addresses in instructions");
	
	for (size_t offset = 0; offset < total_memory_needed - 4; offset += 1) {
	    uint32_t* addr32 = (uint32_t*)(loaded_data + offset);
	
	    // Check if this 32-bit value is in our ELF address range
	    if (*addr32 >= (uint32_t)code_segment_addr && *addr32 < (uint32_t)(code_segment_addr + total_memory_needed)) {
	        uint32_t old_addr = *addr32;
	        *addr32 = old_addr + (uint32_t)relocation_offset;
		
	        print("ELF_LOADER: Relocated 32-bit address from ");
	        uint64_to_hex(old_addr, addr_str);
	        print(addr_str);
	        print(" to ");
	        uint64_to_hex(*addr32, addr_str);
	        print(addr_str);
	        print(" at offset ");
	        uint64_to_hex(offset, addr_str);
	        println(addr_str);
	    }
	}

    // Copy all the loaded ELF data to this segment
	uint8_t* elf_data = (uint8_t*)memory_segment->start_addr;
	if (mfs_write(code_segment, 0, elf_data, total_memory_needed) != 0) {  // Use total_memory_needed, not segment_size
        println("ELF_LOADER: ERROR - Cannot copy ELF data to code segment");
        fs_close(fd);
        return 0;
    }

	// SYMBOL RESOLUTION WITH RELOCATED ADDRESSES - Add after relocation
	println("ELF_LOADER: Resolving function symbols with relocated addresses");

	// Find MODULES directory for function pointer storage
	mfs_entry_t* modules_dir = mfs_find("MODULES", mfs_sb.root_dir);
	if (!modules_dir) {
	    modules_dir = mfs_dir("MODULES", mfs_sb.root_dir);
	}

	// Create module directory
	mfs_entry_t* module_dir = mfs_dir(thread_name, modules_dir);
	if (module_dir) {
	    // Process section headers to find symbol table
	    for (int i = 0; i < elf_header.e_shnum; i++) {
	        int rerrno = 0;
	        if (fat_lseek(fd, elf_header.e_shoff + i * sizeof(elf64_section_t), SEEK_SET, &rerrno) < 0) {
	            continue;
	        }
		
	        elf64_section_t sh;
	        if (fs_read(fd, &sh, sizeof(sh)) != sizeof(sh)) {
	            continue;
	        }
		
	        // Found symbol table
	        if (sh.sh_type == 2) {  // SHT_SYMTAB = 2
	            int num_symbols = sh.sh_size / sizeof(elf64_symbol_t);
			
	            for (int j = 0; j < num_symbols; j++) {
	                if (fat_lseek(fd, sh.sh_offset + j * sizeof(elf64_symbol_t), SEEK_SET, &rerrno) < 0) {
	                    continue;
	                }
				
	                elf64_symbol_t sym;
	                if (fs_read(fd, &sym, sizeof(sym)) != sizeof(sym)) {
	                    continue;
	                }
				
	                // Check if this is a function symbol
	                if ((sym.st_info & 0xF) == 2 && sym.st_name != 0) {  // STT_FUNC = 2
	                    // Get function name from string table
	                    char func_name[64] = {0};
	                    if (get_symbol_name_from_elf(fd, &elf_header, sym.st_name, func_name, sizeof(func_name))) {
	                        // Create MFS segment for RELOCATED function pointer
	                        mfs_entry_t* func_segment = mfs_seg(func_name, sizeof(uint64_t), module_dir);
	                        if (func_segment) {
	                            // CRITICAL: Store RELOCATED address, not original
	                            uint64_t relocated_func_ptr = sym.st_value + relocation_offset;
	                            mfs_write(func_segment, 0, &relocated_func_ptr, sizeof(relocated_func_ptr));
							
	                            print("ELF_LOADER: Mapped relocated function ");
	                            print(func_name);
	                            print(" at ");
	                            uint64_to_hex(relocated_func_ptr, addr_str);
	                            println(addr_str);
	                        }
	                    }
	                }
	            }
	            break;
	        }
	    }
	}
    
    // Create thread with the correct code segment name
    uint32_t thread_id = create_thread(code_segment_name, thread_name, 5, 16384);
    if (thread_id == 0) {
        println("ELF_LOADER: ERROR - Cannot create thread");
        return 0;
    }

	fs_close(fd);
    
    print("ELF_LOADER: Created ELF thread with ID ");
    char num_str[8];
    uint64_to_hex(thread_id, num_str);
    println(num_str);
    
    return thread_id;
}

