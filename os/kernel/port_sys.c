#include "include.h"
/*==============================================================================================================
  PORT SYSTEM
================================================================================================================*/

// Update init_port_system() to use fixed address
void init_port_system (void) {
    println("PORT: Initializing mailbox communication system");
    
    // Create PORTS directory in MFS ROOT
    ports_dir = mfs_dir("PORTS", mfs_sb.root_dir);
    if (!ports_dir) {
        println("PORT: Failed to create PORTS directory");
        return;
    }

    // Create printf port at FIXED address 0x20100000
    mfs_entry_t* printf_port_entry = mfs_seg_at("printf", sizeof(port_message_t), 
                                                 0x20100000, ports_dir);
    if (printf_port_entry) {
        // Initialize port at known address
        port_message_t* printf_port = (port_message_t*)0x20100000;
        printf_port->magic = PORT_MAGIC;
        
        // Copy port name
        printf_port->port_name[0] = 'p';
        printf_port->port_name[1] = 'r';
        printf_port->port_name[2] = 'i';
        printf_port->port_name[3] = 'n';
        printf_port->port_name[4] = 't';
        printf_port->port_name[5] = 'f';
        printf_port->port_name[6] = '\0';
        
        printf_port->status = PORT_STATUS_EMPTY;
        printf_port->request_id = 0;
        printf_port->data_size = 0;
		printf_port->notification_flag = 0;  // ADD THIS LINE
        
        println("PORT: Created printf port at fixed address 0x20100000");
    }

	// In init_port_system(), add:
	mfs_entry_t* syscall_port = mfs_seg_at("syscall", sizeof(port_message_t), 0x20110000, ports_dir);
	if (syscall_port) {
	    port_message_t* port = (port_message_t*)syscall_port->start_addr;
	    port->magic = PORT_MAGIC;
	    strcpy(port->port_name, "syscall");
	    port->status = PORT_STATUS_EMPTY;
	    println("PORT: Created syscall port");
	}

    // Create other kernel service ports (at dynamic addresses)
    create_port("kernel_load_module");
    create_port("kernel_call_module");
    
    println("PORT: PORTS directory created successfully");
}

// Create a port for a specific function
int create_port(const char* port_name) {
    if (!ports_dir) {
        return -1;
    }
    
    // Create port segment
    mfs_entry_t* port_segment = mfs_seg(port_name, sizeof(port_message_t), ports_dir);
    if (!port_segment) {
        return -1;
    }
    
    // Initialize port message
    port_message_t* port = (port_message_t*)port_segment->start_addr;
    port->magic = PORT_MAGIC;
    
    // Copy port name
    for (int i = 0; i < MAX_PORT_NAME-1 && port_name[i]; i++) {
        port->port_name[i] = port_name[i];
        port->port_name[i+1] = '\0';
    }
    
    port->status = PORT_STATUS_EMPTY;
    port->request_id = 0;
    port->data_size = 0;
    port->notification_flag = 0;  // ADD THIS LINE - initialize notification flag
    
    print("PORT: Created port ");
    println(port_name);
    
    return 0;
}

#define MFS_TYPE_DIRECTORY 2

int call_func_port(const char* app_name, const char* func_name, void* args, size_t args_size) {
    char port_name[128];
    strcpy(port_name, app_name);
    strcat(port_name, "_");
    strcat(port_name, func_name);

    mfs_entry_t* ports_dir = mfs_find("PORTS", mfs_sb.root_dir);
    if (!ports_dir) return -1;
    mfs_entry_t* func_port = mfs_find(port_name, ports_dir);
    if (!func_port) return -1;

    port_message_t port_snapshot;
    if (mfs_read(func_port, 0, &port_snapshot, sizeof(port_message_t)) != 0) return -1;
    if (port_snapshot.status != PORT_STATUS_EMPTY) {
        // Port is busy, return immediately (let the scheduler run other threads)
        return -2;
    }

    // Prepare request_id (unique for this call)
    int my_request_id = port_snapshot.request_id + 1;

    // Write request to port (using mfs_write for all fields)
    if (args && args_size > 0 && args_size <= sizeof(port_snapshot.data)) {
        mfs_write(func_port, offsetof(port_message_t, data), args, args_size);
        mfs_write(func_port, offsetof(port_message_t, data_size), &args_size, sizeof(args_size));
    } else {
        size_t zero = 0;
        mfs_write(func_port, offsetof(port_message_t, data_size), &zero, sizeof(zero));
    }
    int status = PORT_STATUS_REQUEST;
    mfs_write(func_port, offsetof(port_message_t, status), &status, sizeof(status));
    mfs_write(func_port, offsetof(port_message_t, request_id), &my_request_id, sizeof(my_request_id));
    int notif = 1;
    mfs_write(func_port, offsetof(port_message_t, notification_flag), &notif, sizeof(notif));

    // Return immediately; the caller can check for response later
    return 0;
}

// Process port requests (called by kernel periodically) - DEBUG VERSION
void process_ports (void) {
    if (!ports_dir) {
        println("DEBUG: ports_dir is NULL");
        return;
    }
    
    mfs_superblock_t* sb = (mfs_superblock_t*)&mfs_sb;
    mfs_entry_t* entry_table = (mfs_entry_t*)sb->entry_table;
    
    int ports_found = 0;
    int requests_found = 0;
    
    // Scan all segments and check if they're port messages
    for (int i = 0; i < MFS_MAX_ENTRIES; i++) {
        if (entry_table[i].magic == MFS_MAGIC && 
            entry_table[i].type == MFS_TYPE_SEGMENT &&
            entry_table[i].size == sizeof(port_message_t)) {  // Port-sized segments
            
            ports_found++;
            port_message_t* port = (port_message_t*)entry_table[i].start_addr;
            
            // Validate it's actually a port
            if (port->magic == PORT_MAGIC) {
                
                if (port->status == PORT_STATUS_REQUEST) {
                    requests_found++;
                    
                    // Process the request
                    process_port_request(port);
                }
            }
        }
    }
}

// Update process_port_request() to handle printf
void process_port_request(port_message_t* port) {
    int param1 = *((int*)&port->data[0]);
    int param2 = *((int*)&port->data[4]);
	char* function_name = (char*)port->data;
    int result = 0;
	if (strcmp(function_name, "printf") == 0) {
	    char* str = (char*)port->data + 32;
	    print(str);
		
	    *((int*)&port->result[0]) = 0;  // Success result
	    port->status = PORT_STATUS_RESPONSE;
	    return;
	}   
    // MFS Functions
    else if (strcmp(function_name, "mfs_find") == 0) {
        char* name = (char*)port->data + 32;
        void* parent = *((void**)&port->data[96]);
        mfs_entry_t* result = mfs_find(name, parent);
        *((mfs_entry_t**)&port->result[0]) = result;
		port->status = PORT_STATUS_RESPONSE;
		return;
        
    } else if (strcmp(function_name, "mfs_read") == 0) {
        mfs_entry_t* entry = *((mfs_entry_t**)&port->data[32]);
        uint64_t offset = *((uint64_t*)&port->data[40]);
        void* buffer = *((void**)&port->data[48]);
        size_t size = *((size_t*)&port->data[56]);
        int result = mfs_read(entry, offset, buffer, size);
        *((int*)&port->result[0]) = result;
		port->status = PORT_STATUS_RESPONSE;
        return;
    } else if (strcmp(function_name, "mfs_write") == 0) {
        mfs_entry_t* entry = *((mfs_entry_t**)&port->data[32]);
        uint64_t offset = *((uint64_t*)&port->data[40]);
        void* buffer = *((void**)&port->data[48]);
        size_t size = *((size_t*)&port->data[56]);
        int result = mfs_write(entry, offset, buffer, size);
        *((int*)&port->result[0]) = result;
		port->status = PORT_STATUS_RESPONSE;
        return;
    } else if (strcmp(function_name, "mfs_seg") == 0) {
        char* name = (char*)port->data + 32;
        size_t size = *((size_t*)&port->data[96]);
        void* parent = *((void**)&port->data[104]);
        mfs_entry_t* result = mfs_seg(name, size, parent);
        *((mfs_entry_t**)&port->result[0]) = result;
		port->status = PORT_STATUS_RESPONSE;
        return;
    } else if (strcmp(function_name, "mfs_dir") == 0) {
        char* name = (char*)port->data + 32;
        void* parent = *((void**)&port->data[96]);
        mfs_entry_t* result = mfs_dir(name, parent);
        *((mfs_entry_t**)&port->result[0]) = result;
		port->status = PORT_STATUS_RESPONSE;
		return;
	} else if (strcmp(function_name, "get_root_dir") == 0) {
    	// Return pointer to root directory
    	*((mfs_entry_t**)&port->result[0]) = mfs_sb.root_dir;
		port->status = PORT_STATUS_RESPONSE;
		return;
	} else if (strcmp(function_name, "get_mfs_superblock") == 0) {
	    *((mfs_superblock_t**)&port->result[0]) = &mfs_sb;
		port->status = PORT_STATUS_RESPONSE;
		return;
	} else if (strcmp(function_name, "get_mfs_entry_table") == 0) {
	    mfs_superblock_t* sb = (mfs_superblock_t*)&mfs_sb;
	    *((mfs_entry_t**)&port->result[0]) = (mfs_entry_t*)sb->entry_table;
		port->status = PORT_STATUS_RESPONSE;
		return;
	} else if (strcmp(function_name, "get_ports_dir") == 0) {
	    mfs_entry_t* ports_directory = mfs_find("PORTS", mfs_sb.root_dir);
	    *((mfs_entry_t**)&port->result[0]) = ports_directory;
		port->status = PORT_STATUS_RESPONSE;
		return;
    // Memory Functions
    } else if (strcmp(function_name, "malloc") == 0) {
        size_t size = *((size_t*)&port->data[32]);
        void* result = malloc(size);
        *((void**)&port->result[0]) = result;
		port->status = PORT_STATUS_RESPONSE;
		return;
        
    } else if (strcmp(function_name, "free") == 0) {
        void* ptr = *((void**)&port->data[32]);
        free(ptr);
        *((int*)&port->result[0]) = 0;  // Success
		port->status = PORT_STATUS_RESPONSE;
		return;
        
    // Time Functions
    } else if (strcmp(function_name, "get_uptime") == 0) {
        uint32_t uptime = get_uptime_seconds();
        *((uint32_t*)&port->result[0]) = uptime;
        port->status = PORT_STATUS_RESPONSE;
		return;
    } else if (strcmp(function_name, "show_uptime") == 0) {
        show_uptime();
        *((int*)&port->result[0]) = 0;  // Success
        port->status = PORT_STATUS_RESPONSE;
		return;
    // File System Functions
    } else if (strcmp(function_name, "fs_open") == 0) {
        char* path = (char*)port->data + 32;
        int result = fs_open(path);
        *((int*)&port->result[0]) = result;
        port->status = PORT_STATUS_RESPONSE;
		return;
    } else if (strcmp(function_name, "fs_close") == 0) {
        int fd = *((int*)&port->data[32]);
        int result = fs_close(fd);
        *((int*)&port->result[0]) = result;
        port->status = PORT_STATUS_RESPONSE;
		return;
    } else if (strcmp(function_name, "fs_read") == 0) {
        int fd = *((int*)&port->data[32]);
        void* buffer = *((void**)&port->data[36]);
        size_t size = *((size_t*)&port->data[44]);
        int result = fs_read(fd, buffer, size);
        *((int*)&port->result[0]) = result;
        port->status = PORT_STATUS_RESPONSE;
		return;
    } else if (strcmp(function_name, "fs_ls") == 0) {
        char* path = (char*)port->data + 32;
        fs_ls(path);
        *((int*)&port->result[0]) = 0;
        port->status = PORT_STATUS_RESPONSE;
		return;
    } else if (strcmp(function_name, "get_mfs_superblock") == 0) {
        *((mfs_superblock_t**)&port->result[0]) = &mfs_sb;
        port->status = PORT_STATUS_RESPONSE;
		return;
    } else if (strcmp(function_name, "get_mfs_entry_table") == 0) {
        mfs_superblock_t* sb = (mfs_superblock_t*)&mfs_sb;
        *((mfs_entry_t**)&port->result[0]) = (mfs_entry_t*)sb->entry_table;
        port->status = PORT_STATUS_RESPONSE;
		return;
    } else if (strcmp(function_name, "get_ports_dir") == 0) {
        mfs_entry_t* ports_directory = mfs_find("PORTS", mfs_sb.root_dir);
        *((mfs_entry_t**)&port->result[0]) = ports_directory;
		port->status = PORT_STATUS_RESPONSE;
		return;
	} else if (strcmp(function_name, "call_module") == 0) {
	    char* target_app = (char*)port->data + 32;
	    char* func_name = (char*)port->data + 96;
	    void* args = (void*)port->data + 128;
	    size_t args_size = port->data_size;
	    void* result = (void*)port->result;
	    size_t result_size = sizeof(port->result);

	    int call_result = call_func_port(target_app, func_name, args, args_size);

	    port->status = PORT_STATUS_RESPONSE;
	    *((int*)&port->result[0]) = call_result;
		port->status = PORT_STATUS_RESPONSE;
		return;
	}
	else if (strcmp(function_name, "make_vga_entry") == 0) {
	    char c = port->data[0];
	    unsigned char color = (unsigned char)port->data[1];
	    unsigned short entry = make_vga_entry(c, color);
	    *((unsigned short*)&port->result[0]) = entry;
		port->status = PORT_STATUS_RESPONSE;
		return;
	}	
	else if (strcmp(function_name, "vga_write_safe") == 0) {
	    int x = *((int*)&port->data[0]);
	    int y = *((int*)&port->data[4]);
	    char c = port->data[8];
	    unsigned char color = (unsigned char)port->data[9];
	    vga_write_safe(x, y, c, color);
	    *((int*)&port->result[0]) = 0;
		port->status = PORT_STATUS_RESPONSE;
		return;
	}
	else if (strcmp(function_name, "clear_screen") == 0) {
	    clear_screen();
	    *((int*)&port->result[0]) = 0;
		port->status = PORT_STATUS_RESPONSE;
		return;
	}
	else if (strcmp(function_name, "scroll_screen") == 0) {
	    scroll_screen();
	    *((int*)&port->result[0]) = 0;
		port->status = PORT_STATUS_RESPONSE;
		return;
	}
	else if (strcmp(function_name, "getchar") == 0) {
	    int ch = kernel_getchar(); // or whatever your kernel input function is
	    *((int*)&port->result[0]) = ch;
		port->status = PORT_STATUS_RESPONSE;
		return;
	}

	else if (strcmp(function_name, "render_char_vbe") == 0) {
	    int px = *((int*)&port->data[0]);
	    int py = *((int*)&port->data[4]);
	    char c = port->data[8];
	    uint32_t color = *((uint32_t*)&port->data[12]);
	    render_char_vbe(px, py, c, color);
	    *((int*)&port->result[0]) = 0; // success
		port->status = PORT_STATUS_RESPONSE;
		return;
	}

	else if (strcmp(function_name, "key_input") == 0) {
	    key_input();
	    *((int*)&port->result[0]) = 0; // success
		port->status = PORT_STATUS_RESPONSE;
		return;
	}

	else if (strcmp(function_name, "clear_screen_vbe") == 0) {
	    uint32_t color = *((uint32_t*)&port->data[0]);
	    clear_screen_vbe(color);
	    *((int*)&port->result[0]) = 0; // success
		port->status = PORT_STATUS_RESPONSE;
		return;
	}

	else if (strcmp(function_name, "load_font") == 0) {
	    char* filename = (char*)port->data;
	    int ret = load_font(filename);
	    *((int*)&port->result[0]) = ret;
		port->status = PORT_STATUS_RESPONSE;
		return;
	}

	else if (strcmp(function_name, "print") == 0) {
	    const size_t max_str_len = 128;
	    if (port->data_size >= max_str_len + sizeof(uint32_t)) {
	        const char* str = (const char*)&port->data[0];
	        uint32_t color = *((uint32_t*)&port->data[max_str_len]);
		
	        // Ensure null-termination
	        char safe_str[max_str_len + 1];
	        memcpy(safe_str, str, max_str_len);
	        safe_str[max_str_len] = '\0';
		
	        print_vbe(safe_str, color);
	        *((int*)&port->result[0]) = 0;
			port->status = PORT_STATUS_RESPONSE;
			return;
	    } else {
	        *((int*)&port->result[0]) = -1;  // Bad data size
			port->status = PORT_STATUS_RESPONSE;
			return;
	    }
	}

	else if (strcmp(function_name, "print_at") == 0) {
	    const size_t max_str_len = 128;
	    if (port->data_size >= 8 + max_str_len + sizeof(uint32_t)) {
	        int x = *((int*)&port->data[0]);
	        int y = *((int*)&port->data[4]);
	        const char* str = (const char*)&port->data[8];
	        uint32_t color = *((uint32_t*)&port->data[8 + max_str_len]);
		
	        // Null-safe
	        char safe_str[max_str_len + 1];
	        memcpy(safe_str, str, max_str_len);
	        safe_str[max_str_len] = '\0';
		
	        print_at_vbe(x, y, safe_str, color);
	        *((int*)&port->result[0]) = 0;
			port->status = PORT_STATUS_RESPONSE;
			return;
	    } else {
	        *((int*)&port->result[0]) = -1;
			port->status = PORT_STATUS_RESPONSE;
			return;
	    }
	}

    else if (strcmp(function_name, "make_color") == 0) {
	    if (port->data_size >= 3) {
	        uint8_t r = port->data[0];
	        uint8_t g = port->data[1];
	        uint8_t b = port->data[2];
	        uint32_t color = make_color(r, g, b);
		
	        *((uint32_t*)&port->result[0]) = color;
			port->status = PORT_STATUS_RESPONSE;
			return;
	    } else {
	        *((int*)&port->result[0]) = -1;
			port->status = PORT_STATUS_RESPONSE;
			return;
	    }
	}

	else if (strcmp(function_name, "renderer_present_mfs") == 0) {
	    if (backbuffer_segment) {
	        renderer_present_mfs();
	        *((int*)&port->result[0]) = 0;
			port->status = PORT_STATUS_RESPONSE;
			return;
	    } else {
	        *((int*)&port->result[0]) = -1;
			port->status = PORT_STATUS_RESPONSE;
			return;
	    }
	}

	else if (strcmp(function_name, "renderer_putpixel_mfs") == 0) {
	    if (backbuffer_segment && port->data_size >= sizeof(int) * 2 + sizeof(uint32_t)) {
	        int x = *((int*)&port->data[0]);
	        int y = *((int*)&port->data[4]);
	        uint32_t color = *((uint32_t*)&port->data[8]);
		
	        renderer_putpixel_mfs(x, y, color);
	        *((int*)&port->result[0]) = 0;
			port->status = PORT_STATUS_RESPONSE;
			return;
	    } else {
	        *((int*)&port->result[0]) = -1;
			port->status = PORT_STATUS_RESPONSE;
			return;
	    }
	}

    // Write response FIRST
	*((int*)&port->data[0]) = result;
	port->data_size = 4;

	// THEN set status to response (don't set to empty yet)
	port->status = PORT_STATUS_RESPONSE;
}

/*==============================================================================================================
  VOSTROX DYNAMIC INTERRUPT-DRIVEN PORT PROCESSING SYSTEM
================================================================================================================*/

// Dynamically register app's check_port_notifications function
void register_dynamic_port_processor(const char* app_name, uint64_t check_notifications_addr) {
    if (dynamic_processor_count < 16) {
        strcpy(dynamic_processors[dynamic_processor_count].app_name, app_name);
        dynamic_processors[dynamic_processor_count].check_notifications_addr = check_notifications_addr;
        dynamic_processors[dynamic_processor_count].active = 1;
        
        print("DYNAMIC: Registered ");
        print(app_name);
        print(".check_port_notifications at ");
        char addr_str[16];
        uint64_to_hex(check_notifications_addr, addr_str);
        println(addr_str);
        
        dynamic_processor_count++;
    }
}

// Call app's check_port_notifications function from interrupt contxt
void call_app_function_from_interrupt(uint64_t function_addr) {
	println("Call_app_function_from_interrupt called");
    if (function_addr == 0) return;
    
    // Save current state
    uint64_t saved_rsp, saved_rbp, saved_rflags;
    __asm__ volatile(
        "movq %%rsp, %0\n"
        "movq %%rbp, %1\n"
        "pushfq; popq %2\n"
        : "=m"(saved_rsp), "=m"(saved_rbp), "=m"(saved_rflags)
    );
    
    // Call the app function directly
    void (*app_function)(void) = (void(*)(void))function_addr;
    app_function();
    
    // Restore state
    __asm__ volatile(
        "movq %0, %%rsp\n"
        "movq %1, %%rbp\n"
        "pushq %2; popfq\n"
        : : "m"(saved_rsp), "m"(saved_rbp), "m"(saved_rflags)
    );
}

// Process ALL registered apps' port notifications in interrupt context
void interrupt_process_all_ports (void) {
	println("Checking...");
    for (int i = 0; i < dynamic_processor_count; i++) {
        if (dynamic_processors[i].active && dynamic_processors[i].check_notifications_addr != 0) {
            // Call each app's check_port_notifications function
            call_app_function_from_interrupt(dynamic_processors[i].check_notifications_addr);
        }
    }
}

/*==============================================================================================================
  VOSTROX PORT NOTIFICATION INTERRUPT - WORKING VERSION
================================================================================================================*/

// Simple port notification interrupt handler
void port_notification_handler (void) {
    // Process all pending port requests
    process_ports();
}

// Simple assembly wrapper - no complex register handling
__asm__(
    ".global port_notification_entry\n"
    "port_notification_entry:\n"
    "    call port_notification_handler\n"
    "    iretq\n"
);

// Initialize port notification interrupt
void init_port_notification_interrupt (void) {
    println("PORT_INT: Installing port notification interrupt (0x69)");
    
    extern void port_notification_entry();
    set_idt_entry(0x69, (uint64_t)port_notification_entry, KERNEL_CODE_SELECTOR, 0xEE);
    
    println("PORT_INT: Port notification interrupt ready");
}
