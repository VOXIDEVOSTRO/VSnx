#ifndef PORT_H
#define PORT_H

#include <stdint.h>
#include "../os/kernel/kernel.h"

#define PORT_MAGIC 0xDEADC0DE
#define PORT_STATUS_EMPTY    0
#define PORT_STATUS_REQUEST  1
#define PRINTF_PORT_ADDR 0x20100000

typedef struct {
    uint32_t magic;
    uint32_t status;  // 0=empty, 1=request, 2=response
    uint32_t function_id;
    uint32_t argc;
    uint64_t args[8];
    uint64_t result;
    char data[256];
} mfs_mailbox_t;

// PRINTF USING STRCPY - CLEAN AND SIMPLE
#define printf(str) do { \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)&_port->data[0], "printf"); \
        strcpy((char*)&_port->data[32], (str)); \
        _port->status = 1; \
        _port->request_id++; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _port->status = 0; \
    } \
} while(0)

// MFS Functions
#define sys_mfs_find(name, parent) do { \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "mfs_find"); \
        strcpy((char*)_port->data + 32, name); \
        *((void**)&_port->data[96]) = parent; \
        _port->status = 1; _port->request_id++; _port->data_size = 104; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _port->status = 0; \
    } \
} while(0)

// Add these to port.h for app port processing
#define sys_get_mfs_superblock() ({ \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    mfs_superblock_t* result = NULL; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "get_mfs_superblock"); \
        _port->status = 1; _port->request_id++; _port->data_size = 32; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        result = *((mfs_superblock_t**)&_port->result[0]); \
        _port->status = 0; \
    } \
    result; \
})

#define sys_get_mfs_entry_table() ({ \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    mfs_entry_t* result = NULL; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "get_mfs_entry_table"); \
        _port->status = 1; _port->request_id++; _port->data_size = 32; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        result = *((mfs_entry_t**)&_port->result[0]); \
        _port->status = 0; \
    } \
    result; \
})

#define sys_get_ports_dir() ({ \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    mfs_entry_t* result = NULL; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "get_ports_dir"); \
        _port->status = 1; _port->request_id++; _port->data_size = 32; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        result = *((mfs_entry_t**)&_port->result[0]); \
        _port->status = 0; \
    } \
    result; \
})

#define sys_get_root_dir() ({ \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    mfs_entry_t* result = NULL; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "get_root_dir"); \
        _port->status = 1; _port->request_id++; _port->data_size = 32; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        result = *((mfs_entry_t**)&_port->result[0]); \
        _port->status = 0; \
    } \
    result; \
})

#define sys_mfs_read(entry, offset, buffer, size) do { \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "mfs_read"); \
        *((void**)&_port->data[32]) = entry; \
        *((uint64_t*)&_port->data[40]) = offset; \
        *((void**)&_port->data[48]) = buffer; \
        *((size_t*)&_port->data[56]) = size; \
        _port->status = 1; _port->request_id++; _port->data_size = 64; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _port->status = 0; \
    } \
} while(0)

#define sys_mfs_write(entry, offset, buffer, size) do { \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "mfs_write"); \
        *((void**)&_port->data[32]) = entry; \
        *((uint64_t*)&_port->data[40]) = offset; \
        *((void**)&_port->data[48]) = buffer; \
        *((size_t*)&_port->data[56]) = size; \
        _port->status = 1; _port->request_id++; _port->data_size = 64; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _port->status = 0; \
    } \
} while(0)

#define sys_mfs_seg(name, size, parent) do { \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "mfs_seg"); \
        strcpy((char*)_port->data + 32, name); \
        *((size_t*)&_port->data[96]) = size; \
        *((void**)&_port->data[104]) = parent; \
        _port->status = 1; _port->request_id++; _port->data_size = 112; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _port->status = 0; \
    } \
} while(0)

#define sys_mfs_dir(name, parent) do { \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "mfs_dir"); \
        strcpy((char*)_port->data + 32, name); \
        *((void**)&_port->data[96]) = parent; \
        _port->status = 1; _port->request_id++; _port->data_size = 104; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _port->status = 0; \
    } \
} while(0)

// Memory Functions
#define sys_malloc(size) do { \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "malloc"); \
        *((size_t*)&_port->data[32]) = size; \
        _port->status = 1; _port->request_id++; _port->data_size = 40; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _port->status = 0; \
    } \
} while(0)

#define sys_free(ptr) do { \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "free"); \
        *((void**)&_port->data[32]) = ptr; \
        _port->status = 1; _port->request_id++; _port->data_size = 40; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _port->status = 0; \
    } \
} while(0)

// Time Functions
#define sys_get_uptime() do { \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "get_uptime"); \
        _port->status = 1; _port->request_id++; _port->data_size = 32; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _port->status = 0; \
    } \
} while(0)

#define sys_show_uptime() do { \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "show_uptime"); \
        _port->status = 1; _port->request_id++; _port->data_size = 32; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _port->status = 0; \
    } \
} while(0)

// File System Functions
#define sys_fs_open(path) do { \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "fs_open"); \
        strcpy((char*)_port->data + 32, path); \
        _port->status = 1; _port->request_id++; _port->data_size = 96; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _port->status = 0; \
    } \
} while(0)

#define sys_fs_close(fd) do { \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "fs_close"); \
        *((int*)&_port->data[32]) = fd; \
        _port->status = 1; _port->request_id++; _port->data_size = 36; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _port->status = 0; \
    } \
} while(0)

#define sys_fs_read(fd, buffer, size) do { \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "fs_read"); \
        *((int*)&_port->data[32]) = fd; \
        *((void**)&_port->data[36]) = buffer; \
        *((size_t*)&_port->data[44]) = size; \
        _port->status = 1; _port->request_id++; _port->data_size = 52; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _port->status = 0; \
    } \
} while(0)

#define sys_fs_ls(path) do { \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "fs_ls"); \
        strcpy((char*)_port->data + 32, path); \
        _port->status = 1; _port->request_id++; _port->data_size = 96; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _port->status = 0; \
    } \
} while(0)

// Syscall macros for MFS access
#define sys_get_mfs_superblock() ({ \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    mfs_superblock_t* result = NULL; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "get_mfs_superblock"); \
        _port->status = 1; _port->request_id++; _port->data_size = 32; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        result = *((mfs_superblock_t**)&_port->result[0]); \
        _port->status = 0; \
    } \
    result; \
})

#define sys_get_mfs_entry_table() ({ \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    mfs_entry_t* result = NULL; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "get_mfs_entry_table"); \
        _port->status = 1; _port->request_id++; _port->data_size = 32; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        result = *((mfs_entry_t**)&_port->result[0]); \
        _port->status = 0; \
    } \
    result; \
})

#define sys_get_ports_dir() ({ \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    mfs_entry_t* result = NULL; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "get_ports_dir"); \
        _port->status = 1; _port->request_id++; _port->data_size = 32; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        result = *((mfs_entry_t**)&_port->result[0]); \
        _port->status = 0; \
    } \
    result; \
})

// Inter-module communication syscall - kernel acts as middleman
#define sys_call_module(target_app, func_name, args, args_size) ({ \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    int _result = -1; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "call_module"); \
        strcpy((char*)_port->data + 32, target_app); \
        strcpy((char*)_port->data + 96, func_name); \
        if (args && args_size > 0) { \
            for (int i = 0; i < args_size && i < 64; i++) { \
                ((char*)_port->data)[160 + i] = ((char*)args)[i]; \
            } \
        } \
        *((size_t*)&_port->data[224]) = args_size; \
        _port->status = 1; _port->request_id++; _port->data_size = 240; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        /* Do not wait for response, return immediately */ \
        _result = 0; \
        _port->status = 0; \
    } \
    _result; \
})

#define sys_getchar() ({ \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    int _result = -1; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "getchar"); \
        _port->status = 1; _port->request_id++; _port->data_size = 32; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _result = *((int*)&_port->result[0]); \
        _port->status = 0; \
    } \
    _result; \
})

#define sys_clear_screen() ({ \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    int _result = -1; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "clear_screen"); \
        _port->status = 1; _port->request_id++; _port->data_size = 32; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _result = *((int*)&_port->result[0]); \
        _port->status = 0; \
    } \
    _result; \
})

#define sys_scroll_screen() ({ \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    int _result = -1; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "scroll_screen"); \
        _port->status = 1; _port->request_id++; _port->data_size = 32; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _result = *((int*)&_port->result[0]); \
        _port->status = 0; \
    } \
    _result; \
})

#define sys_make_vga_entry(c, color) ({ \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    unsigned short _result = 0; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "make_vga_entry"); \
        _port->data[0] = (char)(c); \
        _port->data[1] = (char)(color); \
        _port->status = 1; _port->request_id++; _port->data_size = 32; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _result = *((unsigned short*)&_port->result[0]); \
        _port->status = 0; \
    } \
    _result; \
})

#define sys_vga_write(x, y, c, color) ({ \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    int _result = -1; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "vga_write_safe"); \
        *((int*)&_port->data[0]) = (x); \
        *((int*)&_port->data[4]) = (y); \
        _port->data[8] = (char)(c); \
        _port->data[9] = (char)(color); \
        _port->status = 1; _port->request_id++; _port->data_size = 32; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _result = *((int*)&_port->result[0]); \
        _port->status = 0; \
    } \
    _result; \
})

#define sys_execute(thread_id) ({ \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    int _result = -1; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "execute"); \
        *((uint32_t*)&_port->data[32]) = (thread_id); \
        _port->status = 1; _port->request_id++; _port->data_size = 36; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _result = *((int*)&_port->result[0]); \
        _port->status = 0; \
    } \
    _result; \
})

#define sys_elf_thread_loader(elf_path, thread_name) ({ \
    volatile port_message_t* _port = (volatile port_message_t*)PRINTF_PORT_ADDR; \
    uint32_t _thread_id = 0; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "elf_thread_loader"); \
        strncpy((char*)_port->data, elf_path, 128); \
        strncpy((char*)_port->data + 128, thread_name, 64); \
        _port->status = 1; _port->request_id++; _port->data_size = 192; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        while (_port->status == 1) {} \
        _thread_id = *((uint32_t*)&_port->result[0]); \
        _port->status = 0; \
    } \
    _thread_id; \
})

// Corresponding userland syscall macros:

#endif // PORT_H
