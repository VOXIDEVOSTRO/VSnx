// port.c - Bidirectional port communication for modules
#include "port.h"
#include <stddef.h>

#define MFS_MAGIC 0xDEADBEEF
#define MFS_TYPE_SEGMENT 1
#define MFS_TYPE_DIRECTORY 2
#define MFS_MAX_ENTRIES 1000
#define MFS_BASE_ADDR 0x20000000

typedef struct {
    uint32_t magic;
    uint32_t type;
    char name[32];
    uint64_t start_addr;
    uint64_t size;
    uint64_t parent_addr;
} mfs_entry_t;

typedef struct {
    uint32_t magic;
    uint32_t total_size;
    uint32_t block_size;
    uint32_t total_blocks;
    uint32_t free_blocks;
    uint64_t entry_table;
    uint64_t next_free_addr;
} mfs_superblock_t;

// String comparison
static int strcmp(const char* str1, const char* str2) {
    while (*str1 && (*str1 == *str2)) {
        str1++;
        str2++;
    }
    return *(unsigned char*)str1 - *(unsigned char*)str2;
}

// Find specific port in MFS
static mfs_entry_t* find_port(const char* port_name) {
    mfs_superblock_t* sb = (mfs_superblock_t*)MFS_BASE_ADDR;
    if (sb->magic != MFS_MAGIC) {
        return NULL;
    }
    
    mfs_entry_t* entry_table = (mfs_entry_t*)sb->entry_table;
    
    for (int i = 0; i < MFS_MAX_ENTRIES; i++) {
        if (entry_table[i].magic == MFS_MAGIC && 
            entry_table[i].type == MFS_TYPE_SEGMENT &&
            strcmp(entry_table[i].name, port_name) == 0) {
            return &entry_table[i];
        }
    }
    
    return NULL;
}

// Write request to port (module to kernel)
int call_port(const char* port_name, int param1, int param2) {
    // Find the port
    mfs_entry_t* port_entry = find_port(port_name);
    if (!port_entry) {
        return -1; // Port not found
    }
    
    // Get port message structure
    port_message_t* port = (port_message_t*)port_entry->start_addr;
    
    // Validate port
    if (port->magic != PORT_MAGIC) {
        return -2; // Invalid port
    }
    
    // Wait for port to be empty
    while (port->status != PORT_STATUS_EMPTY) {
        // Simple busy wait
    }
    
    // Write request
    port->status = PORT_STATUS_REQUEST;
    port->request_id++;
    port->data_size = 8; // Two 32-bit integers
    *((int*)&port->data[0]) = param1;
    *((int*)&port->data[4]) = param2;
    
    // Wait for response
    while (port->status == PORT_STATUS_REQUEST) {
        // Busy wait for kernel to process
    }
    
    // Check response
    if (port->status == PORT_STATUS_RESPONSE) {
        int result = *((int*)&port->data[0]);
        port->status = PORT_STATUS_EMPTY; // Clear port
        return result;
    }
    
    return -3; // Error response
}

// Read from port (kernel to module communication)
int read_port(const char* port_name, int* param1, int* param2) {
    // Find the port
    mfs_entry_t* port_entry = find_port(port_name);
    if (!port_entry) {
        return -1; // Port not found
    }
    
    // Get port message structure
    port_message_t* port = (port_message_t*)port_entry->start_addr;
    
    // Validate port
    if (port->magic != PORT_MAGIC) {
        return -2; // Invalid port
    }
    
    // Check if there's a request waiting
    if (port->status == PORT_STATUS_REQUEST) {
        // Read parameters
        if (param1) *param1 = *((int*)&port->data[0]);
        if (param2) *param2 = *((int*)&port->data[4]);
        return 1; // Request available
    }
    
    return 0; // No request
}

// Write response to port (module to kernel)
int write_port_response(const char* port_name, int result) {
    // Find the port
    mfs_entry_t* port_entry = find_port(port_name);
    if (!port_entry) {
        return -1; // Port not found
    }
    
    // Get port message structure
    port_message_t* port = (port_message_t*)port_entry->start_addr;
    
    // Validate port
    if (port->magic != PORT_MAGIC) {
        return -2; // Invalid port
    }
    
    // Write response
    *((int*)&port->data[0]) = result;
    port->data_size = 4;
    port->status = PORT_STATUS_RESPONSE;
    
    return 0; // Success
}

// Check if port has request (non-blocking)
int port_has_request(const char* port_name) {
    // Find the port
    mfs_entry_t* port_entry = find_port(port_name);
    if (!port_entry) {
        return 0; // Port not found
    }
    
    // Get port message structure
    port_message_t* port = (port_message_t*)port_entry->start_addr;
    
    // Validate port and check status
    if (port->magic == PORT_MAGIC && port->status == PORT_STATUS_REQUEST) {
        return 1; // Has request
    }
    
    return 0; // No request
}
