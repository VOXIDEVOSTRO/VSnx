
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
  header files
================================================================================================================*/
#include "block.h"
#include "gristle.h"
#include "dirent.h"
#include "partition.h"
#include "syscall.h"
#include "../../modules/port.h"
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

/*==============================================================================================================
  defines and constants
================================================================================================================*/

// File operation constants
#ifndef O_RDONLY
#define O_RDONLY    0x0000
#endif
#ifndef O_WRONLY
#define O_WRONLY    0x0001
#endif
#ifndef O_RDWR
#define O_RDWR      0x0002
#endif
#ifndef O_CREAT
#define O_CREAT     0x0040
#endif
#ifndef O_TRUNC
#define O_TRUNC     0x0200
#endif
#ifndef O_APPEND
#define O_APPEND    0x0400
#endif

// Error codes that might be missing
#ifndef ENOENT
#define ENOENT      2
#endif
#ifndef ENFILE
#define ENFILE      23
#endif
#ifndef EROFS
#define EROFS       30
#endif
#ifndef EEXIST
#define EEXIST      17
#endif
#ifndef EACCES
#define EACCES      13
#endif
#ifndef EISDIR
#define EISDIR      21
#endif

// File mode constants
#ifndef S_IFDIR
#define S_IFDIR     0040000
#endif
#ifndef S_IWUSR
#define S_IWUSR     0000200
#endif

// Memory constants
#define HEAP_START        0x200000    // 2MB (heap start address)
#define HEAP_SIZE         0x800000    // 8MB heap size

// Define kernel virtual base address
#define KERNEL_VIRTUAL_BASE 0xFFFFFFFF80000000ULL

// Mouse IRQ number
#define IRQ_MOUSE 12

// Memory block structure
typedef struct memory_block {
    size_t size;
    int free;
    struct memory_block* next;
} memory_block_t;

// Memory management globals
extern memory_block_t* heap_start ;
extern int memory_initialized ;
// Add global counter at top of file
extern uint32_t loaded_modules_count ;
extern uint32_t interrupt_processing_active ;

extern uint32_t g_fb_width, g_fb_height, g_fb_pitch;
extern uint64_t g_fb_addr;
extern uint8_t red_pos, green_pos, blue_pos;

// VGA text mode
#define VGA_WIDTH 80
#define VGA_HEIGHT 25
extern int cursor_x ;
extern int cursor_y ;

// ATA/SATA port definitions
#define ATA_PRIMARY_DATA         0x1F0
#define ATA_PRIMARY_ERROR        0x1F1
#define ATA_PRIMARY_SECTOR_COUNT 0x1F2
#define ATA_PRIMARY_LBA_LOW      0x1F3
#define ATA_PRIMARY_LBA_MID      0x1F4
#define ATA_PRIMARY_LBA_HIGH     0x1F5
#define ATA_PRIMARY_DRIVE_HEAD   0x1F6
#define ATA_PRIMARY_STATUS       0x1F7
#define ATA_PRIMARY_COMMAND      0x1F7

// ATA commands
#define ATA_CMD_READ_SECTORS     0x20
#define ATA_CMD_IDENTIFY         0xEC
#define ATA_CMD_WRITE_SECTORS    0x30

// Status register bits
#define ATA_STATUS_DRQ  0x08
#define ATA_STATUS_BSY  0x80

// Disk information
extern uint32_t disk_size ;
extern int disk_error ;
extern int fs_initialized ;

// Filesystem constants
#define PART_TYPE_FAT32 0x0B

// PS/2 Mouse Support for VOSTROX Kernel

// PS/2 Controller Ports
#define PS2_DATA_PORT 0x60
#define PS2_STATUS_PORT 0x64
#define PS2_COMMAND_PORT 0x64

// PS/2 Mouse Commands
#define PS2_ENABLE_AUX_DEVICE 0xA8
#define PS2_WRITE_TO_MOUSE 0xD4
#define PS2_MOUSE_ENABLE 0xF4
#define PS2_MOUSE_RESET 0xFF

// Mouse packet size
#define MOUSE_PACKET_SIZE 3

// Mouse state
extern uint8_t mouse_packet[MOUSE_PACKET_SIZE];
extern uint8_t mouse_packet_index ;

// Mouse position (can be integrated with your input system)
extern int mouse_x ;
extern int mouse_y ;
extern int mouse_buttons ;

// External filesystem globals (defined in krnlfs32.c)
extern struct fat_info fatfs;
extern FileS file_num[MAX_OPEN_FILES];

// Extended thread state for preemptive switching
typedef struct {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip, rflags;
    uint16_t cs, ds, es, fs, gs, ss;
    uint32_t thread_id;
    uint32_t is_active;
} saved_thread_state_t;

// Complete CPU state for temporary context switches
typedef struct {
    // ALL CPU REGISTERS
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip, rflags;
    uint16_t cs, ds, es, fs, gs, ss;
    
    // CALL TRACKING INFO
    uint32_t caller_thread_id;
    uint32_t target_thread_id;
    char target_app[32];
    char target_function[64];
    char target_port_name[96];
    
    // PORT REFERENCES
    port_message_t* caller_port;
    port_message_t* target_port;
    
    // CALL STATE
    uint32_t call_active;
    uint64_t call_start_time;
} full_temp_context_t;

// Global mapping table
typedef struct {
    uint64_t elf_base;
    uint64_t mfs_base;
    size_t size;
    char thread_name[32];
} elf_mapping_t;

extern elf_mapping_t elf_mappings[16];
extern int mapping_count ;

typedef struct {
    uint32_t magic;
    uint32_t thread_id;
    uint32_t state;           // READY, RUNNING, BLOCKED, TERMINATED
    uint32_t priority;
    
    // CPU context - minimal stack usage
    uint64_t rsp, rbp, rip;
    uint64_t rflags;
    
    // MFS-based thread data - NAMES ONLY
    char stack_segment_name[32];    // Name of MFS stack segment
    char data_segment_name[32];     // Name of MFS data segment
    char code_segment_name[32];     // Name of MFS code segment (NOT raw address)
    char name[32];                  // Thread name
    
    uint64_t stack_size;
    uint64_t time_slice;
    uint64_t total_time;
} thread_control_block_t;

// Thread states
#define THREAD_STATE_READY      0
#define THREAD_STATE_RUNNING    1
#define THREAD_STATE_BLOCKED    2
#define THREAD_STATE_TERMINATED 3

extern full_temp_context_t temp_call_stack[16];
extern uint32_t temp_call_depth ;

extern saved_thread_state_t thread_states[64];  // Match MAX_THREADS
extern uint32_t current_thread_index ;
extern uint32_t preemptive_enabled ;
extern uint32_t active_thread_count ;

// Paging constants
#define PAGE_SIZE           0x1000      // 4KB
#define PAGE_ENTRIES        512         // 512 entries per table
#define PAGE_PRESENT        (1ULL << 0)
#define PAGE_WRITE          (1ULL << 1)
#define PAGE_USER           (1ULL << 2)
#define PAGE_SIZE_2MB       (1ULL << 7)

// Page table structures
typedef struct {
    uint64_t entries[PAGE_ENTRIES];
} page_table_t __attribute__((aligned(PAGE_SIZE)));

// Global page tables
extern page_table_t* pml4_table;
extern page_table_t* pdpt_table;
extern page_table_t* pd_tables[4];  // Support up to 4GB
extern uint64_t next_free_page ; // Start after 8MB

// Paging-based memory management
extern uint64_t paging_heap_start ;  // 256MB
extern uint64_t paging_heap_current ;
extern uint64_t paging_heap_end ;    // 512MB (256MB heap)
extern int paging_memory_initialized ;
extern int paging_initialized ;

// Memory block structure for paging system
typedef struct paging_memory_block {
    size_t size;
    int free;
    struct paging_memory_block* next;
    uint32_t magic;  // For corruption detection
} paging_memory_block_t;

#define PAGING_BLOCK_MAGIC 0xDEADBEEF

extern paging_memory_block_t* paging_heap_head ;
// Memory operation context to prevent circular calls
extern int memory_operation_in_progress ;
extern int paging_operation_in_progress ;

#define USER_VIRTUAL_START    0x20000000  // 512MB

#define SERIAL_PORT_COM1 0x3F8

// VGA buffer constants
#define VGA_BUFFER_ADDR 0xB8000
#define VGA_WIDTH 80
#define VGA_HEIGHT 25

// VGA buffer - Use linker symbols for proper mapping
extern uint64_t vga_buffer_start;
extern uint64_t vga_buffer_end;

// VGA buffer - properly mapped by linker
extern volatile unsigned short* const VGA_BUFFER ;

// Global variable for stack protection
extern uintptr_t __stack_chk_guard;

// User memory layout
#define USER_VIRTUAL_END      0x40000000  // 1GB
#define USER_PAGE_SIZE        0x1000      // 4KB pages
#define USER_LARGE_PAGE_SIZE  0x200000    // 2MB large pages
#define MAX_USER_PAGES        1024        // Limit to prevent crashes

// Reliable User Memory System with Guard Pages and Tracking
#define USER_MEMORY_START     0x20000000  // 512MB
#define USER_MEMORY_END       0x40000000  // 1GB
#define MAX_USER_ALLOCATIONS  1024
#define GUARD_PAGE_MAGIC      0xDEADDEAD

// Page fault handler type
typedef void (*page_fault_handler_t)(void);

// Current page fault handler
extern page_fault_handler_t current_page_fault_handler ;

// Page tracking structure (limited size)
typedef struct {
    uint64_t virtual_addr;
    uint64_t physical_addr;
    int is_mapped;
    int is_writable;
    int reference_count;
} user_page_info_t;

extern user_page_info_t user_pages[MAX_USER_PAGES];
extern int user_pages_count ;
extern int user_paging_initialized ;

// User memory block structure
typedef struct user_memory_block {
    uint64_t size;
    int is_free;
    struct user_memory_block* next;
} user_memory_block_t;

extern user_memory_block_t* user_memory_head ;

// Global error flag for memory validation
extern int validation_error ;

// User allocation tracking
typedef struct user_allocation {
    uint64_t start_addr;
    uint64_t size;
    uint64_t guard_before;
    uint64_t guard_after;
    uint32_t magic;
    int is_allocated;
    int allocation_id;
} user_allocation_t;

extern user_allocation_t user_allocations[MAX_USER_ALLOCATIONS];
extern int user_allocation_count ;
extern int user_tracking_initialized ;

#define KEYBOARD_BUFFER_SIZE 256
extern volatile char keyboard_buffer[KEYBOARD_BUFFER_SIZE];
extern volatile int keyboard_buffer_head ;
extern volatile int keyboard_buffer_tail ;

#define MFS_REGION_START    0x20000000  // 512MB
#define MFS_REGION_END      0x40000000  // 1GB
#define MFS_BLOCK_SIZE      0x1000      // 4KB blocks
#define MFS_MAX_NAME_LEN    64
#define MFS_MAX_ENTRIES     1024
#define MFS_MAGIC           0xDEADBEEF

// Permission constants
#define MFS_PERM_READ    0x004
#define MFS_PERM_WRITE   0x002
#define MFS_PERM_EXEC    0x001
#define MFS_PERM_USER_R  0x040
#define MFS_PERM_USER_W  0x020
#define MFS_PERM_USER_X  0x010

// MFS entry types
typedef enum {
    MFS_TYPE_FREE = 0,
    MFS_TYPE_DIR = 1,
    MFS_TYPE_SEGMENT = 2,
    MFS_TYPE_GUARD = 3
} mfs_entry_type_t;

// Enhanced MFS entry structure (add to existing struct)
typedef struct mfs_entry {
    uint32_t magic;
    mfs_entry_type_t type;
    char name[MFS_MAX_NAME_LEN];
    uint64_t start_addr;
    uint64_t size;
    uint64_t blocks_used;
    uint32_t permissions;
    uint32_t ref_count;
    uint32_t process_id;        // NEW: Process ID
    uint32_t segment_id;        // NEW: Segment ID within process
    uint64_t entry_point;       // NEW: Entry point for executables
    struct mfs_entry* parent;
    struct mfs_entry* next;
    struct mfs_entry* children;
} mfs_entry_t;

// Process management globals
extern int next_process_id ;
extern mfs_entry_t* processes_dir ;

// MFS superblock
typedef struct {
    uint32_t magic;
    uint64_t total_size;
    uint64_t free_blocks;
    uint64_t used_blocks;
    uint64_t next_free_addr;
    mfs_entry_t* root_dir;
    mfs_entry_t* entry_table;
    int initialized;
} mfs_superblock_t;

extern mfs_superblock_t mfs_sb;

// Add flags and PID support
#define MFS_FLAG_NX    0x1  // Not executable
#define MFS_FLAG_X     0x2  // Executable

extern int next_pid ;  // Start PIDs at 100

// CONTEXT RESTORATION INTERRUPT - ADD THESE DECLARATIONS
extern uint32_t pending_restore_thread_id ;
extern uint32_t current_thread_id ;  // Track current thread
extern uint32_t thread_count ;

#define MULTIBOOT2_TAG_TYPE_FRAMEBUFFER 8

struct multiboot_tag {
    uint32_t type;
    uint32_t size;
};

struct multiboot_tag_framebuffer {
    uint32_t type;
    uint32_t size;
    uint64_t framebuffer_addr;
    uint32_t framebuffer_pitch;
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint8_t  framebuffer_bpp;
    uint8_t  framebuffer_type;
    uint16_t reserved;

    union {
        struct {
            uint16_t framebuffer_palette_num_colors;
            struct {
                uint8_t framebuffer_palette_red;
                uint8_t framebuffer_palette_green;
                uint8_t framebuffer_palette_blue;
            } framebuffer_palette[];
        };
        struct {
            uint8_t framebuffer_red_field_position;
            uint8_t framebuffer_red_mask_size;
            uint8_t framebuffer_green_field_position;
            uint8_t framebuffer_green_mask_size;
            uint8_t framebuffer_blue_field_position;
            uint8_t framebuffer_blue_mask_size;
        };
    };
};

// Renderer globals
// Globals for MFS backbuffer
extern mfs_entry_t* backbuffer_segment ;
extern uint32_t backbuffer_width ;
extern uint32_t backbuffer_height ;
extern uint32_t backbuffer_pitch ;
extern uint64_t framebuffer_addr ;
extern uint32_t framebuffer_pitch ;
extern uint32_t framebuffer_width ;
extern uint32_t framebuffer_height ;

// Stack management using our paged memory system
#define STACK_SIZE (64 * 1024)  // 64KB per stack
#define MAX_STACKS 16

// Stack tracking structure
typedef struct {
    void* stack_ptr;
    int in_use;
} paged_stack_entry_t;

extern paged_stack_entry_t paged_stacks[MAX_STACKS];
extern int paged_stack_system_initialized ;

extern uint8_t fat32_buffer[512] __attribute__((aligned(512))); // 512-byte aligned buffer

// fs_init - Initialize and mount the filesystem (extracted from fs_ls)


// FIXED: Proper segment selectors with RPL bits
#define KERNEL_CODE_SELECTOR 0x08  // Ring 0 code
#define KERNEL_DATA_SELECTOR 0x10  // Ring 0 data  
#define USER_CODE_SELECTOR   (0x18 | 3)  // Ring 3 code with RPL=3
#define USER_DATA_SELECTOR   (0x20 | 3)  // Ring 3 data with RPL=3

// Define TSS structure
typedef struct {
    uint32_t reserved1;
    uint64_t rsp0;      // Ring 0 stack pointer
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved2;
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint64_t reserved3;
    uint16_t reserved4;
    uint16_t iomap_base;
} __attribute__((packed)) tss_t;

extern tss_t kernel_tss;
extern uint8_t kernel_stack[65536] __attribute__((aligned(16)));

// IDT entry structure
typedef struct {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t ist;
    uint8_t type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t reserved;
} __attribute__((packed)) idt_entry_t;

// IDT descriptor
typedef struct {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) idt_descriptor_t;

extern idt_entry_t idt[256];
extern int idt_initialized ;

// Global variables to store kernel context - ADD THESE DECLARATIONS
extern uint64_t kernel_rsp_global;
extern uint64_t kernel_rbp_global;

// Interrupt frame structure
typedef struct {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t int_no, err_code;
    uint64_t rip, cs, rflags, rsp, ss;
} interrupt_frame_t;

extern volatile int should_test_port ;

// ELF constants
#define ELF_MAGIC_0     0x7F
#define ELF_MAGIC_1     'E'
#define ELF_MAGIC_2     'L'
#define ELF_MAGIC_3     'F'
#define ELF_CLASS_64    2
#define ELF_DATA_LSB    1
#define ELF_TYPE_EXEC   2
#define ELF_TYPE_DYN    3
#define ELF_MACHINE_X86_64  62
#define PT_LOAD         1

// ELF structures
typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed)) elf_header_t;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} __attribute__((packed)) elf_program_header_t;

// Page flags
#define PAGE_PRESENT    0x1
#define PAGE_WRITABLE   0x2
#define PAGE_USER       0x4
#define PAGE_NX         (1ULL << 63)

// User stack address
#define USER_STACK_ADDR 0x7FFFFFF000ULL
#define USER_STACK_SIZE 0x1000

// Mouse IRQ and interrupt constants
#define IRQ_MOUSE           12
#define MOUSE_IRQ_VECTOR    (32 + IRQ_MOUSE)  // IRQ 12 maps to interrupt 44

// Enhanced mouse state for scroll wheel support
typedef struct {
    int x, y;
    int last_x, last_y;
    uint8_t buttons;
    uint8_t last_buttons;
    int8_t scroll_delta;
    uint8_t packet[4];            // 4 bytes for scroll wheel mode
    uint8_t packet_index;
    uint8_t packet_size;          // 3 for standard, 4 for scroll wheel
    uint32_t packets_received;
    uint32_t sync_errors;
    volatile int data_ready;
} mouse_interrupt_state_t;

// Fix cursor artifacts by disabling cursor updates during screen clear
extern int cursor_disabled ;

extern mouse_interrupt_state_t mouse_state ;

// 32x32 arrow cursor pattern
extern uint32_t arrow_cursor_32[32];

extern uint32_t saved_background[2048]; // Increase for outline pixels
extern int saved_pixel_count ;
extern int saved_valid ;

// Dynamic Module System
#define MAX_MODULES 32
#define MAX_FUNCTIONS_PER_MODULE 1

typedef struct {
    char name[32];
    uint64_t address;
    uint32_t size;
} module_function_t;

typedef struct {
    char name[32];
    mfs_entry_t* segment;
    module_function_t functions[MAX_FUNCTIONS_PER_MODULE];
    int function_count;
} module_t;

extern module_t loaded_modules[MAX_MODULES];
extern int module_count ;
extern mfs_entry_t* modules_dir ;

// ELF header structures
typedef struct {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf64_header_t;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} elf64_program_header_t;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} elf64_section_t;

typedef struct {
    uint32_t st_name;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} elf64_symbol_t;

// Add to kernel.c - Port management system
extern mfs_entry_t* ports_dir ;

#ifndef offsetof
#define offsetof(type, member) ((size_t)&((type*)0)->member)
#endif

// Port processing function registry
typedef struct {
    char app_name[32];
    void (*port_processor)(void);  // Function to process this app's ports
    uint32_t active;
} port_processor_registry_t;

extern port_processor_registry_t port_processors[16];
extern uint32_t processor_count ;

extern uint32_t trampoline_in_progress ;
#define RESUME_FLAG_MAGIC 0x1234567890ABCDEF

// Dynamic port processor registry
typedef struct {
    char app_name[32];
    uint64_t check_notifications_addr;  // Address of app's check_port_notifications function
    uint32_t active;
} dynamic_port_processor_t;

extern dynamic_port_processor_t dynamic_processors[16];
extern uint32_t dynamic_processor_count ;

// ELF constants
#define ELF_MAGIC 0x464C457F
#define PT_LOAD 1
#define PF_X 1
#define PF_W 2
#define PF_R 4

// ELF section types
#define SHT_SYMTAB 2

// ELF symbol types
#define STT_FUNC 2

// Module function registry
typedef struct {
    char module_name[32];
    char function_name[64];
    char full_port_name[96];
} module_function_entry_t;

#define MAX_MODULE_FUNCTIONS 1000

#define CONTEXT_MAGIC 0xC0DE5AFE

typedef struct __attribute__((packed, aligned(16))) {
    uint32_t magic;
    uint32_t thread_id;
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rsi, rdi, rbp, rdx, rcx, rbx, rax;
    uint64_t rip, cs, rflags, rsp, ss;
    uint64_t ds, es, fs, gs;
} cpu_context_t;

// Simple system time tracking
extern volatile uint64_t system_ticks ;
extern volatile uint32_t uptime_seconds ;
extern int clock_initialized ;

#define FONT_CHAR_WIDTH    8
#define FONT_CHAR_HEIGHT   16
#define FONT_NUM_CHARS     256

extern uint8_t font_bitmaps[FONT_NUM_CHARS][FONT_CHAR_HEIGHT];

// Updated syscall system with support for variable arguments using uniform function signature

// Example argument structs for different syscalls
typedef struct {
    const char* str;
} print_args_t;

typedef struct {
    int a;
    int b;
} add_args_t;
// Usage example:
// print_args_t p_args = { "Hello from syscall!\n" };
// invoke_sys("print", &p_args);

// add_args_t a_args = { 5, 7 };
// int sum = invoke_sys("add", &a_args);

#define MAILBOX_ADDR 0x21000000
#define MAILBOX_SIZE 4096

typedef struct {
    uint32_t magic;
    uint32_t status;  // 0=empty, 1=request, 2=response
    uint32_t function_id;
    uint32_t argc;
    uint64_t args[8];
    uint64_t result;
    char data[256];
} mfs_mailbox_t;

// Sovereign prototype manifest
inline void ata_wait_bsy (void) ;
inline void ata_wait_drq (void) ;
int ata_identify (void) ;
int block_init (void) ;
int block_halt (void) ;
int block_read(blockno_t block, void *buf) ;
int block_write(blockno_t block, void *buf) ;
blockno_t block_get_volume_size (void) ;
int block_get_block_size (void) ;
int block_get_device_read_only (void) ;
int block_get_error (void) ;
int get_symbol_name_from_elf(int fd, elf64_header_t* elf_header, uint32_t name_offset, char* name_buffer, size_t buffer_size) ;
void store_elf_mapping(const char* thread_name, uint64_t elf_base, uint64_t mfs_base, size_t size) ;
int elf_resolve_and_map_functions(const char* elf_path, const char* module_dir_name) ;
uint32_t elf_thread_loader(const char* elf_path, const char* thread_name) ;
void* safe_buffer_alloc(size_t size) ;
time_t fat_to_unix_time(uint16_t fat_time) ;
uint16_t fat_from_unix_time(time_t seconds) ;
time_t fat_to_unix_date(uint16_t fat_date) ;
uint16_t fat_from_unix_date(time_t seconds) ;
int fat_update_atime(int fd) ;
int fat_update_mtime(int fd) ;
int8_t fat_get_next_file() ;
char doschar(char c) ;
int make_dos_name(char *dosname, const char *path, int *path_pointer) ;
int fatname_to_str(char *output, char *input) ;
int str_to_fatname(char *url, char *dosname) ;
int fat_get_free_cluster() ;
int fat_free_clusters(uint32_t cluster) ;
int fat_flush(int fd) ;
int fat_select_cluster(int fd, uint32_t cluster) ;
int fat_next_cluster(int fd, int *rerrno) ;
int fat_next_sector(int fd) ;
int fat_flush_fileinfo(int fd) ;
int fat_lookup_path(int fd, const char *path, int *rerrno) ;
int fat_mount_fat16(blockno_t start, blockno_t volume_size) ;
int fat_mount_fat32(blockno_t start, blockno_t volume_size) ;
int fat_mount(blockno_t part_start, blockno_t volume_size, uint8_t filesystem_hint) ;
int fat_open(const char *name, int flags, int mode, int *rerrno) ;
int fat_close(int fd, int *rerrno) ;
int fat_read(int fd, void *buffer, size_t count, int *rerrno) ;
int fat_write(int fd, const void *buffer, size_t count, int *rerrno) ;
int fat_fstat(int fd, struct stat *st, int *rerrno) ;
int fat_lseek(int fd, int ptr, int dir, int *rerrno) ;
int fat_get_next_dirent(int fd, struct dirent *out_de, int *rerrno) ;
uint32_t find_directory_cluster(uint32_t parent_cluster, const char* dir_name) ;
int fat_unlink(const char *path, int *rerrno) ;
int fat_rmdir(const char *path, int *rerrno) ;
int fs_ls(const char *path) ;
int fs_open(const char* filename) ;
int fs_close(int fd) ;
int fs_read(int fd, void* buffer, size_t count) ;
int initialize_file_descriptor(int fd) ;
int load_font(const char* filename) ;
void setup_gdt_with_rings (void) ;
void general_exception_handler (void) ;
void isr_handler(interrupt_frame_t* frame) ;
void irq_handler(interrupt_frame_t* frame) ;
void set_idt_entry(int num, uint64_t handler, uint16_t selector, uint8_t flags) ;
void init_idt (void) ;
void exception_init (void) ;
void outb(uint16_t port, uint8_t value) ;
uint8_t inb(uint16_t port) ;
uint16_t inw(uint16_t port) ;
void outw(uint16_t port, uint16_t value) ;
int declare_kernel_function(const char* module_name, const char* function_name, int arg_count) ;
int call_kernel_function(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int printun(uint64_t arg) ;
void syscall_interrupt_handler (void) ;
void syscall_0x80_handler (void) ;
void init_direct_syscall (void) ;
int extract_call (void) ;
void syscall_0x81_handler (void) ;
void init_syscall_system (void) ;
void init_mfs_mailbox (void) ;
void process_mfs_mailbox (void) ;
int64_t sys_printf_handler(uint64_t str, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_call_function_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_declare_function_handler(uint64_t module, uint64_t function, uint64_t arg_count, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_mfs_find_handler(uint64_t name, uint64_t parent, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_mfs_read_handler(uint64_t entry, uint64_t offset, uint64_t buffer, uint64_t size, uint64_t arg5, uint64_t arg6) ;
int64_t sys_mfs_write_handler(uint64_t entry, uint64_t offset, uint64_t buffer, uint64_t size, uint64_t arg5, uint64_t arg6) ;
int64_t sys_mfs_seg_handler(uint64_t name, uint64_t size, uint64_t parent, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_mfs_dir_handler(uint64_t name, uint64_t parent, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_get_mfs_sb_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_get_mfs_table_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_get_root_dir_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_get_ports_dir_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_malloc_handler(uint64_t size, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_free_handler(uint64_t ptr, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_get_uptime_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_show_uptime_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_fs_open_handler(uint64_t path, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_fs_close_handler(uint64_t fd, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_fs_read_handler(uint64_t fd, uint64_t buffer, uint64_t size, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_fs_ls_handler(uint64_t path, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_getchar_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_clear_screen_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_vga_write_handler(uint64_t x, uint64_t y, uint64_t c, uint64_t color, uint64_t arg5, uint64_t arg6) ;
int64_t sys_execute_handler(uint64_t thread_id, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
int64_t sys_elf_loader_handler(uint64_t path, uint64_t name, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
void syscall_handler(uint64_t syscall_num, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
void init_syscalls (void) ;
uint64_t virt_to_phys(uint64_t virt_addr) ;
uint64_t alloc_page (void) ;
int map_page(uint64_t virt_addr, uint64_t phys_addr, uint64_t flags) ;
int paging_init (void) ;
int paging_map_range(uint64_t start_addr, uint64_t size) ;
void page_fault_handler(uint64_t error_code, uint64_t fault_addr) ;
void clear_page_raw(uint64_t page_addr) ;
void memory_init (void) ;
int safe_memory_write(void* addr, uint8_t value, size_t offset) ;
int safe_memory_read(void* addr, uint8_t* value, size_t offset) ;
void* malloc(size_t size) ;
void free(void* ptr) ;
void* realloc(void* ptr, size_t size) ;
void* calloc(size_t nmemb, size_t size) ;
void* basic_malloc(size_t size) ;
void basic_free(void* ptr) ;
void* safe_malloc(size_t size) ;
void kernel_main(uint64_t mb2_info_addr) ;
char scancode_to_ascii(uint8_t scancode) ;
int kernel_getchar(void) ;
int mfs_init (void) ;
int mfs_chmod(mfs_entry_t* entry, uint32_t new_permissions) ;
int mfs_check_permission(mfs_entry_t* entry, uint32_t required_perm) ;
int mfs_map_massive_block (void) ;
void mfs_free_entry(mfs_entry_t* entry) ;
void mfs_safe_remove_from_parent(mfs_entry_t* entry) ;
uint64_t mfs_alloc_blocks(size_t size) ;
mfs_entry_t* mfs_dir(const char* name, mfs_entry_t* parent) ;
mfs_entry_t* mfs_seg(const char* name, size_t size, mfs_entry_t* parent) ;
mfs_entry_t* mfs_seg_at(const char* name, size_t size, uint64_t specific_addr, mfs_entry_t* parent) ;
mfs_entry_t* find_segment_by_address(uint64_t addr) ;
void mfs_cleanup_all (void) ;
void* mfs_get_data(mfs_entry_t* entry) ;
size_t mfs_get_size(mfs_entry_t* entry) ;
mfs_entry_t* mfs_find(const char* name, mfs_entry_t* dir) ;
int mfs_write(mfs_entry_t* entry, size_t offset, const void* data, size_t size) ;
int mfs_read(mfs_entry_t* entry, size_t offset, void* data, size_t size) ;
void* user_malloc(size_t size) ;
void user_free(void* ptr) ;
void init_module_system (void) ;
int load_module(const char* module_name) ;
int call_module_function(const char* module_name, const char* function_name) ;
int call_module_via_port(const char* module_name, const char* function_name, int param1, int param2) ;
void load_boot_modules (void) ;
int load_test_module_direct (void) ;
void create_module_function_registry (void) ;
void register_module_function(const char* module_name, const char* function_name) ;
void draw_arrow_cursor_32(int x, int y) ;
int get_mouse_x (void) ;
int get_mouse_y (void) ;
void disable_cursor_updates (void) ;
void enable_cursor_updates (void) ;
void mouse_irq_handler(void) ;
void init_mouse_interrupt(void) ;
int get_left_button_state (void) ;
int get_right_button_state (void) ;
void get_mouse_state(int* x, int* y, uint8_t* buttons) ;
void print_mouse_stats(void) ;
int get_left_click(void) ;
int get_right_click(void) ;
int get_middle_click(void) ;
int get_scroll(void) ;
int init_paged_stack_system (void) ;
void * allocate_paged_stack (void) ;
void free_paged_stack(void* stack_ptr) ;
void set_page_permissions(uint64_t vaddr, uint64_t flags) ;
void* allocate_safe_user_stack(size_t size) ;
void debug_walk_page_tables(uint64_t vaddr, const char* desc) ;
void debug_ring3_transition(uint64_t entry_point, uint64_t user_rsp) ;
void set_page_permissions_4kb(uint64_t vaddr, uint64_t flags) ;
int map_page_4kb(uint64_t virt_addr, uint64_t phys_addr, uint64_t flags) ;
void* user_malloc_4kb(size_t size) ;
void* user_malloc_aligned(size_t size, size_t alignment) ;
int verify_ring3_environment (void) ;
void validation_fault_handler(void) ;
void default_page_fault_handler(void) ;
page_fault_handler_t set_page_fault_handler(page_fault_handler_t handler) ;
int validate_memory_mapping(uint64_t addr, size_t size) ;
void page_fault_handler_entry(void) ;
void init_page_fault_handler(void) ;
int user_paging_init (void) ;
void init_port_system (void) ;
int create_port(const char* port_name) ;
int call_func_port(const char* app_name, const char* func_name, void* args, size_t args_size) ;
void process_ports (void) ;
void process_port_request(port_message_t* port) ;
void register_dynamic_port_processor(const char* app_name, uint64_t check_notifications_addr) ;
void call_app_function_from_interrupt(uint64_t function_addr) ;
void interrupt_process_all_ports (void) ;
void port_notification_handler (void) ;
void init_port_notification_interrupt (void) ;
void serial_init (void) ;
int serial_transmit_empty (void) ;
void serial_putchar(char c) ;
void serial_write(const char* str) ;
void serial_println(const char* str) ;
void serial_print_hex(uint64_t value) ;
void serial_print_int(uint64_t value) ;
void serial_dump_vga_buffer (void) ;
void init_system_clock (void) ;
void update_system_clock (void) ;
uint32_t get_uptime_seconds (void) ;
void show_uptime (void) ;
void timer_interrupt_handler (void) ;
void test_paging (void) ;
void memory_stress_test (void) ;
void simple_buffer_test (void) ;
void test_paged_stack_system (void) ;
void test_minimal_allocation (void) ;
void show_stack_slots (void) ;
void validate_gdt_selectors (void) ;
void test_minimal_iretq (void) ;
void test_user_memory (void) ;
void test_ring3_setup (void) ;
uint64_t load_test_program (void) ;
void test_mfs_comprehensive (void) ;
void dump_stack_area(const char* label) ;
void test_stack_push (void) ;
void test_stack_frame (void) ;
void test_stack_stress (void) ;
void test_stack_alignment (void) ;
void debug_interrupt_handler (void) ;
void test_function_return (void) ;
void test_elf_threading_system (void) ;
void test_delay (void) ;
void test_print_font_vbe (void) ;
void mfs_dump_seg(mfs_entry_t* segment) ;
int test_invoke_kernel_function(const char* module_name, const char* function_name) ;
int test(int a, int b) ;
int test_simple_call (void) ;
int test_6_args(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) ;
mfs_entry_t * find_thread_table (void) ;
int read_thread(uint32_t thread_id, thread_control_block_t* thread_buffer) ;
int write_thread(uint32_t thread_id, const thread_control_block_t* thread_data) ;
uint32_t find_thread_by_name(const char* module_name) ;
void init_threading_system (void) ;
uint32_t create_thread(const char* code_segment_name, const char* thread_name, uint32_t priority, uint32_t stack_size) ;
void execute_thread(uint32_t thread_id) ;
void create_thread_code_segment (void) ;
void dump_page_permissions(uint64_t virt_addr) ;
void dump_gdt_info (void) ;
void real_context_switch(uint32_t thread_id, interrupt_frame_t* frame) ;
void thread_terminate(uint32_t thread_id) ;
void register_preemptive_thread(uint32_t thread_id) ;
void execute(uint32_t thread_id) ;
void init_context_restoration_interrupt (void) ;
void context_restore_interrupt_handler (void) ;
void init_user_tracking (void) ;
uint64_t create_guard_page (void) ;
int check_guard_page(uint64_t guard_addr) ;
int find_user_allocation(void* ptr) ;
int user_memory_init (void) ;
uint64_t user_guard_page_allocator(size_t guard_size) ;
void user_guard_page_deallocator(uint64_t guard_addr) ;
void user_memcpy(void* dest, const void* src, size_t n) ;
void* user_memset(void* ptr, int value, size_t n) ;
int user_map_page(uint64_t virt_addr, uint64_t phys_addr, uint64_t flags) ;
void* user_stack_alloc(size_t size) ;
void user_stack_free(void* stack_top, size_t size) ;
time_t time(time_t *t) ;
struct tm* gmtime(const time_t *timep) ;
time_t mktime(struct tm *tm) ;
size_t strlen(const char *s) ;
char* strcpy(char *dest, const char *src) ;
int strcmp(const char *s1, const char *s2) ;
int strncmp(const char *s1, const char *s2, size_t n) ;
char* strtok(char *str, const char *delim) ;
char* strstr(const char *haystack, const char *needle) ;
void* memset(void* s, int c, size_t n) ;
void* memcpy(void* dest, const void* src, size_t n) ;
void* __memcpy_chk(void* dest, const void* src, size_t len, size_t destlen) ;
char* __strcpy_chk(char* dest, const char* src, size_t destlen) ;
int __printf_chk(int flag, const char* format, ...) ;
int printf(const char* format, ...) ;
char* __strcat_chk(char* dest, const char* src, size_t destlen) ;
char* itoa(int value, char* str, int base) ;
void* __memmove_chk(void* dest, const void* src, size_t len, size_t destlen) ;
void* __memset_chk(void* s, int c, size_t len, size_t slen) ;
void __stack_chk_fail(void) ;
void* memmove(void* dest, const void* src, size_t n) ;
int memcmp(const void* s1, const void* s2, size_t n) ;
char* strcat(char* dest, const char* src) ;
char* strncpy(char* dest, const char* src, size_t n) ;
void abort(void) ;
void exit(int status) ;
void uint64_to_hex(uint64_t value, char* str) ;
void print_decimal(uint64_t num) ;
void print_signed_decimal(int64_t num) ;
uint64_t get_stack_pointer (void) ;
uint64_t get_base_pointer (void) ;
int copy_string_from_user(uint64_t user_ptr, char* kernel_buf, size_t max_len) ;
char hex_digit(unsigned char val) ;
void byte_to_hex(uint8_t byte, char* out) ;
void offset_to_hex(size_t offset, char* out) ;
void parse_multiboot2(uint64_t mb2_addr) ;
uint32_t make_color(uint8_t r, uint8_t g, uint8_t b) ;
void putpixel(uint64_t fb_addr, uint32_t pitch, uint32_t x, uint32_t y, uint32_t color) ;
void draw_rect(int x, int y, int width, int height, uint32_t color) ;
void fill_screen(uint64_t fb_addr, uint32_t width, uint32_t height, uint32_t pitch, uint32_t color) ;
int renderer_init_mfs_backbuffer(uint32_t width, uint32_t height, uint32_t pitch) ;
void put_pixel(int x, int y, uint32_t color) ;
void renderer_putpixel_mfs(int x, int y, uint32_t color) ;
void renderer_fill_rect_mfs(int x, int y, int w, int h, uint32_t color) ;
void renderer_present_mfs (void) ;
void renderer_blink_animation_mfs(int x, int y, int w, int h, uint32_t color1, uint32_t color2, int frames, int delay_loops) ;
void test_renderer_mfs (void) ;
void clear_screen_vbe(uint32_t color) ;
void render_char_vbe(int px, int py, char c, uint32_t color) ;
void print_vbe(const char* str, uint32_t color) ;
void print_at_vbe(int x, int y, const char* str, uint32_t color) ;
void key_input (void) ;
unsigned short make_vga_entry(char c, unsigned char color) ;
void vga_write_safe(int x, int y, char c, unsigned char color) ;
void clear_screen (void) ;
void scroll_screen (void) ;
void print(const char* str) ;
void println(const char* str) ;
void debug_mfs_state_after_threading();

void debug_directory_contents(mfs_entry_t* dir, const char* dir_name);
