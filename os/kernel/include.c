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

// Memory management globals
memory_block_t* heap_start = NULL;
int memory_initialized = 0;
// Add global counter at top of file
uint32_t loaded_modules_count = 0;
uint32_t interrupt_processing_active = 0;

uint32_t g_fb_width, g_fb_height, g_fb_pitch;
uint64_t g_fb_addr;
uint8_t red_pos, green_pos, blue_pos;

int cursor_x = 0;
int cursor_y = 0;

// Disk information
uint32_t disk_size = 0;
int disk_error = 0;
int fs_initialized = 0;

// Mouse state
uint8_t mouse_packet[MOUSE_PACKET_SIZE];
uint8_t mouse_packet_index = 0;

// Mouse position (can be integrated with your input system)
int mouse_x = 0;
int mouse_y = 0;
int mouse_buttons = 0;

// External filesystem globals (defined in krnlfs32.c)
extern struct fat_info fatfs;
extern FileS file_num[MAX_OPEN_FILES];

// Extended thread state for preemptive switching


// Complete CPU state for temporary context switches


// Global mapping table


elf_mapping_t elf_mappings[16];
int mapping_count = 0;

full_temp_context_t temp_call_stack[16];
uint32_t temp_call_depth = 0;

saved_thread_state_t thread_states[64];  // Match MAX_THREADS
uint32_t current_thread_index = 0;
uint32_t preemptive_enabled = 0;
uint32_t active_thread_count = 0;

paging_memory_block_t* paging_heap_head = NULL;
// Memory operation context to prevent circular calls
int memory_operation_in_progress = 0;
int paging_operation_in_progress = 0;

// VGA buffer - Use linker symbols for proper mapping
extern uint64_t vga_buffer_start;
extern uint64_t vga_buffer_end;

// VGA buffer - properly mapped by linker
volatile unsigned short* const VGA_BUFFER = (volatile unsigned short*)0xB8000;

// Page fault handler type
typedef void (*page_fault_handler_t)(void);

// Current page fault handler
page_fault_handler_t current_page_fault_handler = NULL;

uintptr_t __stack_chk_guard = 0xdeadbeef;  // ✅ Definition in source file

// Page tracking structure (limited size)


user_page_info_t user_pages[MAX_USER_PAGES];
int user_pages_count = 0;
int user_paging_initialized = 0;

// User memory block structure


user_memory_block_t* user_memory_head = NULL;

// Global error flag for memory validation
int validation_error = 0;


// Global page tables
page_table_t* pml4_table;
page_table_t* pdpt_table;
page_table_t* pd_tables[4];  // Support up to 4GB
uint64_t next_free_page = 0x800000; // Start aft
uint64_t paging_heap_start = 0x10000000;  // 256MB
uint64_t paging_heap_current = 0x10000000;
uint64_t paging_heap_end = 0x20000000;    // 512MB (256MB heap)
int paging_memory_initialized = 0;
int paging_initialized = 0;
// User allocation tracking


user_allocation_t user_allocations[MAX_USER_ALLOCATIONS];
int user_allocation_count = 0;
int user_tracking_initialized = 0;

idt_entry_t idt[256];
int idt_initialized = 0;
uint64_t kernel_rsp_global;
uint64_t kernel_rbp_global;

volatile char keyboard_buffer[KEYBOARD_BUFFER_SIZE];
volatile int keyboard_buffer_head = 0;
volatile int keyboard_buffer_tail = 0;

// Process management globals
int next_process_id = 1;
mfs_entry_t* processes_dir = NULL;

// MFS superblock

tss_t kernel_tss;
uint8_t kernel_stack[65536] __attribute__((aligned(16)));

mfs_superblock_t mfs_sb = {0};  // ✅ Single definition with zero initialization

int next_pid = 100;  // Start PIDs at 100

// CONTEXT RESTORATION INTERRUPT - ADD THESE DECLARATIONS
uint32_t pending_restore_thread_id = 0;
uint32_t current_thread_id = 0;  // Track current thread
uint32_t thread_count = 0;

// Renderer globals
// Globals for MFS backbuffer
mfs_entry_t* backbuffer_segment = NULL;
uint32_t backbuffer_width = 0;
uint32_t backbuffer_height = 0;
uint32_t backbuffer_pitch = 0;
uint64_t framebuffer_addr = 0;
uint32_t framebuffer_pitch = 0;
uint32_t framebuffer_width = 0;
uint32_t framebuffer_height = 0;


paged_stack_entry_t paged_stacks[MAX_STACKS];
int paged_stack_system_initialized = 0;

uint8_t fat32_buffer[512] __attribute__((aligned(512))); // 512-byte aligned buffer

// fs_init - Initialize and mount the filesystem (extracted from fs_ls

// Define TSS structure


volatile int should_test_port = 0;


// Fix cursor artifacts by disabling cursor updates during screen clear
int cursor_disabled = 0;

mouse_interrupt_state_t mouse_state = {640, 360, 640, 360, 0, 0, 0, {0}, 0, 0, 0, 0};


uint32_t saved_background[2048]; // Increase for outline pixels
int saved_pixel_count = 0;
int saved_valid = 0;

module_t loaded_modules[MAX_MODULES];
int module_count = 0;
mfs_entry_t* modules_dir = NULL;

// ELF header structures
uint32_t arrow_cursor_32[32] = {
    0x80000000, 0xC0000000, 0xE0000000, 0xF0000000,
    0xF8000000, 0xFC000000, 0xFE000000, 0xFF000000,
    0xFF800000, 0xFFC00000, 0xFFE00000, 0xFFF00000,
    0xFFF80000, 0xFFFC0000, 0xFFFE0000, 0xFFFF0000,
    0xFFF80000, 0xFFF80000, 0xF9F80000, 0xF0FC0000,
    0xE0FC0000, 0xC07E0000, 0x807E0000, 0x003F0000,
    0x003F0000, 0x001F8000, 0x001F8000, 0x000FC000,
    0x000FC000, 0x00000000, 0x00000000, 0x00000000
};

// Add to kernel.c - Port management system
mfs_entry_t* ports_dir = NULL;

// Port processing function registry


port_processor_registry_t port_processors[16];
uint32_t processor_count = 0;

uint32_t trampoline_in_progress = 0;


dynamic_port_processor_t dynamic_processors[16];
uint32_t dynamic_processor_count = 0;

// Simple system time tracking
volatile uint64_t system_ticks = 0;
volatile uint32_t uptime_seconds = 0;
int clock_initialized = 0;

uint8_t font_bitmaps[FONT_NUM_CHARS][FONT_CHAR_HEIGHT];

