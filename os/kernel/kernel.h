#ifndef KERNEL_H
#define KERNEL_H

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

#include "block.h"
#include "gristle.h"
#include "dirent.h"
#include "../../modules/port.h"
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>

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

#define PORT_MAGIC 0xDEADC0DE
#define MAX_PORT_NAME 32
#define MAX_PORT_DATA 256
#define PORT_STATUS_EMPTY 0
#define PORT_STATUS_REQUEST 1
#define PORT_STATUS_RESPONSE 2
#define PORT_STATUS_ERROR 3

// MFS entry types
typedef enum {
    MFS_TYPE_FREE = 0,
    MFS_TYPE_DIR = 1,
    MFS_TYPE_SEGMENT = 2,
    MFS_TYPE_GUARD = 3
} mfs_entry_type_t;

typedef struct {
    uint32_t magic;
    char port_name[32];
    uint32_t status;
    uint32_t request_id;
    uint32_t data_size;
    uint8_t data[256];
    uint8_t result[64];
    uint32_t timestamp;
	uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
	uint32_t caller_id;
    uint32_t notification_flag;  // ADD AT THE END to avoid breaking existing code
} port_message_t;

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
static int next_process_id = 1;
static mfs_entry_t* processes_dir = NULL;

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

static mfs_superblock_t mfs_sb;

// Dynamic Module System
#define MAX_MODULES 32
#define MAX_FUNCTIONS_PER_MODULE 16

typedef struct {
    char name[32];
    uint64_t address;
    uint32_t size;
} module_function_t;

// ALSO - Change entry_point to segment name
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

// Define syscall_entry_t struct
typedef struct {
    const char* name;
    int arg_count;          // Number of arguments expected
    const char* arg_types;  // String representing argument types, e.g. "iis" for int, int, string
    const char* ret_type;   // Return type as string, e.g. "i" for int
    int (*func_ptr)(void* args);  // Uniform function pointer taking void* args
} syscall_entry_t;

// Example argument structs for different syscalls
typedef struct {
    const char* str;
} print_args_t;

typedef struct {
    int a;
    int b;
} add_args_t;

// Thread states
#define THREAD_STATE_READY      0
#define THREAD_STATE_RUNNING    1
#define THREAD_STATE_BLOCKED    2
#define THREAD_STATE_TERMINATED 3

typedef struct {
    char name[32];
    mfs_entry_t* segment;
    module_function_t functions[MAX_FUNCTIONS_PER_MODULE];
    int function_count;
} module_t;

static module_t loaded_modules[MAX_MODULES];
static int module_count = 0;
static mfs_entry_t* modules_dir = NULL;

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

// Page fault handler type
typedef void (*page_fault_handler_t)(void);

typedef struct {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t int_no, err_code;
    uint64_t rip, cs, rflags, rsp, ss;
} interrupt_frame_t;

/* os/kernel/kernel.c */
int paging_init(void);
int paging_map_range(uint64_t start_addr, uint64_t size);
void page_fault_handler(uint64_t error_code, uint64_t fault_addr);
void serial_init(void);
int serial_transmit_empty(void);
void serial_putchar(char c);
void serial_write(const char *str);
void serial_println(const char *str);
void serial_print_hex(uint64_t value);
void serial_print_int(uint64_t value);
void serial_dump_vga_buffer(void);
time_t time(time_t *t);
struct tm *gmtime(const time_t *timep);
time_t mktime(struct tm *tm);
size_t strlen(const char *s);
char *strcpy(char *dest, const char *src);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strtok(char *str, const char *delim);
char *strstr(const char *haystack, const char *needle);
void *memset(void *s, int c, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
void memory_init(void);
void *malloc(size_t size);
void free(void *ptr);
void *realloc(void *ptr, size_t size);
void *calloc(size_t nmemb, size_t size);
void *basic_malloc(size_t size);
void basic_free(void *ptr);
void GRISTLE_SYSUNLOCK(void);
void clear_screen(void);
void scroll_screen(void);
void print(const char *str);
void println(const char *str);
void *__memcpy_chk(void *dest, const void *src, size_t len, size_t destlen);
char *__strcpy_chk(char *dest, const char *src, size_t destlen);
int __printf_chk(int flag, const char *format, ...);
int printf(const char *format, ...);
char *__strcat_chk(char *dest, const char *src, size_t destlen);
void *__memmove_chk(void *dest, const void *src, size_t len, size_t destlen);
void *__memset_chk(void *s, int c, size_t len, size_t slen);
void __stack_chk_fail(void);
int gettimeofday(struct timeval *tv, struct timezone *tz);
void *memmove(void *dest, const void *src, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
char *strcat(char *dest, const char *src);
char *strncpy(char *dest, const char *src, size_t n);
void abort(void);
void exit(int status);
void *safe_malloc(size_t size);
void validation_fault_handler(void);
void default_page_fault_handler(void);
page_fault_handler_t set_page_fault_handler(page_fault_handler_t handler);
int validate_memory_mapping(uint64_t addr, size_t size);
void page_fault_handler_entry(void);
void init_page_fault_handler(void);
int user_paging_init(void);
int user_memory_init(void);
void user_memcpy(void *dest, const void *src, size_t n);
void *user_memset(void *ptr, int value, size_t n);
int user_map_page(uint64_t virt_addr, uint64_t phys_addr, uint64_t flags);
void *user_stack_alloc(size_t size);
void user_stack_free(void *stack_top, size_t size);
char scancode_to_ascii(uint8_t scancode);
int mfs_init(void);
int mfs_chmod(mfs_entry_t *entry, uint32_t new_permissions);
int mfs_check_permission(mfs_entry_t *entry, uint32_t required_perm);
mfs_entry_t *mfs_dir(const char *name, mfs_entry_t *parent);
mfs_entry_t *mfs_seg(const char *name, size_t size, mfs_entry_t *parent);
mfs_entry_t *mfs_seg_at(const char *name, size_t size, uint64_t specific_addr, mfs_entry_t *parent);
void mfs_cleanup_all(void);
void *mfs_get_data(mfs_entry_t *entry);
size_t mfs_get_size(mfs_entry_t *entry);
mfs_entry_t *mfs_find(const char *name, mfs_entry_t *dir);
int mfs_write(mfs_entry_t *entry, size_t offset, const void *data, size_t size);
int mfs_read(mfs_entry_t *entry, size_t offset, void *data, size_t size);
void *user_malloc(size_t size);
void user_free(void *ptr);
int init_paged_stack_system(void);
void *allocate_paged_stack(void);
void free_paged_stack(void *stack_ptr);
int block_init(void);
int block_halt(void);
int block_read(blockno_t block, void *buf);
int block_write(blockno_t block, void *buf);
blockno_t block_get_volume_size(void);
int block_get_block_size(void);
int block_get_device_read_only(void);
int block_get_error(void);
void *safe_buffer_alloc(size_t size);
time_t fat_to_unix_time(uint16_t fat_time);
uint16_t fat_from_unix_time(time_t seconds);
time_t fat_to_unix_date(uint16_t fat_date);
uint16_t fat_from_unix_date(time_t seconds);
int fat_update_atime(int fd);
int fat_update_mtime(int fd);
int8_t fat_get_next_file(void);
char doschar(char c);
int make_dos_name(char *dosname, const char *path, int *path_pointer);
int fatname_to_str(char *output, char *input);
int str_to_fatname(char *url, char *dosname);
int fat_get_free_cluster(void);
int fat_free_clusters(uint32_t cluster);
int fat_flush(int fd);
int fat_select_cluster(int fd, uint32_t cluster);
int fat_next_cluster(int fd, int *rerrno);
int fat_next_sector(int fd);
int fat_flush_fileinfo(int fd);
int fat_lookup_path(int fd, const char *path, int *rerrno);
int fat_mount_fat16(blockno_t start, blockno_t volume_size);
int fat_mount_fat32(blockno_t start, blockno_t volume_size);
int fat_mount(blockno_t part_start, blockno_t volume_size, uint8_t filesystem_hint);
int fat_open(const char *name, int flags, int mode, int *rerrno);
int fat_close(int fd, int *rerrno);
int fat_read(int fd, void *buffer, size_t count, int *rerrno);
int fat_write(int fd, const void *buffer, size_t count, int *rerrno);
int fat_fstat(int fd, struct stat *st, int *rerrno);
int fat_lseek(int fd, int ptr, int dir, int *rerrno);
int fat_get_next_dirent(int fd, struct dirent *out_de, int *rerrno);
uint32_t find_directory_cluster(uint32_t parent_cluster, const char *dir_name);
int fat_delete(int fd, int *rerrno);
int fat_unlink(const char *path, int *rerrno);
int fat_rmdir(const char *path, int *rerrno);
int fat_mkdir(const char *path, int mode, int *rerrno);
int fs_ls(const char *path);
int fs_open(const char *filename);
int fs_close(int fd);
int fs_read(int fd, void *buffer, size_t count);
void test_disk(void);
int analyze_fat32_boot_sector(void);
int fs_init(void);
int validate_fat32_volume(void);
void test_filesystem(void);
int ensure_fat32_buffers_mapped(void);
int initialize_file_descriptor(int fd);
void setup_gdt_with_rings(void);
void general_exception_handler(void);
void isr_handler(interrupt_frame_t *frame);
void irq_handler(interrupt_frame_t *frame);
void set_idt_entry(int num, uint64_t handler, uint16_t selector, uint8_t flags);
void init_idt(void);
void exception_init(void);
void test_stable_filesystem(void);
void test_paging(void);
void memory_stress_test(void);
void simple_buffer_test(void);
void test_paged_stack_system(void);
void test_minimal_allocation(void);
void show_stack_slots(void);
void validate_gdt_selectors(void);
void test_minimal_iretq(void);
void uint64_to_hex(uint64_t value, char *str);
void test_user_memory(void);
void test_ring3_setup(void);
uint64_t load_test_program(void);
void set_page_permissions(uint64_t vaddr, uint64_t flags);
void *allocate_safe_user_stack(size_t size);
void debug_walk_page_tables(uint64_t vaddr, const char *desc);
void debug_ring3_transition(uint64_t entry_point, uint64_t user_rsp);
void set_page_permissions_4kb(uint64_t vaddr, uint64_t flags);
void *user_malloc_4kb(size_t size);
void *user_malloc_aligned(size_t size, size_t alignment);
int verify_ring3_environment(void);
void test_mfs_comprehensive(void);
void init_module_system(void);
int load_module(const char *module_name);
int call_module_function(const char *module_name, const char *function_name);
int call_module_via_port(const char *module_name, const char *function_name, int param1, int param2);
void load_boot_modules(void);
int load_test_module_direct(void);
void init_port_system(void);
int create_port(const char *port_name);
int call_func_port(const char *app_name, const char *func_name, void *args, size_t args_size);
void process_ports(void);
void process_port_request(port_message_t *port);
void print_decimal(uint64_t num);
void print_signed_decimal(int64_t num);
uint64_t get_stack_pointer(void);
uint64_t get_base_pointer(void);
void dump_stack_area(const char *label);
void test_stack_push(void);
void test_stack_frame(void);
void test_stack_stress(void);
void test_stack_alignment(void);
void debug_interrupt_handler(void);
void test_function_return(void);
mfs_entry_t *find_thread_table(void);
int read_thread(uint32_t thread_id, thread_control_block_t *thread_buffer);
int write_thread(uint32_t thread_id, const thread_control_block_t *thread_data);
uint32_t find_thread_by_name(const char *module_name);
void init_threading_system(void);
uint32_t create_thread(const char *code_segment_name, const char *thread_name, uint32_t priority, uint32_t stack_size);
void execute_thread(uint32_t thread_id);
void create_thread_code_segment(void);
void dump_page_permissions(uint64_t virt_addr);
void dump_gdt_info(void);
void real_context_switch(uint32_t thread_id, interrupt_frame_t *frame);
void thread_terminate(void);
void save_thread_state(uint32_t thread_index);
void restore_thread_state(uint32_t thread_index);
void register_preemptive_thread(uint32_t thread_id);
void register_port_processor(const char *app_name, void (*processor_func)(void));
void standalone_trampoline_switch(uint32_t target_thread_id, port_message_t *caller_port, port_message_t *target_port, const char *target_function);
void check_fast_trampoline_completion(void);
void register_dynamic_port_processor(const char *app_name, uint64_t check_notifications_addr);
void call_app_function_from_interrupt(uint64_t function_addr);
void interrupt_process_all_ports(void);
int get_symbol_name_from_elf(int fd, elf64_header_t *elf_header, uint32_t name_offset, char *name_buffer, size_t buffer_size);
int elf_resolve_and_map_functions(const char *elf_path, const char *module_dir_name);
uint32_t elf_thread_loader(const char *elf_path, const char *thread_name);
void test_elf_threading_system(void);
void create_module_function_registry(void);
void register_module_function(const char *module_name, const char *function_name);
void execute(uint32_t thread_id);
void init_context_restoration_interrupt(void);
void context_restore_interrupt_handler(void);
void init_system_clock(void);
void update_system_clock(void);
uint32_t get_uptime_seconds(void);
void show_uptime(void);
void timer_interrupt_handler(void);
void port_notification_handler(void);
void init_port_notification_interrupt(void);
void test_delay(void);
int kernel_getchar(void);
void parse_multiboot2(uint64_t mb2_addr);
uint32_t make_color(uint8_t r, uint8_t g, uint8_t b);
void putpixel(uint64_t fb_addr, uint32_t pitch, uint32_t x, uint32_t y, uint32_t color);
void fill_screen(uint64_t fb_addr, uint32_t width, uint32_t height, uint32_t pitch, uint32_t color);
int renderer_init_mfs_backbuffer(uint32_t width, uint32_t height, uint32_t pitch);
void renderer_putpixel_mfs(int x, int y, uint32_t color);
void renderer_fill_rect_mfs(int x, int y, int w, int h, uint32_t color);
void renderer_present_mfs(void);
void renderer_blink_animation_mfs(int x, int y, int w, int h, uint32_t color1, uint32_t color2, int frames, int delay_loops);
void test_renderer_mfs(void);
int load_font(const char *filename);
void render_char_vbe(int px, int py, char c, uint32_t color);
void test_print_font_vbe(void);
void print_vbe(const char *str, uint32_t color);
void print_at_vbe(int x, int y, const char *str, uint32_t color);
void key_input(void);
char hex_digit(unsigned char val);
void byte_to_hex(uint8_t byte, char *out);
void offset_to_hex(size_t offset, char *out);
void mfs_dump_seg(mfs_entry_t *segment);
void kernel_main(uint64_t mb2_info_addr);

#endif // KERNEL_H

