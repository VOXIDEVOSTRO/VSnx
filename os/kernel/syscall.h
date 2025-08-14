// syscall.h - Syscall definitions and IDs
#ifndef SYSCALL_H
#define SYSCALL_H

#include <stdint.h>

// Syscall numbers
#define SYS_PRINTF          1
#define SYS_MFS_FIND        2
#define SYS_MFS_READ        3
#define SYS_MFS_WRITE       4
#define SYS_MFS_SEG         5
#define SYS_MFS_DIR         6
#define SYS_GET_MFS_SB      7
#define SYS_GET_MFS_TABLE   8
#define SYS_GET_ROOT_DIR    9
#define SYS_GET_PORTS_DIR   10
#define SYS_MALLOC          11
#define SYS_FREE            12
#define SYS_GET_UPTIME      13
#define SYS_SHOW_UPTIME     14
#define SYS_FS_OPEN         15
#define SYS_FS_CLOSE        16
#define SYS_FS_READ         17
#define SYS_FS_LS           18
#define SYS_GETCHAR         19
#define SYS_CLEAR_SCREEN    20
#define SYS_VGA_WRITE       21
#define SYS_EXECUTE         22
#define SYS_ELF_LOADER      23
#define SYS_DECLARE_FUNCTION	26
#define SYS_CALL_FUNCTION         27

#define MAX_SYSCALLS        30

// Syscall function pointer type
typedef int64_t (*syscall_handler_t)(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);

// Syscall structure
typedef struct {
    syscall_handler_t handler;
    const char* name;
    int arg_count;
} syscall_entry_t;

// Add the syscall table declaration before the handlers
static syscall_entry_t syscall_table[MAX_SYSCALLS];

// Userland syscall macro
#define syscall(num, arg1, arg2, arg3, arg4, arg5, arg6) \
    ({ \
        int64_t result; \
        __asm__ volatile( \
            "movq %1, %%rax\n\t"     /* syscall number */ \
            "movq %2, %%rdi\n\t"     /* arg1 */ \
            "movq %3, %%rsi\n\t"     /* arg2 */ \
            "movq %4, %%rdx\n\t"     /* arg3 */ \
            "movq %5, %%r10\n\t"     /* arg4 */ \
            "movq %6, %%r8\n\t"      /* arg5 */ \
            "movq %7, %%r9\n\t"      /* arg6 */ \
            "int $0x80\n\t"          /* syscall interrupt */ \
            "movq %%rax, %0" \
            : "=r" (result) \
            : "r" ((uint64_t)(num)), "r" ((uint64_t)(arg1)), "r" ((uint64_t)(arg2)), \
              "r" ((uint64_t)(arg3)), "r" ((uint64_t)(arg4)), "r" ((uint64_t)(arg5)), \
              "r" ((uint64_t)(arg6)) \
            : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "memory" \
        ); \
        result; \
    })

// Global state for pre-declared function calls
static struct {
    char module_name[64];
    char function_name[64];
    int arg_count;
    int is_set;
} predeclared_call = {0};

// Convenience macros for common syscalls
#define sys_printf(str)                     syscall(SYS_PRINTF, (uint64_t)(str), 0, 0, 0, 0, 0)
#define sys_mfs_find(name, parent)          syscall(SYS_MFS_FIND, (uint64_t)(name), (uint64_t)(parent), 0, 0, 0, 0)
#define sys_mfs_read(entry, offset, buf, sz) syscall(SYS_MFS_READ, (uint64_t)(entry), (uint64_t)(offset), (uint64_t)(buf), (uint64_t)(sz), 0, 0)
#define sys_mfs_write(entry, offset, buf, sz) syscall(SYS_MFS_WRITE, (uint64_t)(entry), (uint64_t)(offset), (uint64_t)(buf), (uint64_t)(sz), 0, 0)
#define sys_mfs_seg(name, size, parent)     syscall(SYS_MFS_SEG, (uint64_t)(name), (uint64_t)(size), (uint64_t)(parent), 0, 0, 0)
#define sys_mfs_dir(name, parent)           syscall(SYS_MFS_DIR, (uint64_t)(name), (uint64_t)(parent), 0, 0, 0, 0)
#define sys_get_mfs_superblock()            syscall(SYS_GET_MFS_SB, 0, 0, 0, 0, 0, 0)
#define sys_get_mfs_entry_table()           syscall(SYS_GET_MFS_TABLE, 0, 0, 0, 0, 0, 0)
#define sys_get_root_dir()                  syscall(SYS_GET_ROOT_DIR, 0, 0, 0, 0, 0, 0)
#define sys_get_ports_dir()                 syscall(SYS_GET_PORTS_DIR, 0, 0, 0, 0, 0, 0)
#define sys_malloc(size)                    syscall(SYS_MALLOC, (uint64_t)(size), 0, 0, 0, 0, 0)
#define sys_free(ptr)                       syscall(SYS_FREE, (uint64_t)(ptr), 0, 0, 0, 0, 0)
#define sys_get_uptime()                    syscall(SYS_GET_UPTIME, 0, 0, 0, 0, 0, 0)
#define sys_show_uptime()                   syscall(SYS_SHOW_UPTIME, 0, 0, 0, 0, 0, 0)
#define sys_fs_open(path)                   syscall(SYS_FS_OPEN, (uint64_t)(path), 0, 0, 0, 0, 0)
#define sys_fs_close(fd)                    syscall(SYS_FS_CLOSE, (uint64_t)(fd), 0, 0, 0, 0, 0)
#define sys_fs_read(fd, buf, size)          syscall(SYS_FS_READ, (uint64_t)(fd), (uint64_t)(buf), (uint64_t)(size), 0, 0, 0)
#define sys_fs_ls(path)                     syscall(SYS_FS_LS, (uint64_t)(path), 0, 0, 0, 0, 0)
#define sys_getchar()                       syscall(SYS_GETCHAR, 0, 0, 0, 0, 0, 0)
#define sys_clear_screen()                  syscall(SYS_CLEAR_SCREEN, 0, 0, 0, 0, 0, 0)
#define sys_vga_write(x, y, c, color)       syscall(SYS_VGA_WRITE, (uint64_t)(x), (uint64_t)(y), (uint64_t)(c), (uint64_t)(color), 0, 0)
#define sys_execute(thread_id)              syscall(SYS_EXECUTE, (uint64_t)(thread_id), 0, 0, 0, 0, 0)
#define sys_elf_loader(path, name)          syscall(SYS_ELF_LOADER, (uint64_t)(path), (uint64_t)(name), 0, 0, 0, 0)
#define sys_declare_function(module, function, argc) syscall(SYS_DECLARE_FUNCTION, (uint64_t)(module), (uint64_t)(function), (uint64_t)(argc), 0, 0, 0)
#define sys_call_function(arg1, arg2, arg3, arg4, arg5, arg6) syscall(SYS_CALL_FUNCTION, (uint64_t)(arg1), (uint64_t)(arg2), (uint64_t)(arg3), (uint64_t)(arg4), (uint64_t)(arg5), (uint64_t)(arg6))

#endif // SYSCALL_H
