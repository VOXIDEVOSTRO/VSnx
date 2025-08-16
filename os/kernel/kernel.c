#include "include.h"
/*==============================================================================================================
  ENTRYPOINT
================================================================================================================*/
void kernel_main(uint64_t mb2_info_addr) {
    clear_screen();
    println("VOSTROX OS - RING 3 ISOLATION TEST");
    println("64-bit Kernel Starting...");
    println("");
	// Test Ring 3 setup instead of ELF
    exception_init();
    println("");
    // Initialize paging system
    paging_init();
    println("");
    // Initialize memory system
    memory_init();
    println("Memory system initialized");
    println("");
	mfs_init();
	println("");
	fs_init();
	println("File system initialized");
	fs_ls("/MODULES/SYS/");
	parse_multiboot2(mb2_info_addr);
	renderer_init_mfs_backbuffer(g_fb_width, g_fb_height, g_fb_pitch);
	load_font("/MODULES/SYS/FONTS/FONTS/AIXOID9.F16");
	// Initialize mailbox communication system
    init_port_system();
	println("");
	init_port_notification_interrupt();
	// Initialize system clock
    init_system_clock();
	println("Uptime 00:00:00:00");
	// Initialize threading
    init_threading_system();
	init_context_restoration_interrupt();
	// Create module function registry
    create_module_function_registry();
	// Initialize interrupt-driven mouse (replaces init_mouse)
    init_mouse_interrupt();
	elf_resolve_and_map_functions("KERNEL/KERNEL.BIN", "SYSTEM");
	// Initialize syscall system
    init_syscalls();
	//init_syscall_system();
	//example_result_parameter_usage();
	test_delay();
    while (1) {
		__asm__ volatile("hlt");
    }
}
