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
  INTERRUPT-DRIVEN MOUSE SUPPORT FOR VOSTROX
================================================================================================================*/

// Simple cursor with built-in outline - just draw black then white
void draw_arrow_cursor_32(int x, int y) {
    static int last_x = -1, last_y = -1;
    
    // Restore previous background
    if (saved_valid && last_x >= 0 && last_y >= 0) {
        int idx = 0;
        for (int cy = 0; cy < 32; cy++) {
            uint32_t row = arrow_cursor_32[cy];
            for (int cx = 0; cx < 32; cx++) {
                if (row & (0x80000000 >> cx)) {
                    int px = last_x + cx;
                    int py = last_y + cy;
                    if (px >= 0 && px < backbuffer_width && py >= 0 && py < backbuffer_height) {
                        size_t offset = (py * backbuffer_width + px) * 4;
                        mfs_write(backbuffer_segment, offset, &saved_background[idx], 4);
                    }
                    idx++;
                }
            }
        }
    }
    
    // Save new background
    saved_pixel_count = 0;
    for (int cy = 0; cy < 32; cy++) {
        uint32_t row = arrow_cursor_32[cy];
        for (int cx = 0; cx < 32; cx++) {
            if (row & (0x80000000 >> cx)) {
                int px = x + cx;
                int py = y + cy;
                if (px >= 0 && px < backbuffer_width && py >= 0 && py < backbuffer_height) {
                    size_t offset = (py * backbuffer_width + px) * 4;
                    mfs_read(backbuffer_segment, offset, &saved_background[saved_pixel_count], 4);
                }
                saved_pixel_count++;
            }
        }
    }
    saved_valid = 1;
    
    // Draw cursor with simple outline - black first, then white smaller
    uint32_t black = 0x000000;
    uint32_t white = 0xFFFFFF;
    
    for (int cy = 0; cy < 32; cy++) {
        uint32_t row = arrow_cursor_32[cy];
        for (int cx = 0; cx < 32; cx++) {
            if (row & (0x80000000 >> cx)) {
                int px = x + cx;
                int py = y + cy;
                if (px >= 0 && px < backbuffer_width && py >= 0 && py < backbuffer_height) {
                    size_t offset = (py * backbuffer_width + px) * 4;
                    
                    // Draw black outline on edges, white in center
                    if (cx == 0 || cy == 0 || 
                        !(arrow_cursor_32[cy] & (0x80000000 >> (cx-1))) ||
                        !(arrow_cursor_32[cy] & (0x80000000 >> (cx+1))) ||
                        (cy > 0 && !(arrow_cursor_32[cy-1] & (0x80000000 >> cx))) ||
                        (cy < 31 && !(arrow_cursor_32[cy+1] & (0x80000000 >> cx)))) {
                        mfs_write(backbuffer_segment, offset, &black, 4);
                    } else {
                        mfs_write(backbuffer_segment, offset, &white, 4);
                    }
                }
            }
        }
    }
    
    last_x = x;
    last_y = y;
}

int get_mouse_x (void) {
	return mouse_state.x;
}
int get_mouse_y (void) {
	return mouse_state.y;
}

// Forward declarations
void mouse_irq_handler(void);
void mouse_irq_asm_wrapper(void);

// Assembly wrapper for mouse IRQ handler
__asm__(
    ".global mouse_irq_asm_wrapper\n"
    "mouse_irq_asm_wrapper:\n"
    "    pushq %rax\n"
    "    pushq %rbx\n"
    "    pushq %rcx\n"
    "    pushq %rdx\n"
    "    pushq %rsi\n"
    "    pushq %rdi\n"
    "    pushq %rbp\n"
    "    pushq %r8\n"
    "    pushq %r9\n"
    "    pushq %r10\n"
    "    pushq %r11\n"
    "    pushq %r12\n"
    "    pushq %r13\n"
    "    pushq %r14\n"
    "    pushq %r15\n"
    "    call mouse_irq_handler\n"
    "    popq %r15\n"
    "    popq %r14\n"
    "    popq %r13\n"
    "    popq %r12\n"
    "    popq %r11\n"
    "    popq %r10\n"
    "    popq %r9\n"
    "    popq %r8\n"
    "    popq %rbp\n"
    "    popq %rdi\n"
    "    popq %rsi\n"
    "    popq %rdx\n"
    "    popq %rcx\n"
    "    popq %rbx\n"
    "    popq %rax\n"
    "    iretq\n"
);

void disable_cursor_updates (void) {
    cursor_disabled = 1;
}

void enable_cursor_updates (void) {
    cursor_disabled = 0;
    saved_valid = 0; // Force cursor redraw
}

// Mouse IRQ handler - called from interrupt
// Mouse IRQ handler - COMPLETE processing in interrupt
void mouse_irq_handler(void) {
    uint8_t status = inb(PS2_STATUS_PORT);
    
    if (!(status & 0x01) || !(status & 0x20)) {
        outb(0xA0, 0x20);
        outb(0x20, 0x20);
        return;
    }
    
    uint8_t data = inb(PS2_DATA_PORT);
    
    if (mouse_state.packet_index == 0 && !(data & 0x08)) {
        mouse_state.sync_errors++;
        outb(0xA0, 0x20);
        outb(0x20, 0x20);
        return;
    }
    
    mouse_state.packet[mouse_state.packet_index++] = data;
    
    if (mouse_state.packet_index >= 3) {
        mouse_state.packet_index = 0;
        
        uint8_t flags = mouse_state.packet[0];
        uint8_t raw_dx = mouse_state.packet[1];
        uint8_t raw_dy = mouse_state.packet[2];
        
        // PROPER SIGN EXTENSION FOR FAST MOVEMENT
        int dx = raw_dx;
        int dy = raw_dy;
        
        // Handle sign bits from flags byte
        if (flags & 0x10) dx = dx - 256;  // X sign bit
        if (flags & 0x20) dy = dy - 256;  // Y sign bit
        
        // Handle overflow flags
        if (flags & 0x40) dx = 0;  // X overflow - ignore packet
        if (flags & 0x80) dy = 0;  // Y overflow - ignore packet
        
        // Apply movement with proper scaling
        mouse_state.x += dx;
        mouse_state.y -= dy;
        
        // Boundary check - clamp hotspot only
		if (mouse_state.x < 0) mouse_state.x = 0;
		if (mouse_state.x >= (int)backbuffer_width) mouse_state.x = (int)backbuffer_width - 1;
		if (mouse_state.y < 0) mouse_state.y = 0;
		if (mouse_state.y >= (int)backbuffer_height) mouse_state.y = (int)backbuffer_height - 1;

        mouse_state.buttons = flags & 0x07;
        mouse_state.data_ready = 1;
    }

	if (mouse_state.packet_index >= mouse_state.packet_size) {
        mouse_state.packet_index = 0;
        
        uint8_t flags = mouse_state.packet[0];
        uint8_t raw_dx = mouse_state.packet[1];
        uint8_t raw_dy = mouse_state.packet[2];
        
        // Handle scroll wheel (4th byte)
        if (mouse_state.packet_size == 4) {
            int8_t scroll_raw = mouse_state.packet[3];
            mouse_state.scroll_delta = scroll_raw & 0x0F;  // Lower 4 bits
            if (mouse_state.scroll_delta & 0x08) {
                mouse_state.scroll_delta |= 0xF0;  // Sign extend
            }
            
            // Middle button is bit 4 of scroll byte
            if (mouse_state.packet[3] & 0x10) {
                mouse_state.buttons |= 0x04;  // Set middle button
            } else {
                mouse_state.buttons &= ~0x04; // Clear middle button
            }
        }
	}

	// Modify mouse_irq_handler:
	if (mouse_state.data_ready && !cursor_disabled) {
	    mouse_state.data_ready = 0;
	    draw_arrow_cursor_32(mouse_state.x, mouse_state.y);
	    renderer_present_mfs();
	}
    
    outb(0xA0, 0x20);
    outb(0x20, 0x20);
}

// Initialize interrupt-driven mouse
// Fix sync errors with proper PS/2 initialization
void init_mouse_interrupt(void) {
    println("MOUSE: Initializing interrupt-driven mouse");
    
    mouse_state.x = 640;
    mouse_state.y = 360;
    mouse_state.buttons = 0;
    mouse_state.packet_index = 0;
    mouse_state.packets_received = 0;
    mouse_state.sync_errors = 0;
    
    __asm__ volatile("cli");
    
    // Proper PS/2 controller initialization sequence
    outb(PS2_COMMAND_PORT, 0xAD);  // Disable first port
    outb(PS2_COMMAND_PORT, 0xA7);  // Disable second port
    
    // Flush output buffer
    while (inb(PS2_STATUS_PORT) & 0x01) {
        inb(PS2_DATA_PORT);
    }
    
    // Get and modify configuration
    outb(PS2_COMMAND_PORT, 0x20);
    uint8_t config = inb(PS2_DATA_PORT);
    config |= 0x02;   // Enable auxiliary interrupt
    config &= ~0x20;  // Enable auxiliary clock
    config &= ~0x10;  // Enable first port clock
    
    outb(PS2_COMMAND_PORT, 0x60);
    outb(PS2_DATA_PORT, config);
    
    // Enable ports
    outb(PS2_COMMAND_PORT, 0xAE);  // Enable first port
    outb(PS2_COMMAND_PORT, 0xA8);  // Enable auxiliary port
    
    // Reset mouse properly
    outb(PS2_COMMAND_PORT, 0xD4);
    outb(PS2_DATA_PORT, 0xFF);
    
    // Wait for BAT completion (0xAA)
    int timeout = 100000;
    while (timeout-- && !(inb(PS2_STATUS_PORT) & 0x01));
    if (timeout > 0) inb(PS2_DATA_PORT);  // Read BAT result
    
    // Wait for device ID
    timeout = 100000;
    while (timeout-- && !(inb(PS2_STATUS_PORT) & 0x01));
    if (timeout > 0) inb(PS2_DATA_PORT);  // Read device ID
    
    // Enable data reporting
    outb(PS2_COMMAND_PORT, 0xD4);
    outb(PS2_DATA_PORT, 0xF4);

	// Enable scroll wheel mode
    outb(PS2_COMMAND_PORT, 0xD4);
    outb(PS2_DATA_PORT, 0xF3);  // Set sample rate
    timeout = 100000;
    while (timeout-- && !(inb(PS2_STATUS_PORT) & 0x01));
    if (timeout > 0) inb(PS2_DATA_PORT);  // Read ACK
    
    outb(PS2_COMMAND_PORT, 0xD4);
    outb(PS2_DATA_PORT, 200);   // Sample rate 200
    timeout = 100000;
    while (timeout-- && !(inb(PS2_STATUS_PORT) & 0x01));
    if (timeout > 0) inb(PS2_DATA_PORT);  // Read ACK
    
    outb(PS2_COMMAND_PORT, 0xD4);
    outb(PS2_DATA_PORT, 0xF3);  // Set sample rate
    timeout = 100000;
    while (timeout-- && !(inb(PS2_STATUS_PORT) & 0x01));
    if (timeout > 0) inb(PS2_DATA_PORT);  // Read ACK
    
    outb(PS2_COMMAND_PORT, 0xD4);
    outb(PS2_DATA_PORT, 100);   // Sample rate 100
    timeout = 100000;
    while (timeout-- && !(inb(PS2_STATUS_PORT) & 0x01));
    if (timeout > 0) inb(PS2_DATA_PORT);  // Read ACK
    
    outb(PS2_COMMAND_PORT, 0xD4);
    outb(PS2_DATA_PORT, 0xF3);  // Set sample rate
    timeout = 100000;
    while (timeout-- && !(inb(PS2_STATUS_PORT) & 0x01));
    if (timeout > 0) inb(PS2_DATA_PORT);  // Read ACK
    
    outb(PS2_COMMAND_PORT, 0xD4);
    outb(PS2_DATA_PORT, 80);    // Sample rate 80
    timeout = 100000;
    while (timeout-- && !(inb(PS2_STATUS_PORT) & 0x01));
    if (timeout > 0) inb(PS2_DATA_PORT);  // Read ACK
    
    // Get device ID to check if scroll wheel is enabled
    outb(PS2_COMMAND_PORT, 0xD4);
    outb(PS2_DATA_PORT, 0xF2);  // Get device ID
    timeout = 100000;
    while (timeout-- && !(inb(PS2_STATUS_PORT) & 0x01));
    if (timeout > 0) inb(PS2_DATA_PORT);  // Read ACK
    
    timeout = 100000;
    while (timeout-- && !(inb(PS2_STATUS_PORT) & 0x01));
    if (timeout > 0) {
        uint8_t device_id = inb(PS2_DATA_PORT);
        if (device_id == 3) {
            mouse_state.packet_size = 4;  // 4-byte packets with scroll wheel
            println("MOUSE: Scroll wheel enabled");
        } else {
            mouse_state.packet_size = 3;  // Standard 3-byte packets
            println("MOUSE: Standard mouse (no scroll wheel)");
        }
    }
    
    timeout = 100000;
    while (timeout-- && !(inb(PS2_STATUS_PORT) & 0x01));
    if (timeout > 0) {
        uint8_t ack = inb(PS2_DATA_PORT);
        if (ack == 0xFA) {
            println("MOUSE: Enabled successfully");
        }
    }
    
    set_idt_entry(MOUSE_IRQ_VECTOR, (uint64_t)mouse_irq_asm_wrapper, KERNEL_CODE_SELECTOR, 0x8E);
    
    // Unmask IRQ 12
    uint8_t mask = inb(0xA1);
    mask &= ~(1 << 4);
    outb(0xA1, mask);
    
    mask = inb(0x21);
    mask &= ~(1 << 2);
    outb(0x21, mask);
    
    __asm__ volatile("sti");
    
    println("MOUSE: Pure interrupt mode active");
}

// Add button state functions that return current state, not edges
int get_left_button_state (void) {
    return (mouse_state.buttons & 0x01) ? 1 : 0;
}

int get_right_button_state (void) {
    return (mouse_state.buttons & 0x02) ? 1 : 0;
}

// Get current mouse state (for applications)
void get_mouse_state(int* x, int* y, uint8_t* buttons) {
    if (x) *x = mouse_state.x;
    if (y) *y = mouse_state.y;
    if (buttons) *buttons = mouse_state.buttons;
}

// Mouse statistics for debugging
void print_mouse_stats(void) {
    print("MOUSE: Packets received: ");
    print_decimal(mouse_state.packets_received);
    println("");
    
    print("MOUSE: Sync errors: ");
    print_decimal(mouse_state.sync_errors);
    println("");
    
    print("MOUSE: Position: (");
    print_decimal(mouse_state.x);
    print(", ");
    print_decimal(mouse_state.y);
    println(")");
    
    print("MOUSE: Buttons: 0x");
    char hex_str[4];
    hex_str[0] = (mouse_state.buttons < 10) ? ('0' + mouse_state.buttons) : ('A' + mouse_state.buttons - 10);
    hex_str[1] = '\0';
    println(hex_str);
}

// API Functions using existing mouse_state
int get_left_click(void) {
    int clicked = (mouse_state.buttons & 0x01) && !(mouse_state.last_buttons & 0x01);
    mouse_state.last_buttons = mouse_state.buttons;
    return clicked;
}

int get_right_click(void) {
    int clicked = (mouse_state.buttons & 0x02) && !(mouse_state.last_buttons & 0x02);
    mouse_state.last_buttons = mouse_state.buttons;
    return clicked;
}

int get_middle_click(void) {
    int clicked = (mouse_state.buttons & 0x04) && !(mouse_state.last_buttons & 0x04);
    mouse_state.last_buttons = mouse_state.buttons;
    return clicked;
}

int get_scroll(void) {
    int scroll = mouse_state.scroll_delta;
    mouse_state.scroll_delta = 0;
    return scroll;
}

typedef struct {
    int x, y;
    int dx, dy;
    int moved;
} mouse_move_data_t;

mouse_move_data_t get_mouse_move(void) {
    mouse_move_data_t data;
    data.x = mouse_state.x;
    data.y = mouse_state.y;
    data.dx = mouse_state.x - mouse_state.last_x;
    data.dy = mouse_state.y - mouse_state.last_y;
    data.moved = (data.dx != 0 || data.dy != 0);
    
    mouse_state.last_x = mouse_state.x;
    mouse_state.last_y = mouse_state.y;
    
    return data;
}

