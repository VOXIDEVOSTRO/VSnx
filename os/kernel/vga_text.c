#include "include.h"

// VGA entry creation
unsigned short make_vga_entry(char c, unsigned char color) {
    return (unsigned short)c | ((unsigned short)color << 8);
}

// Safe VGA write function
void vga_write_safe(int x, int y, char c, unsigned char color) {
    if (x >= 0 && x < VGA_WIDTH && y >= 0 && y < VGA_HEIGHT) {
        int pos = y * VGA_WIDTH + x;
        if (pos >= 0 && pos < (VGA_WIDTH * VGA_HEIGHT)) {
            VGA_BUFFER[pos] = make_vga_entry(c, color);
        }
    }
}

void clear_screen (void) {
    // Reset cursor first
    cursor_x = 0;
    cursor_y = 0;
    
    // Clear entire screen with white text on black background
    for (int i = 0; i < 2000; i++) { // 80*25 = 2000
        VGA_BUFFER[i] = make_vga_entry(' ', 0x07);
    }
}

// Screen scrolling when cursor exceeds line 25
void scroll_screen (void) {
    if (cursor_y >= VGA_HEIGHT) {
        // Move all lines up by one
        for (int line = 0; line < VGA_HEIGHT - 1; line++) {
            for (int col = 0; col < VGA_WIDTH; col++) {
                int dest = line * VGA_WIDTH + col;
                int src = (line + 1) * VGA_WIDTH + col;
                VGA_BUFFER[dest] = VGA_BUFFER[src];
            }
        }
        
        // Clear the last line
        for (int col = 0; col < VGA_WIDTH; col++) {
            int index = (VGA_HEIGHT - 1) * VGA_WIDTH + col;
            VGA_BUFFER[index] = make_vga_entry(' ', 0x07);
        }
        
        cursor_y = VGA_HEIGHT - 1;
    }
}

// Updated print function with scrolling
void print(const char* str) {
    if (!str) return;

    for (int i = 0; str[i] != '\0' && i < 1000; i++) {
        char c = str[i];

        if (c == '\n') {
            cursor_x = 0;
            cursor_y++;
            scroll_screen();
        } else if (c == '\b') {
            // Move cursor back and erase previous character
            if (cursor_x > 0) {
                cursor_x--;
            } else if (cursor_y > 0) {
                cursor_y--;
                cursor_x = VGA_WIDTH - 1;
            }
            int pos = cursor_y * VGA_WIDTH + cursor_x;
            if (pos >= 0 && pos < VGA_WIDTH * VGA_HEIGHT) {
                VGA_BUFFER[pos] = make_vga_entry(' ', 0x07); // Overwrite with space
            }
        } else if (c >= 32 && c <= 126) {
            if (cursor_x >= 0 && cursor_x < VGA_WIDTH && cursor_y >= 0 && cursor_y < VGA_HEIGHT) {
                int pos = cursor_y * VGA_WIDTH + cursor_x;
                if (pos >= 0 && pos < VGA_WIDTH * VGA_HEIGHT) {
                    VGA_BUFFER[pos] = make_vga_entry(c, 0x07);
                    cursor_x++;
                }
            }
        }

        if (cursor_x >= VGA_WIDTH) {
            cursor_x = 0;
            cursor_y++;
            scroll_screen();
        }
    }
    // Add serial output
    serial_write(str);
}

void println(const char* str) {
    print(str);
    cursor_x = 0;
    cursor_y++;
    scroll_screen(); // Add scrolling check
    serial_putchar('\r');
    serial_putchar('\n');
}
