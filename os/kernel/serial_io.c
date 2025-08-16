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
  SERIAL PORT IMPLEMENTATION - MIRROR VGA OUTPUT
================================================================================================================*/

// Initialize serial port
void serial_init (void) {
    // Disable interrupts
    outb(SERIAL_PORT_COM1 + 1, 0x00);
    
    // Set baud rate divisor (115200 baud)
    outb(SERIAL_PORT_COM1 + 3, 0x80);  // Enable DLAB
    outb(SERIAL_PORT_COM1 + 0, 0x01);  // Divisor low byte
    outb(SERIAL_PORT_COM1 + 1, 0x00);  // Divisor high byte
    
    // Configure line: 8 bits, no parity, 1 stop bit
    outb(SERIAL_PORT_COM1 + 3, 0x03);
    
    // Enable FIFO, clear buffers, 14-byte threshold
    outb(SERIAL_PORT_COM1 + 2, 0xC7);
    
    // Enable auxiliary output 2, request to send, data terminal ready
    outb(SERIAL_PORT_COM1 + 4, 0x0B);
    
    // Test serial chip
    outb(SERIAL_PORT_COM1 + 4, 0x1E);
    outb(SERIAL_PORT_COM1 + 0, 0xAE);
    
    if (inb(SERIAL_PORT_COM1 + 0) != 0xAE) {
        return;
    }
    
    // Set normal operation mode
    outb(SERIAL_PORT_COM1 + 4, 0x0F);
}

// Check if transmit buffer is empty
int serial_transmit_empty (void) {
    return inb(SERIAL_PORT_COM1 + 5) & 0x20;
}

// Send a character to serial port
void serial_putchar(char c) {
    while (!serial_transmit_empty());
    outb(SERIAL_PORT_COM1, c);
}

// Send a string to serial port
void serial_write(const char* str) {
    while (*str) {
        serial_putchar(*str);
        str++;
    }
}

// Send a string with newline to serial port
void serial_println(const char* str) {
    serial_write(str);
    serial_putchar('\r');
    serial_putchar('\n');
}

// Print hex value to serial
void serial_print_hex(uint64_t value) {
    char hex_str[20];
    uint64_to_hex(value, hex_str);
    serial_write("0x");
    serial_write(hex_str);
}

// Print integer to serial
void serial_print_int(uint64_t value) {
    char int_str[20];
    int pos = 0;
    
    if (value == 0) {
        int_str[pos++] = '0';
    } else {
        char temp[20];
        int temp_pos = 0;
        while (value > 0) {
            temp[temp_pos++] = '0' + (value % 10);
            value /= 10;
        }
        for (int i = temp_pos - 1; i >= 0; i--) {
            int_str[pos++] = temp[i];
        }
    }
    int_str[pos] = '\0';
    
    serial_write(int_str);
}

// Copy entire VGA buffer to serial port
void serial_dump_vga_buffer (void) {
    uint16_t* vga_buffer = (uint16_t*)VGA_BUFFER_ADDR;
    
    serial_println("=== VGA BUFFER DUMP ===");
    
    for (int y = 0; y < VGA_HEIGHT; y++) {
        char line[VGA_WIDTH + 1];
        int line_pos = 0;
        
        for (int x = 0; x < VGA_WIDTH; x++) {
            uint16_t vga_entry = vga_buffer[y * VGA_WIDTH + x];
            char character = vga_entry & 0xFF;
            
            // Replace non-printable characters with spaces
            if (character < 32 || character > 126) {
                character = ' ';
            }
            
            line[line_pos++] = character;
        }
        
        // Remove trailing spaces
        while (line_pos > 0 && line[line_pos - 1] == ' ') {
            line_pos--;
        }
        
        line[line_pos] = '\0';
        
        // Only send non-empty lines
        if (line_pos > 0) {
            char line_header[10];
            line_header[0] = '0' + (y / 10);
            line_header[1] = '0' + (y % 10);
            line_header[2] = ':';
            line_header[3] = ' ';
            line_header[4] = '\0';
            
            serial_write(line_header);
            serial_println(line);
        }
    }
    
    serial_println("=== END VGA BUFFER DUMP ===");

}
