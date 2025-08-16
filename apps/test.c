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

// test.c - Modified for context switching test
#include <stdint.h>
#include <stddef.h>
#include "../os/kernel/syscall.h"
void _start() {
    
    sys_call_function("Mouse API Test Started!", 0, 0, 0, 0, 0);
    
    while (1) {
        // Test left click
        sys_declare_function("SYSTEM", "get_left_click", 0);
        int left_click = sys_call_function(0, 0, 0, 0, 0, 0);
        if (left_click) {
            sys_declare_function("SYSTEM", "println", 1);
            sys_call_function("LEFT CLICK DETECTED!", 0, 0, 0, 0, 0);
        }
        
        // Test right click
        sys_declare_function("SYSTEM", "get_right_click", 0);
        int right_click = sys_call_function(0, 0, 0, 0, 0, 0);
        if (right_click) {
            sys_declare_function("SYSTEM", "println", 1);
            sys_call_function("RIGHT CLICK DETECTED!", 0, 0, 0, 0, 0);
        }
        
        // Test middle click
        sys_declare_function("SYSTEM", "get_middle_click", 0);
        int middle_click = sys_call_function(0, 0, 0, 0, 0, 0);
        if (middle_click) {
            sys_declare_function("SYSTEM", "println", 1);
            sys_call_function("MIDDLE CLICK DETECTED!", 0, 0, 0, 0, 0);
        }
        
        // Test scroll
        sys_declare_function("SYSTEM", "get_scroll", 0);
        int scroll = sys_call_function(0, 0, 0, 0, 0, 0);
        if (scroll > 0) {
            sys_declare_function("SYSTEM", "println", 1);
            sys_call_function("SCROLL UP!", 0, 0, 0, 0, 0);
        } else if (scroll < 0) {
            sys_declare_function("SYSTEM", "println", 1);
            sys_call_function("SCROLL DOWN!", 0, 0, 0, 0, 0);
        }
        
        // Small delay
        for (volatile int i = 0; i < 100000; i++);
    }
}

void uint64_to_hex(uint64_t value, char* buffer) {
    const char hex_chars[] = "0123456789ABCDEF";
    buffer[0] = '0';
    buffer[1] = 'x';
    
    for (int i = 15; i >= 0; i--) {
        buffer[2 + (15 - i)] = hex_chars[(value >> (i * 4)) & 0xF];
    }
    buffer[18] = '\0';
}


char* itoa(int value, char* str, int base) {
    char* ptr = str;
    char* ptr1 = str;
    char tmp_char;
    int tmp_value;

    // Handle base limits
    if (base < 2 || base > 36) {
        *str = '\0';
        return str;
    }

    // Handle negative numbers in base 10 only
    if (value < 0 && base == 10) {
        *ptr++ = '-';
        value = -value;
        ptr1 = ptr; // move ptr1 past the minus sign
    }

    // Convert value to string
    do {
        tmp_value = value;
        value /= base;
        *ptr++ = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[tmp_value - value * base];
    } while (value);

    *ptr = '\0';

    // Reverse string
    while (--ptr > ptr1) {
        tmp_char = *ptr;
        *ptr = *ptr1;
        *ptr1 = tmp_char;
        ++ptr1;
    }

    return str;
}

char* strncpy(char* dest, const char* src, size_t n) {
    size_t i;
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0';
    }
    return dest;
}

size_t strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

// Simple string compare
int strcmp(const char* a, const char* b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return *a - *b;
}

char* strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;

}
