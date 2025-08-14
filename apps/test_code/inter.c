#include "../os/kernel/syscall.h"
#include <stdint.h>
#include <stddef.h>

// Add this to the beginning of inter.c _start() function
void _start() {
    
	int loop_count = 0;
    while(1) {
        __asm__ volatile("nop");
    }
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

// Encodes up to 8 characters into a single 64-bit integer
uint64_t str_int(const char* str) {
    uint64_t glyph = 0;
    for (int i = 0; str[i] && i < 8; i++) {
        glyph |= ((uint64_t)(uint8_t)str[i]) << (8 * i);
    }
    return glyph;
}

void print_banner() {

}