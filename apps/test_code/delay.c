// delay.c - Simple delay app for testing context switching
#include "port.h"

void _start() {
    printf("DELAY_APP: Starting delay application!\n");
    printf("DELAY_APP: This is thread ID 1\n");

    while (1) {
        for (volatile int i = 0; i < 1000000; i++) {
            __asm__ volatile("nop");
        }
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