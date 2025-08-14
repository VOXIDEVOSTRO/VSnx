#include "port.h"

void _start() {

    printf("VOSTROX TTY: Welcome!\n");
    printf("Type a command like: $ fat fs_ls /MODULES/SYS/\n");


    while (1) {
		__asm__ volatile("nop");
    }
}

size_t strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

// Parse: "%d %d %c %x"
int sscanf(const char* str, int* x, int* y, char* c, int* color) {
    // Skip leading whitespace
    while (*str == ' ') str++;
    int n = 0;
    int consumed;
    if (sscanf_int(str, x, &consumed)) {
        n++; str += consumed;
        while (*str == ' ') str++;
        if (sscanf_int(str, y, &consumed)) {
            n++; str += consumed;
            while (*str == ' ') str++;
            if (*str) {
                *c = *str; n++; str++;
                while (*str == ' ') str++;
                if (sscanf_hex(str, color, &consumed)) {
                    n++; // All four parsed
                }
            }
        }
    }
    return n;
}

// Helper: parse decimal int
int sscanf_int(const char* str, int* out, int* consumed) {
    int v = 0, sign = 1, i = 0;
    if (str[0] == '-') { sign = -1; i++; }
    int found = 0;
    while (str[i] >= '0' && str[i] <= '9') {
        v = v * 10 + (str[i] - '0');
        i++; found = 1;
    }
    if (found) { *out = v * sign; *consumed = i; return 1; }
    return 0;
}

// Helper: parse hex int (e.g., 0x1F or 1F)
int sscanf_hex(const char* str, int* out, int* consumed) {
    int v = 0, i = 0;
    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) i += 2;
    int found = 0;
    while ((str[i] >= '0' && str[i] <= '9') ||
           (str[i] >= 'a' && str[i] <= 'f') ||
           (str[i] >= 'A' && str[i] <= 'F')) {
        v *= 16;
        if (str[i] >= '0' && str[i] <= '9') v += str[i] - '0';
        else if (str[i] >= 'a' && str[i] <= 'f') v += str[i] - 'a' + 10;
        else if (str[i] >= 'A' && str[i] <= 'F') v += str[i] - 'A' + 10;
        i++; found = 1;
    }
    if (found) { *out = v; *consumed = i; return 1; }
    return 0;
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

int parse_two_strings(const char* src, char* out1, int max1, char* out2, int max2) {
    int i = 0, j = 0;
    // Skip leading spaces
    while (src[i] == ' ') i++;
    // Copy first string
    while (src[i] && src[i] != ' ' && j < max1 - 1) out1[j++] = src[i++];
    out1[j] = '\0';
    // Skip spaces
    while (src[i] == ' ') i++;
    j = 0;
    // Copy second string
    while (src[i] && src[i] != ' ' && j < max2 - 1) out2[j++] = src[i++];
    out2[j] = '\0';
    // Return 2 if both are non-empty
    return (out1[0] && out2[0]) ? 2 : 0;
}

char* strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

// Simple atoi
int atoi(const char* s) {
    int v = 0, sign = 1;
    if (*s == '-') { sign = -1; s++; }
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        s++;
    }
    return v * sign;
}