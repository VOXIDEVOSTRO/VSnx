#include "include.h"

/*==============================================================================================================
  MEMORY AND UTILITY FUNCTIONS
================================================================================================================*/
// Time functions required by FAT32 driver
time_t time(time_t *t) {
    // Simple time implementation - return a fixed value for now
    time_t current_time = 1000000; // Some arbitrary time
    if (t) *t = current_time;
    return current_time;
}

struct tm* gmtime(const time_t *timep) {
    static struct tm tm_result;
    // Simple implementation - return a fixed date/time
    tm_result.tm_sec = 0;
    tm_result.tm_min = 0;
    tm_result.tm_hour = 12;
    tm_result.tm_mday = 1;
    tm_result.tm_mon = 0;  // January
    tm_result.tm_year = 120; // 2020
    tm_result.tm_wday = 0;
    tm_result.tm_yday = 0;
    tm_result.tm_isdst = 0;
    return &tm_result;
}

time_t mktime(struct tm *tm) {
    // Simple implementation - return a fixed time
    return 1000000;
}

// String functions required by FAT32 driver
size_t strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

char* strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

int strncmp(const char *s1, const char *s2, size_t n) {
    while (n && *s1 && (*s1 == *s2)) {
        s1++;
        s2++;
        n--;
    }
    if (n == 0) return 0;
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

char* strtok(char *str, const char *delim) {
    static char *last = NULL;
    if (str) last = str;
    if (!last) return NULL;
    
    // Skip leading delimiters
    while (*last && *last == *delim) last++;
    if (!*last) return NULL;
    
    char *start = last;
    // Find end of token
    while (*last && *last != *delim) last++;
    if (*last) *last++ = '\0';
    
    return start;
}

char* strstr(const char *haystack, const char *needle) {
    if (!*needle) return (char*)haystack;
    
    while (*haystack) {
        const char *h = haystack;
        const char *n = needle;
        while (*h && *n && (*h == *n)) {
            h++;
            n++;
        }
        if (!*n) return (char*)haystack;
        haystack++;
    }
    return NULL;
}

// FIXED: memset for paged disk buffers
void* memset(void* s, int c, size_t n) {
    if (!s || n == 0) {
        return s;
    }
    
    uint64_t start_addr = (uint64_t)s;
    uint8_t* p = (uint8_t*)s;
    uint8_t value = (uint8_t)c;
    
    // Check if we're in a recursive call
    if (memory_operation_in_progress) {
        for (size_t i = 0; i < n; i++) {
            p[i] = value;
        }
        return s;
    }
    
    // Handle paging heap memory
    if (start_addr >= paging_heap_start && start_addr < paging_heap_end) {
        for (size_t i = 0; i < n; i++) {
            p[i] = value;
        }
        return s;
    }
    
    // Handle other kernel memory
    if (start_addr < 0x20000000) {
        for (size_t i = 0; i < n; i++) {
            p[i] = value;
        }
        return s;
    }
    
    return s;
}

// CRITICAL FIX: memcpy must ONLY work on already mapped memory
void* memcpy(void* dest, const void* src, size_t n) {
    if (!dest || !src || n == 0) {
        return dest;
    }
    
    uint64_t dest_addr = (uint64_t)dest;
    uint64_t src_addr = (uint64_t)src;
    
    // CRITICAL: Only work on memory that should already be mapped
    if (dest_addr < 0x100000 || src_addr < 0x100000) {
        // Below 1MB - dangerous, don't touch
        return dest;
    }
    
    // Check if we're already in a memory operation to prevent recursion
    if (memory_operation_in_progress) {
        // Direct operation without additional checks
        uint8_t* d = (uint8_t*)dest;
        const uint8_t* s = (const uint8_t*)src;
        for (size_t i = 0; i < n; i++) {
            d[i] = s[i];
        }
        return dest;
    }
    
    // Only work on known mapped regions
    if ((dest_addr < 0x20000000 && src_addr < 0x20000000)) {
        uint8_t* d = (uint8_t*)dest;
        const uint8_t* s = (const uint8_t*)src;
        for (size_t i = 0; i < n; i++) {
            d[i] = s[i];
        }
        return dest;
    }
    
    // Unknown memory regions - don't touch
    return dest;
}

// Security check functions required by GCC's stack protection
void* __memcpy_chk(void* dest, const void* src, size_t len, size_t destlen) {
    // Simple implementation - just call memcpy
    return memcpy(dest, src, len);
}

char* __strcpy_chk(char* dest, const char* src, size_t destlen) {
    // Simple implementation - just call strcpy
    return strcpy(dest, src);
}

int __printf_chk(int flag, const char* format, ...) {
    // Simple printf implementation for debugging
    // For now, just return 0 to avoid crashes
    return 0;
}

int printf(const char* format, ...) {
    // Simple printf implementation - for now just return 0
    // The FAT32 driver uses printf for debugging but we can ignore it
    return 0;
}

// Additional string functions that might be needed
char* __strcat_chk(char* dest, const char* src, size_t destlen) {
    // Find end of dest
    char* d = dest;
    while (*d) d++;
    
    // Copy src to end of dest
    while ((*d++ = *src++));
    
    return dest;
}

// Converts integer 'value' to null-terminated string stored in 'str' with given 'base'
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

void* __memmove_chk(void* dest, const void* src, size_t len, size_t destlen) {
    // Simple memmove implementation
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    
    if (d < s) {
        // Copy forward
        for (size_t i = 0; i < len; i++) {
            d[i] = s[i];
        }
    } else {
        // Copy backward
        for (size_t i = len; i > 0; i--) {
            d[i-1] = s[i-1];
        }
    }
    
    return dest;
}

void* __memset_chk(void* s, int c, size_t len, size_t slen) {
    return memset(s, c, len);
}

// Stack protection functions
void __stack_chk_fail(void) {
    // Stack overflow detected - halt the system
    println("Stack overflow detected!");
    while (1) {
        __asm__ volatile("hlt");
    }
}

// Additional time functions that might be needed
int gettimeofday(struct timeval* tv, struct timezone* tz) {
    // Simple implementation
    if (tv) {
        tv->tv_sec = 1000000;
        tv->tv_usec = 0;
    }
    return 0;
}

// Additional memory functions
void* memmove(void* dest, const void* src, size_t n) {
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    
    if (d < s) {
        // Copy forward
        for (size_t i = 0; i < n; i++) {
            d[i] = s[i];
        }
    } else {
        // Copy backward
        for (size_t i = n; i > 0; i--) {
            d[i-1] = s[i-1];
        }
    }
    
    return dest;
}

int memcmp(const void* s1, const void* s2, size_t n) {
    const uint8_t* p1 = (const uint8_t*)s1;
    const uint8_t* p2 = (const uint8_t*)s2;
    
    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }
    return 0;
}

// Additional string functions
char* strcat(char* dest, const char* src) {
    char* d = dest;
    while (*d) d++;
    while ((*d++ = *src++));
    return dest;
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

// Error handling functions
void abort(void) {
    println("Abort called!");
    while (1) {
        __asm__ volatile("hlt");
    }
}

void exit(int status) {
    println("Exit called!");
    while (1) {
        __asm__ volatile("hlt");
    }
}

// Helper function for hex conversion
void uint64_to_hex(uint64_t value, char* str) {
    int pos = 0;
    if (value == 0) {
        str[pos++] = '0';
    } else {
        char temp[20];
        int temp_pos = 0;
        while (value > 0) {
            uint8_t digit = value % 16;
            temp[temp_pos++] = (digit < 10) ? ('0' + digit) : ('A' + digit - 10);
            value /= 16;
        }
        for (int i = temp_pos - 1; i >= 0; i--) {
            str[pos++] = temp[i];
        }
    }
    str[pos] = '\0';
}



// Helper function to print decimal numbers
void print_decimal(uint64_t num) {
    if (num == 0) {
        print("0");
        return;
    }
    
    char digits[32];
    int pos = 0;
    
    while (num > 0) {
        digits[pos++] = '0' + (num % 10);
        num /= 10;
    }
    
    // Print in reverse order
    for (int i = pos - 1; i >= 0; i--) {
        char digit_str[2];
        digit_str[0] = digits[i];
        digit_str[1] = '\0';
        print(digit_str);
    }
}

// Helper function to print signed decimal numbers
void print_signed_decimal(int64_t num) {
    if (num < 0) {
        print("-");
        print_decimal((uint64_t)(-num));
    } else {
        print_decimal((uint64_t)num);
    }
}

// Get current stack pointer
uint64_t get_stack_pointer (void) {
    uint64_t rsp;
    __asm__ volatile("movq %%rsp, %0" : "=r"(rsp));
    return rsp;
}

// Get current base pointer
uint64_t get_base_pointer (void) {
    uint64_t rbp;
    __asm__ volatile("movq %%rbp, %0" : "=r"(rbp));
    return rbp;
}

// Register app's port processor with interrupt system
void register_port_processor(const char* app_name, void (*processor_func)(void)) {
    if (processor_count < 16) {
        strcpy(port_processors[processor_count].app_name, app_name);
        port_processors[processor_count].port_processor = processor_func;
        port_processors[processor_count].active = 1;
        
        print("IRQ_REGISTRY: Registered port processor for ");
        println(app_name);
        
        processor_count++;
    }
}

// Kernel validates and copies user memory
int copy_string_from_user(uint64_t user_ptr, char* kernel_buf, size_t max_len) {
    println("DEBUG: copy_string_from_user called");
    
    // Validate user pointer is in valid range
    if (user_ptr < 0x20000000 || user_ptr >= 0x40000000) {
        println("DEBUG: user_ptr out of range");
        return -1;
    }
    
    println("DEBUG: user_ptr in valid range");
    
    const char* user_str = (const char*)user_ptr;
    for (size_t i = 0; i < max_len - 1; i++) {
        kernel_buf[i] = user_str[i];
        if (kernel_buf[i] == '\0') {
            println("DEBUG: found null terminator");
            return 0;
        }
    }
    kernel_buf[max_len - 1] = '\0';
    println("DEBUG: reached max_len");
    return 0;
}

// Helper: convert a single digit to hex char
char hex_digit(unsigned char val) {
	return val < 10 ? '0' + val : 'a' + (val - 10);
}

// Helper: convert byte to 2-digit hex
void byte_to_hex(uint8_t byte, char* out) {
	out[0] = hex_digit((byte >> 4) & 0xF);
	out[1] = hex_digit(byte & 0xF);
	out[2] = ' ';
}

// Helper: convert offset to 8-digit hex
void offset_to_hex(size_t offset, char* out) {
	for (int i = 7; i >= 0; i--) {
		out[i] = hex_digit(offset & 0xF);
		offset >>= 4;
	}
	out[8] = ':';
	out[9] = ' ';
}
