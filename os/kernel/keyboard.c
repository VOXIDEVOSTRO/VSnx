#include "include.h"

/*==============================================================================================================
  KEYBOARD
================================================================================================================*/
// Example scancode to ASCII (US QWERTY, add more as needed)
char scancode_to_ascii(uint8_t scancode) {
    static const char scancode_table[128] = {
        0, 27, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b', // 0x0E = Backspace
        '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n', 0, // 0x1C = Enter
        'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\',
        'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0, '*', 0, ' ', 0,
        // ... fill out as needed ...
    };
    if (scancode < 128)
        return scancode_table[scancode];
    return 0;
}

int kernel_getchar(void) {
    if (keyboard_buffer_head == keyboard_buffer_tail) {
        return -1; // No input available
    }
    char c = keyboard_buffer[keyboard_buffer_tail];
    keyboard_buffer_tail = (keyboard_buffer_tail + 1) % KEYBOARD_BUFFER_SIZE;
    return (int)c;
}
