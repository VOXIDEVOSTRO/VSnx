// test.c - Module using mailbox communication
#include "port.h"

// Module's own functions
int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    int result = 0;
    for (int i = 0; i < b; i++) {
        result += a;
    }
    return result;
}

// Function that uses mailbox to call test2's multiply
int multiply_using_mailbox(int a, int b) {
    // Call test2's multiply function via mailbox
    call_port("test2_multiply", a, b);
}

// Function that uses mailbox to call test2's subtract
int subtract_using_mailbox(int a, int b) {
    // Call test2's subtract function via mailbox
    call_port("test2_subtract", a, b);
}
