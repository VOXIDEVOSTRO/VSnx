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

// port.h - Mailbox communication structures
#ifndef PORT_H
#define PORT_H

#include <stdint.h>
#include <stddef.h>

#define PORT_MAGIC 0xDEADC0DE
#define MAX_PORT_NAME 32
#define MAX_PORT_DATA 256
#define PORT_STATUS_EMPTY 0
#define PORT_STATUS_REQUEST 1
#define PORT_STATUS_RESPONSE 2
#define PORT_STATUS_ERROR 3

typedef struct {
    uint32_t magic;
    char port_name[32];
    uint32_t status;
    uint32_t request_id;
    uint32_t data_size;
    uint8_t data[256];
    uint8_t result[64];
    uint32_t timestamp;
	uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
	uint32_t caller_id;
    uint32_t notification_flag;  // ADD AT THE END to avoid breaking existing code
} port_message_t;

#endif

