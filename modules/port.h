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
