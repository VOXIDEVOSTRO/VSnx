// port.h - Mailbox communication structures
#ifndef PORT_H
#define PORT_H

#include <stdint.h>

#define PORT_MAGIC 0xDEADC0DE
#define MAX_PORT_NAME 32
#define MAX_PORT_DATA 256
#define PORT_STATUS_EMPTY 0
#define PORT_STATUS_REQUEST 1
#define PORT_STATUS_RESPONSE 2
#define PORT_STATUS_ERROR 3

typedef struct {
    uint32_t magic;
    char port_name[MAX_PORT_NAME];
    uint32_t status;
    uint32_t request_id;
    uint32_t data_size;
    uint8_t data[MAX_PORT_DATA];
    uint64_t timestamp;
} port_message_t;

#endif
