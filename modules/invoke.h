#ifndef INVOKE_H
#define INVOKE_H

// Inter-module communication syscall - kernel acts as middleman
#define invoke(target_app, func_name, args, args_size) ({ \
    volatile port_message_t* _port = (volatile port_message_t*)SYSCALL_PORT_ADDR; \
    int _result = -1; \
    if (_port->magic == PORT_MAGIC) { \
        while (_port->status != 0) {} \
        strcpy((char*)_port->data, "call_module"); \
        strcpy((char*)_port->data + 32, target_app); \
        strcpy((char*)_port->data + 96, func_name); \
        if (args && args_size > 0) { \
            for (int i = 0; i < args_size && i < 64; i++) { \
                ((char*)_port->data)[160 + i] = ((char*)args)[i]; \
            } \
        } \
        *((size_t*)&_port->data[224]) = args_size; \
        _port->status = 1; _port->request_id++; _port->data_size = 240; \
        __asm__ volatile("int $0x69" : : : "memory"); \
        /* Do not wait for response, return immediately */ \
        _result = 0; \
        _port->status = 0; \
    } \
    _result; \
})

#endif // INVOKE_H