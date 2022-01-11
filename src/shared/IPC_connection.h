#pragma once
#include <stdint.h>

typedef enum {
    IPC_ERR_OK = 0,
    IPC_ERR_NO_SOCKET = -1,
    IPC_ERR_BIND_FAIL = -2,
    IPC_ERR_LISTEN_FAIL = -3,
    IPC_ERR_MAX_SND_SIZE_FAIL = -4,
    IPC_ERR_MAX_REC_SIZE_FAIL = -5,
    IPC_ERR_PERMISSION_FAIL = -6,
    IPC_ERR_THREAD = -7,
    IPC_ERR_READER_THREAD = -8,
    IPC_ERR_WRITTER_THREAD = -9,
    IPC_ERR_FAIL_SERVER_CON = -10,
} IPC_RET_CODES;

typedef struct {
    char *socket_path;
    uint32_t max_queued_connections;
    uint32_t permissions;
    uint32_t is_server;
} IPC_config_t;

#define INTERNAL_MESSAGE_SIZE 24
typedef union {
    struct {
        void *data;
        uint32_t size;
        int32_t sender;
    };
    char __[INTERNAL_MESSAGE_SIZE];
} message_t;

#define INVALID_MSG_ID UINT32_MAX

#define IPC_prepare_response_msg(request, data_ptr, s) \
    free(request.data);                                \
    request.data = data_ptr;                           \
    request.size = (s);

#define IPC_cancel_response(request) \
    free(request.data);              \
    request.data = 0;                \
    request.size = 0;

#define IPC_create_request(d, s) \
    { .data = d, .size = s }

//void *mempcpy(void *restrict dest, const void *restrict src, uint64_t n);
//void *malloc(uint64_t size);
//// Sadly this can't be a macro, so hopefully it always gets inlined
//static message_t IPC_create_request_from_copy(void *d, uint32_t s) {
//    message_t m = {.data = malloc(s), .size = s};
//    mempcpy(m.data, d, s);
//    return m;
//}

typedef struct _IPC_connection *IPC_connection;

IPC_connection IPC_initialize(IPC_config_t const *cfg);
void IPC_shutdown(IPC_connection *connection);
int IPC_is_connection_valid(const IPC_connection connection);
void IPC_print_error(const IPC_connection connection);
IPC_RET_CODES IPC_start_server(IPC_connection connection, int max_supported_clients);
IPC_RET_CODES IPC_start_client(IPC_connection connection);

// This will wait for a max of timeout us for a response matching the request_id provided.
// Clients have to use this function to get the specific reponse to the requests sent to the server
// The caller will own the message memory so is responsible of cleaning it up
message_t IPC_pop_response(IPC_connection connection, uint32_t request_id, int timeout /*in us*/);

// This will pop a FIFO request from the in_queue. Only a server can call this function.
// The caller will own the message memory so is responsible of cleaning it up
message_t IPC_pop_request(IPC_connection connection);

// The function will own the message memory so the data will be freed after the message is sent
uint32_t IPC_push_message(IPC_connection connection, message_t message);
