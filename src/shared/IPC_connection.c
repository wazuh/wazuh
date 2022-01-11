#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(OPENBSD) || defined(FREEBSD) || defined(DRAGONFLY)
#include <pthread_np.h>
#endif

#include "IPC_connection.h"

#include "my_assert.h"
#include "serialization_util.h"
#include "crc32.h"

#define KB(n) ((uint64_t)n * 1024LL)
#define MB(n) (KB(n) * 1024LL)

// Internal configs
#define MAX_DATA_SIZE (MB(5))
#define MAX_MESSAGE_FRAME_SIZE UINT16_MAX
#define MAX_HEADER_SIZE 32
#define MAX_BACKOFF_SLEEP 64
// Ammount of seconds that the read thread can be blocked waiting for data from a client
// consider making this a configurable value in the cfg
#define READ_TIMEOUT 5
// Ammount of seconds that the write thread can be blocked waiting for a client to be ready to write to
// consider making this a configurable value in the cfg
#define WRITE_TIMEOUT 5

typedef struct incomming_message {
    uint32_t total_size;
    uint32_t received;
    void *buffer;
    struct incomming_message *next;
    int32_t sender;
    uint32_t msg_id;
} msg_in_progress_t;

// Its important to have the same member order
// in message_t and internal_message
typedef union {
    message_t m;
    struct {
        void *data;
        uint32_t size;
        int32_t sender;
        uint32_t msg_id;
        char __pad[4];
    };
} internal_message_t;

// If the assertion fails it means that the internal message struct has changed and you need
// to update the INTERNAL_MESSAGE_SIZE macro to reflect the new size
STATIC_ASSERT(INTERNAL_MESSAGE_SIZE == sizeof(internal_message_t));

typedef struct complete_message {
    struct complete_message *next;
    internal_message_t msg;
} imessage_queue_t;

struct _IPC_connection {
    IPC_config_t cfg;
    int32_t socket;
    int32_t err_code;

    uint32_t current_msg_id;
    uint32_t is_connected; // For clients this mark if there's an active server connection

    const char *msg;

    imessage_queue_t *in_queue;
    imessage_queue_t *out_queue;

    msg_in_progress_t *incomming_queue;

    pthread_mutex_t get_message_mtx;
    pthread_mutex_t send_message_mtx;
    pthread_cond_t in_queue_updated_cond;
    pthread_cond_t out_queue_updated_cond;

    pthread_t reader_thread;
    pthread_t writter_thread;

    uint32_t max_msg_size;
};

static int set_socket_size(int socket, uint32_t *max_size, int buff_type) {
    socklen_t optlen = sizeof(uint32_t);
    uint32_t current_size = 0;

    if (getsockopt(socket, SOL_SOCKET, buff_type, (void *)&current_size, &optlen) == -1) {
        current_size = 0;
    }

    if (current_size < *max_size) {
        if (setsockopt(socket, SOL_SOCKET, SO_RCVBUF, (const void *)max_size, optlen) < 0) {
            return -1;
        }
    }

    if (getsockopt(socket, SOL_SOCKET, buff_type, &current_size, &optlen) == -1) {
        if (current_size != *max_size) {
            fprintf(stderr, "Could not set max buffer size. Wanted [%d] got [%d]\n", *max_size, current_size);
            *max_size = current_size;
        }
        return -1;
    }

    return 0;
}

typedef enum {
    MSG_CONT = 0,
    MSG_INITIAL = 1,
} MSG_TYPE;

struct first_byte_info {
    uint8_t msg_type : 2;
    uint8_t header_size : 5;
    uint8_t fin : 1;
};

static void *start_write_loop(void *args) {
    char *header_buffer[MAX_HEADER_SIZE] = {0};

    while (1) {
        IPC_connection connection = (IPC_connection)args;
        const uint32_t MAX_MSG_SIZE = connection->max_msg_size;

        pthread_mutex_lock(&connection->send_message_mtx);
        int ret = 0;
        while ((connection->out_queue == 0) || (connection->is_connected == 0)) {
            pthread_cond_wait(&connection->out_queue_updated_cond, &connection->send_message_mtx);
        }

        imessage_queue_t *tmp = connection->out_queue;
        connection->out_queue = connection->out_queue->next;

        pthread_mutex_unlock(&connection->send_message_mtx);

        uint32_t done = 0;
        uint32_t initial_frame = 1;
        uint32_t data_bytes_sent = 0;
        internal_message_t msg = tmp->msg;

        struct pollfd pfd[1];
        pfd[0].fd = msg.sender;
        pfd[0].events = POLLOUT;

        while (!done) {
            int event = poll(pfd, 1, WRITE_TIMEOUT * 1000);

            if (event == 0) {
                fprintf(stderr, "(IPC) Timeout waiting for the sender to become writeable.\n");
                // TODO(santi) what do we do here? For now we drop the message;
                break;
            }
            else if ((event < 0) && (errno != EINTR)) {
                fprintf(stderr, "(IPC) Errror while waiting for IPC event: %s\n", strerror(errno));
                continue;
            }
            else if (pfd[0].revents == 0) {
                fprintf(stderr, "(IPC) Errror while waiting for IPC event: %s\n", strerror(errno));
                continue;
            }

            if ((pfd->revents & POLLHUP) || (pfd->revents & POLLERR)) {
                fprintf(stderr, "(IPC) Sender disconnected. Dropping the rest of the message...\n");
                break;
            }
            else if (pfd->revents & POLLOUT) {
                header_buffer[0] = 0;
                uint8_t *data = (uint8_t *)header_buffer;

                uint32_t *header_crc = (uint32_t *)data;
                data += sizeof(*header_crc);

                struct first_byte_info *header = (struct first_byte_info *)data;
                data += sizeof(*header);

                uint16_t *msg_size = (uint16_t *)data;
                data += sizeof(*msg_size);

                if (initial_frame) {
                    initial_frame = 0;
                    header->msg_type = MSG_INITIAL;
                    serialize_unsigned(&data, msg.msg_id);
                    serialize_unsigned(&data, msg.size);
                }
                else {
                    header->msg_type = MSG_CONT;
                }

                uint8_t header_size = data - (uint8_t *)header_buffer;
                header->header_size = header_size;

                uint32_t max_data_size = MAX_MSG_SIZE - header_size;
                uint32_t left_data = msg.size - data_bytes_sent;

                uint32_t data_size = 0;
                if (max_data_size < left_data) {
                    data_size = max_data_size;
                }
                else {
                    data_size = left_data;
                    header->fin = 1;
                }

                uint32_t size_to_send = (data - (uint8_t *)header_buffer) + data_size;
                ASSERT(size_to_send <= UINT16_MAX);
                *msg_size = size_to_send;

                *header_crc = xcrc32((unsigned char *)header_buffer + 4, header_size - 4, 0);

                ret = send(msg.sender, header_buffer, header_size, 0);
                if (ret == -1 || errno != 0) {
                    fprintf(stderr, "(IPC) Error sending header [%d] [%s]\n", errno, strerror(errno));
                    // TODO(santi) what do we do here?
                    break;
                }

                ret = send(msg.sender, msg.data + data_bytes_sent, data_size, 0);

                if (ret == -1 || errno != 0) {
                    fprintf(stderr, "(IPC) Error sending data [%d] [%s]\n", errno, strerror(errno));
                    // TODO(santi) what do we do here?
                    break;
                }

                if (ret == data_size) {
                    data_bytes_sent += data_size;
                    if (data_bytes_sent == msg.size) {
                        done = 1;
                        continue;
                    }
                }
                else {
                    fprintf(stderr, "(IPC) Could not send the full data!\n");
                    // TODO(santi) what do we do here?
                    break;
                }
            }
        }

        free(msg.data);
        free(tmp);
    }
    return 0;
}

static void process_incomming_message(IPC_connection connection, uint32_t len, uint8_t *buffer, int sender) {
    ASSERT((len != 0) && (buffer != 0));

    // Putting the incomplete incomming messages is probably not the best
    // Consider making this a hash map of messages with the 'sender' as the index
    // We spect to have a low number of incomplete messages in this list so should not be
    //'super slow'

    // Taking the idea from the websocket data-frame we will parse the first byte as:
    //     - high byte will signal FIN of data (0/1)
    //     - next 4 are the header size
    //     - 2 lower bits are the 'type' of message
    //         -- 0 continuation
    //         -- 1 initial msg
    //
    // The initial message will have the message Id and the total size encoded next to the type as varints
    //    Initial msg:       [u8 type][uvint msgid][uvint totalsize][u32 data_size][data]
    //    Continuatuion msg: [u8 type][u32 data_size][data]
    //

    uint8_t *data = buffer;
    // skip the crc32 of the header stored a the start
    data += 4;

    struct first_byte_info info = *(struct first_byte_info *)data;
    data += sizeof(info);

    uint16_t msg_size = *(uint16_t *)data;
    data += sizeof(msg_size);

    msg_in_progress_t **msg = &connection->incomming_queue;
    while (*msg != 0 && (*msg)->sender != sender) { msg = &(*msg)->next; }

    if (info.msg_type == MSG_INITIAL) {
        if (*msg != 0) {
            ASSERT_MSG(0, "Got an 'initial' message but already have an incomming message in progress\n");

            fprintf(stderr,
                    "Got an 'initial' message but already have an incomming message in progress for [%d]\n",
                    sender);
        }
        else {
            uint32_t msg_id = deserialize_unsigned(&data);
            uint32_t total_message_len = deserialize_unsigned(&data);
            ASSERT_MSG(total_message_len < MAX_DATA_SIZE,
                       "The connetion does not allow messages larger than [%dMB]\n",
                       MAX_DATA_SIZE / (1024LL * 1024LL));

            if (total_message_len < MAX_DATA_SIZE) {
                *msg = (msg_in_progress_t *)calloc(1, sizeof(msg_in_progress_t));
                (*msg)->buffer = malloc(total_message_len);
                (*msg)->sender = sender;
                (*msg)->msg_id = msg_id;
                (*msg)->total_size = total_message_len;
                (*msg)->next = 0;
            }
            else if (connection->cfg.is_server) {
                // We are about to drop the rest of the msg_frames of the series so
                // we want to send an empty response in case the client is blocking on
                // and endless loop waiting for the response
                internal_message_t response = {.data = 0,
                                               .size = 0,
                                               .msg_id = (*msg)->msg_id,
                                               .sender = (*msg)->sender};
                IPC_push_message(connection, response.m);
            }
        }
    }

    uint32_t header_size = data - (uint8_t *)buffer;
    uint32_t packet_size = msg_size - header_size;

    // We either have a malformed msg or a malicious attacker trying to make us crash
    // by requesting too much memory.
    ASSERT(packet_size <= (*msg)->total_size);

    if (*msg == 0) {
        // A possible case for this is some one sending a message bigger than the maximum allowed
        // or we maybe got a packet_size larger than total_size so we want to drop the rest of the
        // frames
        fprintf(stderr,
                "Got a continuation message but we don't have a previous record of it.\nIgnoring the rest of the "
                "frames...\n");

        // We still need to read the 'data' part of the message but we are going to discard whatever we read
        char* discard_buffer[MAX_MESSAGE_FRAME_SIZE];
        int ret = recv(sender, discard_buffer, packet_size, MSG_WAITALL);

        if (ret != packet_size) {
            // TODO(santi)This is probably a fatal error as we can't do much to recover from this
            fprintf(stderr, "(IPC) Error trying to discard [%d] sent data.", sender);
        }
        return;
    }

    ASSERT((*msg)->received <= (*msg)->total_size);

    // We got a MSG_CONT but we already received all the data we supposed to receive for this msg We either have a
    // malformed msg or a malicious attacker trying to make us crash by requesting too much memory.
    if ((*msg)->received >= (*msg)->total_size) {
        fprintf(stderr,
                "(IPC) Got extra continuation messages from [%u] but already received all the data. Dropping malformed "
                "message...",
                sender);

        if (connection->cfg.is_server) {
            // We want to send an empty response in case the client is blocking on
            // and endless loop waiting for the response
            internal_message_t response = {.data = 0, .size = 0, .msg_id = (*msg)->msg_id, .sender = (*msg)->sender};
            IPC_push_message(connection, response.m);
        }

        msg_in_progress_t *tmp = *msg;
        *msg = (*msg)->next;
        free(tmp);
        return;
    }

    int error = 0;
    if ((packet_size > 0) && (packet_size <= (*msg)->total_size)) {
        uint8_t *dest = (uint8_t *)(*msg)->buffer + (*msg)->received;
        int ret = recv(sender, dest, packet_size, MSG_WAITALL);
        if (ret == packet_size) {
            (*msg)->received += packet_size;
        }
        else if ((ret < packet_size) || (errno == EWOULDBLOCK) || (errno == EAGAIN)) {
            // TODO(santi) seems a bit much. Maybe we want other way to handle a client being too slow? but also you
            // could configure a higher timeout
            // There's also a possibility that a malicious client would delay the sending of the data part and send it
            // after this timeout happens but it's not clear to me atm if this can be used to exploit something.
            // What happens if the client sends this data after the timeout?
            fprintf(stderr,
                    "(IPC) Timed out waiting for [%d] to send the data. Dropping the rest of the frames...\n",
                    sender);
            error = -1;
        }
    }

    if (error) {
        fprintf(stderr, "Got malformed message. Dropping the rest of the frames...\n");
        if (connection->cfg.is_server) {
            // We want to send an empty response in case the client is blocking on
            // and endless loop waiting for the response
            internal_message_t response = {.data = 0, .size = 0, .msg_id = (*msg)->msg_id, .sender = (*msg)->sender};
            IPC_push_message(connection, response.m);
        }

        msg_in_progress_t *tmp = *msg;
        *msg = (*msg)->next;
        free(tmp);
    }

    if (info.fin) {
        ASSERT_MSG((*msg)->received == (*msg)->total_size,
                   "Message finalized sending but received bytes and total size do not match\nrec:[%d] total[%d]\n",
                   (*msg)->received,
                   (*msg)->total_size);

        if ((*msg)->received == (*msg)->total_size) {
            pthread_mutex_lock(&connection->get_message_mtx);

            // TODO(santi) this could be 'slow' if the incomming messages
            // don't get popped fast enough and the list grows 'big'
            imessage_queue_t **queue = &connection->in_queue;
            while (*queue != 0) { queue = &(*queue)->next; }

            *queue = (imessage_queue_t *)calloc(1, sizeof(imessage_queue_t));

            if (*queue) {
                internal_message_t m = {.data = (*msg)->buffer,
                                        .size = (*msg)->total_size,
                                        .msg_id = (*msg)->msg_id,
                                        .sender = (*msg)->sender};
                (*queue)->msg = m;
            }
            else {
                fprintf(stderr, "Max in stack reached\n");
                fprintf(stderr, "(IPC) Dropping message received from [%d]\n", (*msg)->sender);
            }

            pthread_cond_broadcast(&connection->in_queue_updated_cond);
            pthread_mutex_unlock(&connection->get_message_mtx);
        }
        else {
            fprintf(stderr, "(IPC) ERROR - Received MSG_FIN but did not get the full data\n");
            fprintf(stderr, "(IPC) Dropping malformed message received from [%d]\n", (*msg)->sender);
            free((*msg)->buffer);
        }

        msg_in_progress_t *tmp = *msg;
        *msg = (*msg)->next;
        free(tmp);
    }
}

void client_try_reconnnect(IPC_connection connection) {
    // TODO(santi) Consider making this an atomic var instead
    pthread_mutex_lock(&connection->get_message_mtx);
    pthread_mutex_lock(&connection->send_message_mtx);
    connection->is_connected = 0;
    pthread_mutex_unlock(&connection->send_message_mtx);
    pthread_mutex_unlock(&connection->get_message_mtx);
    // Set the is_connected to 0 to signal an error and wake up the clients waiting for a server
    // response that is never going to come so they can pop an eempty response
    pthread_cond_broadcast(&connection->in_queue_updated_cond);

    printf("Waiting for server to come back...\n");
    // If we are a client we want to try to reconnect when the server comes alive again
    int new_server = socket(AF_UNIX, SOCK_STREAM, 0);

    connection->max_msg_size = MAX_MESSAGE_FRAME_SIZE;
    if (set_socket_size(new_server, &connection->max_msg_size, SO_SNDBUF) != 0) {
        // TODO(santi) probably the only option that we have here is to panic and exit
        // as we don't really have an option of handling this inside the reader thread
        connection->err_code = IPC_ERR_MAX_SND_SIZE_FAIL;
        connection->msg = strerror(errno);
    }

    connection->max_msg_size = MAX_MESSAGE_FRAME_SIZE;
    if (set_socket_size(new_server, &connection->max_msg_size, SO_RCVBUF) != 0) {
        // TODO(santi) probably the only option that we have here is to panic and exit
        // as we don't really have an option of handling this inside the reader thread
        connection->err_code = IPC_ERR_MAX_REC_SIZE_FAIL;
        connection->msg = strerror(errno);
    }

    // Unix trickery to so we don't have to rework all
    // the poll calls on the reader/writter threads
    dup2(new_server, connection->socket);
    close(new_server);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, connection->cfg.socket_path, sizeof(addr.sun_path) - 1);

    int ret = -1;
    int backoff = 1;
    while (ret == -1) {
        fprintf(stderr, "(IPC) Trying to reconnect to server\n");
        ret = connect(connection->socket, (const struct sockaddr *)&addr, sizeof(addr));
        if (ret == -1) {
            fprintf(stderr, "(IPC) The server is down. Sleeping for [%d]s...\n", backoff);
            sleep(backoff);
            backoff = backoff < MAX_BACKOFF_SLEEP ? backoff * 2 : MAX_BACKOFF_SLEEP;
        }
    }

    pthread_mutex_lock(&connection->get_message_mtx);
    pthread_mutex_lock(&connection->send_message_mtx);
    connection->is_connected = 1;
    pthread_mutex_unlock(&connection->send_message_mtx);
    pthread_mutex_unlock(&connection->get_message_mtx);

    // We got a server connection so we can send any pending requests now
    pthread_cond_broadcast(&connection->out_queue_updated_cond);
}

struct reader_thread_data {
    IPC_connection connection;
    int max_supported_clients;
};

struct reader_thread_cleanup {
    struct pollfd *pfds;
    int max_supported_clients;
};

static void reader_loop_cleanup(void *args) {
    struct reader_thread_cleanup *cdata = (struct reader_thread_cleanup *)args;
    int max_clients = cdata->max_supported_clients;
    struct pollfd *pfds = cdata->pfds;

    fprintf(stderr, "(IPC) Cleaning up server thread...\n");

    for (int i = 0; i < max_clients; ++i) {
        if (pfds[i].fd != -1) {
            close(pfds[i].fd);
        }
    }

    free(pfds);
}

static void *start_read_loop(void *pdata) {
    ASSERT_MSG(pdata != 0, "Need a valid connection to start server thread\n");

    struct reader_thread_data *data = (struct reader_thread_data *)pdata;
    IPC_connection connection = data->connection;
    int max_supported_clients = data->max_supported_clients;
    free(data);

    struct pollfd *pfds;
    pfds = (struct pollfd *)calloc(max_supported_clients, sizeof(struct pollfd));

    pfds[0].fd = connection->socket;
    pfds[0].events = POLLIN;
    // pfds structures with fd = -1 are ignored in the poll call
    for (int i = 1; i < max_supported_clients; ++i) { pfds[i].fd = -1; }

    // This buffer will live in the stack so we want to make sure that nobody
    // changes this blindly to something that will not fit
    STATIC_ASSERT(MAX_MESSAGE_FRAME_SIZE < KB(128));

    uint8_t local_buffer[MAX_HEADER_SIZE] = {0};

    // When the IPC server gets shutdown we want to make sure that we cleanup our data
    // in case that we want to re-initialize the server for some reason
    struct reader_thread_cleanup *cleanup_data =
        (struct reader_thread_cleanup *)calloc(0, sizeof(struct reader_thread_cleanup));
    cleanup_data->max_supported_clients = max_supported_clients;
    cleanup_data->pfds = pfds;
    pthread_cleanup_push(reader_loop_cleanup, cleanup_data);

    int done = 0;
    while (!done) {
        int event = poll(pfds, max_supported_clients, -1);

        if ((event < 0) && (errno != EINTR)) {
            fprintf(stderr, "(IPC) Errror while waiting for IPC event: %s\n", strerror(errno));
            continue;
        }

        for (int i = 0; i < max_supported_clients; i++) {
            struct pollfd *pfd = pfds + i;

            if (pfd->revents != 0) {
                if ((pfd->revents & POLLHUP) || (pfd->revents & POLLERR)) {
                    printf("(IPC) Closing client [%d]\n", pfd->fd);

                    // Check if we had any in progress messages from that connection
                    msg_in_progress_t **msg = &connection->incomming_queue;
                    while (*msg != 0 && (*msg)->sender != pfd->fd) { msg = &(*msg)->next; }
                    if (*msg) {
                        fprintf(stderr,
                                "(IPC) Connection [%d] closed but had messages in-progress. Dropping incomplete "
                                "messages...\n",
                                pfd->fd);
                        msg_in_progress_t *tmp = *msg;
                        *msg = (*msg)->next;
                        free(tmp);
                    }

                    if ((pfd->fd == connection->socket) && (connection->cfg.is_server == 0)) {
                        client_try_reconnnect(connection);
                    }
                    else {
                        if (close(pfd->fd) == -1) {
                            fprintf(stderr, "(IPC) Error closing client [%d]\n", pfd->fd);
                        }
                        else {
                            // Poll will ignore this pfd on the next call
                            pfd->fd = -1;
                        }
                    }
                }
                else if (pfd->revents & POLLIN) {
                    if (connection->cfg.is_server && pfd->fd == connection->socket) {
                        int new_connection = accept(connection->socket, 0, 0);
                        if (new_connection < 0) {
                            fprintf(stderr, "(IPC) Error connecting new client\n");
                        }
                        else {
                            printf("(IPC) New client requested connection [%d]\n", new_connection);
                            int k = 1;
                            for (; k < max_supported_clients; ++k) {
                                if (pfds[k].fd == -1) {
                                    pfds[k].fd = new_connection;
                                    pfds[k].events = POLLIN;

                                    struct timeval tv;
                                    tv.tv_sec = READ_TIMEOUT;
                                    tv.tv_usec = 0;
                                    setsockopt(new_connection, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
                                    break;
                                }
                            }
                            ASSERT_MSG(k != max_supported_clients,
                                       "Error adding new client. Max connections exceeded\n");
                        }
                    }
                    else {
                        int bytes_recieved = recv(pfd->fd, &local_buffer, 5, MSG_PEEK);
                        if (bytes_recieved == 5) {
                            uint32_t header_crc = *(uint32_t*)local_buffer;
                            struct first_byte_info *info = (struct first_byte_info*)&local_buffer[4];
                            // The first_byte_info contains the actual header size that we need to read;
                            int header_bytes = recv(pfd->fd, &local_buffer, info->header_size, MSG_WAITALL);

                            if (header_bytes == info->header_size) {
                                // check if we have valid header data by using the crc32 stored at the start of the msg
                                if (header_crc == xcrc32(local_buffer + 4, info->header_size - 4, 0)) {
                                    process_incomming_message(connection, header_bytes, local_buffer, pfd->fd);
                                }
                                else {
                                    fprintf(stderr, "(IPC) Invalid header data for [%u]. Ignoring message...\n", pfd->fd);
                                }
                            }
                            else {
                                fprintf(stderr, "(IPC) Error reading clients [%d] header\n", pfd->fd);
                            }
                        }
                        else {
                            fprintf(stderr, "(IPC) Error reading client [%d] data\n", pfd->fd);
                        }
                    }
                }
            }
        }
    }

    pthread_cleanup_pop(0);
    return 0;
}

static int create_ipc_threads(IPC_connection connection, int max_clients) {
    int ret = 0;

    pthread_attr_t attr;
    if (pthread_attr_init(&attr)) {
        return IPC_ERR_THREAD;
    }

    struct reader_thread_data *data = (struct reader_thread_data *)calloc(1, sizeof(struct reader_thread_data));
    data->connection = connection;
    data->max_supported_clients = max_clients;

    ret = pthread_create(&connection->reader_thread, &attr, start_read_loop, (void *)data);
    if (ret != 0) {
        return IPC_ERR_READER_THREAD;
    }

    pthread_setname_np(connection->reader_thread, "IPC_reader");

    ret = pthread_create(&connection->writter_thread, &attr, start_write_loop, (void *)connection);
    if (ret != 0) {
        return IPC_ERR_WRITTER_THREAD;
    }

    pthread_setname_np(connection->writter_thread, "IPC_writter");

    pthread_attr_destroy(&attr);

    return ret;
}

IPC_connection IPC_initialize(IPC_config_t const *cfg) {
    ASSERT_MSG(cfg != 0, "Must provide a valid config");
    ASSERT_MSG(cfg->socket_path != 0, "Must provide a valid socket path");

    IPC_connection ret = (IPC_connection)calloc(1, sizeof(struct _IPC_connection));

    int new_socket;
    new_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (new_socket == -1) {
        ret->err_code = IPC_ERR_NO_SOCKET;
        ret->msg = strerror(errno);
        return ret;
    }

    if (cfg->is_server) {
        // TODO(santi) review this
        unlink(cfg->socket_path);

        struct sockaddr_un name;
        memset(&name, 0, sizeof(name));
        name.sun_family = AF_UNIX;
        strncpy(name.sun_path, cfg->socket_path, sizeof(name.sun_path) - 1);

        if (bind(new_socket, (const struct sockaddr *)&name, sizeof(name)) == -1) {
            ret->err_code = IPC_ERR_BIND_FAIL;
            ret->msg = strerror(errno);
            return ret;
        }

        ASSERT_MSG(cfg->max_queued_connections < SOMAXCONN,
                   "Max queued connections exceed the UNIX allowed connections");
        if (listen(new_socket, cfg->max_queued_connections) == -1) {
            ret->err_code = IPC_ERR_LISTEN_FAIL;
            ret->msg = strerror(errno);
            return ret;
        }

        if (chmod(cfg->socket_path, cfg->permissions) < 0) {
            ret->err_code = IPC_ERR_PERMISSION_FAIL;
            ret->msg = strerror(errno);
            close(new_socket);
            return ret;
        }

        ret->is_connected = 1; // A server can't really disconnect so this shouldn't change
    }

    ret->max_msg_size = MAX_MESSAGE_FRAME_SIZE;
    if (set_socket_size(new_socket, &ret->max_msg_size, SO_SNDBUF) != 0) {
        ret->err_code = IPC_ERR_MAX_SND_SIZE_FAIL;
        ret->msg = strerror(errno);
    }

    ret->max_msg_size = MAX_MESSAGE_FRAME_SIZE;
    if (set_socket_size(new_socket, &ret->max_msg_size, SO_RCVBUF) != 0) {
        ret->err_code = IPC_ERR_MAX_REC_SIZE_FAIL;
        ret->msg = strerror(errno);
    }

    ret->cfg = *cfg;
    ret->socket = new_socket;
    ret->incomming_queue = 0;
    ret->cfg.socket_path = strdup(cfg->socket_path);
    ret->err_code = IPC_ERR_OK;
    return ret;
}

void IPC_shutdown(IPC_connection *connection) {
    IPC_connection pcon = *connection;

    if (pcon->socket == 0) {
        return;
    }

    pthread_cancel(pcon->reader_thread);
    pthread_cancel(pcon->writter_thread);
    pthread_join(pcon->reader_thread, 0);
    pthread_join(pcon->writter_thread, 0);

    msg_in_progress_t **msg = &pcon->incomming_queue;
    while (*msg) {
        msg_in_progress_t *tmp = (*msg);
        *msg = (*msg)->next;
        free(tmp);
    }

    imessage_queue_t **in_msg = &pcon->in_queue;
    while (*msg) {
        imessage_queue_t *tmp = (*in_msg);
        *in_msg = (*in_msg)->next;
        free(tmp);
    }

    imessage_queue_t **out_msg = &pcon->out_queue;
    while (*msg) {
        imessage_queue_t *tmp = (*out_msg);
        *out_msg = (*out_msg)->next;
        free(tmp);
    }

    shutdown(pcon->socket, SHUT_RDWR);
    close(pcon->socket);

    if (pcon->cfg.is_server) {
        unlink(pcon->cfg.socket_path);
    }

    free((void *)pcon->cfg.socket_path);

    free(pcon);
    *connection = 0;
}

int IPC_is_connection_valid(const IPC_connection connection) {
    return (connection->err_code == IPC_ERR_OK);
}

void IPC_print_error(const IPC_connection connection) {
    fprintf(stderr, "Error creating IPC connection: (%d) %s\n", connection->err_code, connection->msg);
}

IPC_RET_CODES IPC_start_client(IPC_connection connection) {
    ASSERT_MSG(connection->cfg.is_server == 0, "(IPC) The connection is not configured as a client\n");

    int ret = IPC_ERR_OK;

    pthread_attr_t attr;
    if (pthread_attr_init(&attr)) {
        return IPC_ERR_THREAD;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, connection->cfg.socket_path, sizeof(addr.sun_path) - 1);

    int retc = -1;
    int backoff = 1;
    while (retc == -1) {
        //fprintf(stderr, "(IPC) Trying to reconnect to server\n");
        retc = connect(connection->socket, (const struct sockaddr *)&addr, sizeof(addr));
        if (retc == -1) {
            fprintf(stderr, "(IPC) The server is down. Sleeping for [%d]s...\n", backoff);
            sleep(backoff);
            backoff = backoff < MAX_BACKOFF_SLEEP ? backoff * 2 : MAX_BACKOFF_SLEEP;
        }
    }

    //ret = connect(connection->socket, (const struct sockaddr *)&addr, sizeof(addr));
    //if (ret == -1) {
    //    fprintf(stderr, "(IPC) The server is down.\n");
    //    return IPC_ERR_FAIL_SERVER_CON;
    //}

    connection->is_connected = 1;

    return create_ipc_threads(connection, 1);
}

IPC_RET_CODES IPC_start_server(IPC_connection connection, int max_supported_clients) {
    ASSERT_MSG(connection->cfg.is_server, "(IPC) The connection is not configured as a server\n");
    int ret = IPC_ERR_OK;

    create_ipc_threads(connection, max_supported_clients);
    return ret;
}

message_t IPC_pop_response(IPC_connection connection, uint32_t request_id, int timeout /*in us*/) {
    ASSERT_MSG(connection, "Need and active connection to pop messages from");

    message_t result = {0};
    struct timespec abstimeout;

    if (timeout) {
        struct timeval now;

        gettimeofday(&now, NULL);
        abstimeout.tv_nsec = (now.tv_usec * 1000) + timeout;
        if (abstimeout.tv_nsec >= 1000000000) {
            abstimeout.tv_sec++;
            abstimeout.tv_nsec -= 1000000000;
        }
    }

    pthread_mutex_lock(&connection->get_message_mtx);

    // Lets try to find the response for the request_id we sent
    imessage_queue_t **msg = &connection->in_queue;
    while ((*msg) != 0 && (*msg)->msg.msg_id != request_id) { msg = &(*msg)->next; }

    int ret = 0;
    // If we didn't find the request_id in the list the either the list is empty or we are at the end of it
    while (*msg == 0 && ret != ETIMEDOUT) {

        if (timeout) {
            ret = pthread_cond_timedwait(&connection->in_queue_updated_cond, &connection->get_message_mtx, &abstimeout);
        }
        else {
            pthread_cond_wait(&connection->in_queue_updated_cond, &connection->get_message_mtx);
        }

        if (connection->is_connected == 0) {
            // We got woken up by a server disconnection so we could unblock clients
            // that are waiting without a timeout. So we just return an empty result
            pthread_mutex_unlock(&connection->get_message_mtx);
            return result;
        }
        // if we woke up we need to re-search the list againt to see if our request_id was added in it
        msg = &connection->in_queue;
        while ((*msg) != 0 && (*msg)->msg.msg_id != request_id) { msg = &(*msg)->next; }
    }

    if (ret == ETIMEDOUT) {
        pthread_mutex_unlock(&connection->get_message_mtx);
        return result;
    }

    result = (*msg)->msg.m;

    imessage_queue_t *tmp = *msg;
    (*msg) = (*msg)->next;
    free(tmp);

    pthread_mutex_unlock(&connection->get_message_mtx);
    return result;
}

message_t IPC_pop_request(IPC_connection connection) {
    ASSERT_MSG(connection, "Need and active connection to pop messages from");
    ASSERT_MSG(connection->cfg.is_server, "Only a server connection can pop requests\n");

    message_t result = {0};

    pthread_mutex_lock(&connection->get_message_mtx);

    int ret = 0;
    while (connection->in_queue == 0) {
        pthread_cond_wait(&connection->in_queue_updated_cond, &connection->get_message_mtx);
    }

    result = connection->in_queue->msg.m;
    imessage_queue_t *tmp = connection->in_queue;
    connection->in_queue = connection->in_queue->next;

    free(tmp);

    pthread_mutex_unlock(&connection->get_message_mtx);
    return result;
}

uint32_t IPC_push_message(IPC_connection connection, message_t message) {
    pthread_mutex_lock(&connection->send_message_mtx);

    // TODO(santi) this could be 'slow' if we are slow writting
    // the messages don't get popped fast enough and the list grows 'big'
    imessage_queue_t **msg = &connection->out_queue;
    while ((*msg) != 0) { msg = &(*msg)->next; }

    *msg = (imessage_queue_t *)calloc(1, sizeof(imessage_queue_t));
    if (msg == 0) {
        fprintf(stderr, "(IPC) Failed to queue message.\n");
        return -1;
    }

    internal_message_t imsg = {.m = message};
    if (connection->cfg.is_server == 0) {
        // If we are a client we want to respond to the server always
        imsg.sender = connection->socket;
        imsg.msg_id = connection->current_msg_id;
        // We don't really care about the overflow because the chances that we could step on a message that still has
        // the same is are really low. Although there's some possibility that a malicious attacker *could* make the id
        // roll over to try to get a client to pop-up a specific response. (needs more investigation probably)
        connection->current_msg_id++;
        if (connection->current_msg_id == INVALID_MSG_ID) {
            connection->current_msg_id++;
        }
    }

    (*msg)->msg = imsg;

    pthread_cond_signal(&connection->out_queue_updated_cond);
    pthread_mutex_unlock(&connection->send_message_mtx);
    return imsg.msg_id;
}
