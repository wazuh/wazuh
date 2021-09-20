/* Network buffer library for Remoted
 * November 26, 2018
 *
 * Copyright (C) 2015-2021 Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include <shared.h>
#include <os_net/os_net.h>
#include "remoted.h"

extern netbuffer_t netbuffer_send;
extern wnotify_t * notify;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void nb_open(netbuffer_t * buffer, int sock, const struct sockaddr_in * peer_info) {
    w_mutex_lock(&mutex);

    if (sock >= buffer->max_fd) {
        os_realloc(buffer->buffers, sizeof(sockbuffer_t) * (sock + 1), buffer->buffers);
        buffer->max_fd = sock;
    }

    memset(buffer->buffers + sock, 0, sizeof(sockbuffer_t));
    memcpy(&buffer->buffers[sock].peer_info, peer_info, sizeof(struct sockaddr_in));

    w_mutex_unlock(&mutex);
}

void nb_close(netbuffer_t * buffer, int sock) {

    w_mutex_lock(&mutex);

    free(buffer->buffers[sock].data);
    memset(buffer->buffers + sock, 0, sizeof(sockbuffer_t));

    w_mutex_unlock(&mutex);
}

/*
 * Receive available data from the network and push as many message as possible
 * Returns -2 on data corruption at application layer (header).
 * Returns -1 on system call error: recv().
 * Returns 0 if no data was available in the socket.
 * Returns the number of bytes received on success.
*/
int nb_recv(netbuffer_t * buffer, int sock) {
    sockbuffer_t * sockbuf = &buffer->buffers[sock];
    unsigned long data_ext = sockbuf->data_len + receive_chunk;
    long recv_len;
    unsigned long i;
    unsigned long cur_offset;
    uint32_t cur_len;

    w_mutex_lock(&mutex);

    // Extend data buffer

    if (data_ext > sockbuf->data_size) {
        os_realloc(sockbuf->data, data_ext, sockbuf->data);
        sockbuf->data_size = data_ext;
    }

    // Receive and append

    recv_len = recv(sock, sockbuf->data + sockbuf->data_len, receive_chunk, 0);

    if (recv_len <= 0) {
        goto end;
    }

    sockbuf->data_len += recv_len;

    // Dispatch as most messages as possible

    for (i = 0; i + sizeof(uint32_t) <= sockbuf->data_len; i = cur_offset + cur_len) {
        cur_len = wnet_order(*(uint32_t *)(sockbuf->data + i));

        if (cur_len > OS_MAXSTR) {
            recv_len = -2;
            goto end;
        }

        cur_offset = i + sizeof(uint32_t);

        if (cur_offset + cur_len > sockbuf->data_len) {
            break;
        }

        rem_msgpush(sockbuf->data + cur_offset, cur_len, &sockbuf->peer_info, sock);
    }

    // Move remaining data to data start

    if (i > 0) {
        if (i < sockbuf->data_len) {
            memcpy(sockbuf->data, sockbuf->data + i, sockbuf->data_len - i);
        }

        sockbuf->data_len -= i;

        switch (buffer_relax) {
        case 0:
            // Do not deallocate memory.
            break;

        case 1:
            // Shrink memory to fit the current buffer or the receive chunk.
            sockbuf->data_size = sockbuf->data_len > receive_chunk ? sockbuf->data_len : receive_chunk;
            os_realloc(sockbuf->data, sockbuf->data_size, sockbuf->data);
            break;

        default:
            // Full memory deallocation.
            sockbuf->data_size = sockbuf->data_len;

            if (sockbuf->data_size) {
                os_realloc(sockbuf->data, sockbuf->data_size, sockbuf->data);
            } else {
                os_free(sockbuf->data);
            }
        }
    }

end:

    w_mutex_unlock(&mutex);
    return recv_len;
}

void nb_send(int socket) {
    w_mutex_lock(&mutex);

    const ssize_t current_data_len = netbuffer_send.buffers[socket].data_len;
    const uint32_t amount_of_data_to_send = send_chunk < current_data_len ? send_chunk : current_data_len;

    mdebug1("Msg added to buffer, buff.data_size: %d", amount_of_data_to_send);

    const ssize_t sent_bytes = send(socket, (const void *)netbuffer_send.buffers[socket].data, amount_of_data_to_send, 0);

    const int error = errno; // Race condition here, the usage if errno is not thread safe!!!

    if (sent_bytes > 0) {
        //assert(sent_bytes <= current_data_len);
        if (sent_bytes == current_data_len) {
            os_free(netbuffer_send.buffers[socket].data);
            netbuffer_send.buffers[socket].data = NULL;
            netbuffer_send.buffers[socket].data_len = 0;
            netbuffer_send.buffers[socket].data_size = 0;
            wnotify_modify(notify, socket, WO_READ);
        }
        else { // sent_bytes < current_data_len
            memmove(netbuffer_send.buffers[socket].data, netbuffer_send.buffers[socket].data + sent_bytes, sent_bytes);
            os_realloc(netbuffer_send.buffers[socket].data, sent_bytes, netbuffer_send.buffers[socket].data);
            netbuffer_send.buffers[socket].data_len -= sent_bytes;
            netbuffer_send.buffers[socket].data_size -= sent_bytes;
        }
    }
    else if (sent_bytes < 0) {

        if (error != ETIMEDOUT) {
            os_free(netbuffer_send.buffers[socket].data);
            netbuffer_send.buffers[socket].data = NULL;
            netbuffer_send.buffers[socket].data_len = 0;
            netbuffer_send.buffers[socket].data_size = 0;
            wnotify_modify(notify, socket, WO_READ);
        }

        mdebug1("sent_bytes: %ld, errno %d, errnostr %s", sent_bytes, error, strerror(error));

        switch (error) {
            case ETIMEDOUT:
                mdebug1("socket [%d], Time out.", socket);
                break;
            case EPIPE:
            case EBADF:
            case ECONNRESET:
                mdebug1("socket [%d], Agent may have disconnected.", socket);
                break;
            case EAGAIN:
#if EAGAIN != EWOULDBLOCK
            case EWOULDBLOCK:
#endif
                mwarn("socket [%d], Agent is not responding.", socket);
                break;
            default:
                merror(strerror(error), socket);
        }
    }

    w_mutex_unlock(&mutex);
}

void nb_queue(int socket, char *crypt_msg, ssize_t msg_size) {

    w_mutex_lock(&mutex);

    for (unsigned int retry = 0; retry < 1; retry++) {

        char * data = netbuffer_send.buffers[socket].data;
        const unsigned long current_data_size = netbuffer_send.buffers[socket].data_size;
        const unsigned long current_data_len = netbuffer_send.buffers[socket].data_len;
        mdebug1("current_data_len %ld, current_data_size: %ld, msg_size: %ld", current_data_len, current_data_size, msg_size);

        if (current_data_size + msg_size <= OS_MAXSTR) {
            os_realloc(data, current_data_len + msg_size + sizeof(uint32_t), data);
            netbuffer_send.buffers[socket].data = data;
            *(uint32_t *)(data + current_data_len) = wnet_order(msg_size);
            memcpy(data + current_data_len + sizeof(uint32_t), crypt_msg, msg_size);
            netbuffer_send.buffers[socket].data_size += msg_size + sizeof(uint32_t);
            netbuffer_send.buffers[socket].data_len += msg_size + sizeof(uint32_t);
            wnotify_modify(notify, socket, WO_READ | WO_WRITE);

            mdebug1("Msg added to buffer, buff.data_size: %ld", netbuffer_send.buffers[socket].data_size);
            break;
        }
        else
        {
            merror("Could not append data into buffer, not enough space, Retrying.... [buffer_size=%lu, msg_size=%lu]", current_data_size, msg_size);
            sleep(1);
        }
    }

    w_mutex_unlock(&mutex);
}
