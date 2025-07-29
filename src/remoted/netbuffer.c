/* Network buffer library for Remoted
 * November 26, 2018
 *
 * Copyright (C) 2015 Wazuh Inc.
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
#include "state.h"

extern wnotify_t * notify;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void nb_open(netbuffer_t * buffer, int sock, const struct sockaddr_storage * peer_info) {
    w_mutex_lock(&mutex);

    if (sock >= buffer->max_fd) {
        os_realloc(buffer->buffers, sizeof(sockbuffer_t) * (sock + 1), buffer->buffers);
        buffer->max_fd = sock;
    }

    memset(buffer->buffers + sock, 0, sizeof(sockbuffer_t));
    memcpy(&buffer->buffers[sock].peer_info, peer_info, sizeof(struct sockaddr_storage));

    buffer->buffers[sock].bqueue = bqueue_init(send_buffer_size, BQUEUE_SHRINK);

    w_mutex_unlock(&mutex);
}

void nb_close(netbuffer_t * buffer, int sock) {

    w_mutex_lock(&mutex);

    if (buffer->buffers[sock].bqueue) {
        bqueue_destroy(buffer->buffers[sock].bqueue);
    }

    os_free(buffer->buffers[sock].data);
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
    long recv_len;
    unsigned long i;
    unsigned long cur_offset;
    uint32_t cur_len;

    w_mutex_lock(&mutex);

    sockbuffer_t * sockbuf = &buffer->buffers[sock];
    unsigned long data_ext = sockbuf->data_len + receive_chunk;

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
            char hex[OS_SIZE_2048 + 1] = {0};
            print_hex_string(&sockbuf->data[i], sockbuf->data_len - i, hex, sizeof(hex));
            mwarn("Unexpected message (hex): '%s'", hex);
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
            memmove(sockbuf->data, sockbuf->data + i, sockbuf->data_len - i);
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

int nb_send(netbuffer_t * buffer, int socket) {
    ssize_t sent_bytes = 0;

    char data[send_chunk];
    memset(data, 0, send_chunk);

    w_mutex_lock(&mutex);

    if (buffer->buffers[socket].bqueue) {

        ssize_t peeked_bytes = bqueue_peek(buffer->buffers[socket].bqueue, data, send_chunk, BQUEUE_NOFLAG);
        if (peeked_bytes > 0) {
            // Asynchronous sending
            sent_bytes = send(socket, (const void *)data, peeked_bytes, MSG_DONTWAIT);
        }

        if (sent_bytes > 0) {
            bqueue_drop(buffer->buffers[socket].bqueue, sent_bytes);
        } else if (sent_bytes < 0) {
            switch (errno) {
            case EAGAIN:
    #if EAGAIN != EWOULDBLOCK
            case EWOULDBLOCK:
    #endif
                break;
            default:
                merror("Could not send data to socket %d: %s (%d)", socket, strerror(errno), errno);
            }
        }

        if (!peeked_bytes || bqueue_used(buffer->buffers[socket].bqueue) == 0) {
            wnotify_modify(notify, socket, WO_READ);
        }
    }

    w_mutex_unlock(&mutex);

    return sent_bytes;
}

int nb_queue(netbuffer_t * buffer, int socket, char * crypt_msg, ssize_t msg_size, char * agent_id) {
    int retval = -1;
    int header_size = sizeof(uint32_t);
    char data[msg_size + header_size];
    const uint32_t bytes = wnet_order(msg_size);

    memcpy((data + header_size), crypt_msg, msg_size);
    // Add header at begining, first 4 bytes, it is message msg_size
    memcpy(data, &bytes, header_size);

    w_mutex_lock(&mutex);

    if (buffer->buffers[socket].bqueue) {

        if (!bqueue_push(buffer->buffers[socket].bqueue, (const void *) data, (size_t)(msg_size + header_size), BQUEUE_NOFLAG)) {

            if (bqueue_used(buffer->buffers[socket].bqueue) == (size_t)(msg_size + header_size)) {
                wnotify_modify(notify, socket, (WO_READ | WO_WRITE));
            }
            retval = 0;
        }
    }

    w_mutex_unlock(&mutex);

    return retval;
}
