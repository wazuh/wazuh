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

int nb_send(netbuffer_t * buffer, int socket) {
    ssize_t sent_bytes = 0;

    w_mutex_lock(&mutex);

    const unsigned long current_data_len = buffer->buffers[socket].data_len;
    const uint32_t amount_of_data_to_send = send_chunk < current_data_len ? send_chunk : current_data_len;

    if (amount_of_data_to_send > 0) {
        sent_bytes = send(socket, (const void *)buffer->buffers[socket].data, amount_of_data_to_send, 0);
    }

    if (sent_bytes > 0) {
        if (sent_bytes == current_data_len) {
            os_free(buffer->buffers[socket].data);
            buffer->buffers[socket].data = NULL;
            buffer->buffers[socket].data_len = 0;
        } else {
            memmove(buffer->buffers[socket].data, buffer->buffers[socket].data + sent_bytes, current_data_len - sent_bytes);
            os_realloc(buffer->buffers[socket].data, current_data_len - sent_bytes, buffer->buffers[socket].data);
            buffer->buffers[socket].data_len -= sent_bytes;
        }
    } else if ((sent_bytes < 0) && (errno != ETIMEDOUT)) {
        os_free(buffer->buffers[socket].data);
        buffer->buffers[socket].data = NULL;
        buffer->buffers[socket].data_len = 0;
    }

    if (buffer->buffers[socket].data_len == 0) {
        wnotify_modify(notify, socket, WO_READ);
    }

    w_mutex_unlock(&mutex);

    return sent_bytes;
}

int nb_queue(netbuffer_t * buffer, int socket, char * crypt_msg, ssize_t msg_size) {
    int retval = -1;

    for (unsigned int retry = 0; retry < 10; retry++) {

        w_mutex_lock(&mutex);

        int header_size = sizeof(uint32_t);
        char * data = buffer->buffers[socket].data;
        const unsigned long current_data_len = buffer->buffers[socket].data_len;

        if (current_data_len + msg_size <= OS_MAXSTR) {
            os_realloc(data, (current_data_len + msg_size + header_size), data);

            buffer->buffers[socket].data = data;
            *(uint32_t *)(data + current_data_len) = wnet_order(msg_size);
            memcpy((data + current_data_len + header_size), crypt_msg, msg_size);
            buffer->buffers[socket].data_len += (msg_size + header_size);

            wnotify_modify(notify, socket, (WO_READ | WO_WRITE));

            w_mutex_unlock(&mutex);

            retval = 0;
            break;
        }
        else {
            mdebug1("Not enough buffer space. Retrying... [buffer_size=%lu, msg_size=%lu]",
                buffer->buffers[socket].data_len, msg_size);

            w_mutex_unlock(&mutex);

            sleep(1);
        }
    }

    if (retval < 0) {
        merror("Package dropped. Could not append data into buffer.");
    }

    return retval;
}
