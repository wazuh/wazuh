/* Network buffer library for Remoted
 * November 26, 2018
 *
 * Copyright (C) 2018 Wazuh Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include <shared.h>
#include <os_net/os_net.h>
#include "remoted.h"

void nb_open(netbuffer_t * buffer, int sock, const struct sockaddr_in * peer_info) {
    if (sock >= buffer->max_fd) {
        os_realloc(buffer->buffers, sizeof(sockbuffer_t) * (sock + 1), buffer->buffers);
        buffer->max_fd = sock;
    }

    memset(buffer->buffers + sock, 0, sizeof(sockbuffer_t));
    memcpy(&buffer->buffers[sock].peer_info, peer_info, sizeof(struct sockaddr_in));
}

int nb_close(netbuffer_t * buffer, int sock) {
    int retval = close(sock);

    if (!retval) {
        free(buffer->buffers[sock].data);
        memset(buffer->buffers + sock, 0, sizeof(sockbuffer_t));
    }

    return retval;
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

    // Extend data buffer

    if (data_ext > sockbuf->data_size) {
        os_realloc(sockbuf->data, data_ext, sockbuf->data);
        sockbuf->data_size = data_ext;
    }

    // Receive and append

    recv_len = recv(sock, sockbuf->data + sockbuf->data_len, receive_chunk, 0);

    if (recv_len <= 0) {
        return recv_len;
    }

    sockbuf->data_len += recv_len;

    // Dispatch as most messages as possible

    for (i = 0; i + sizeof(uint32_t) <= sockbuf->data_len; i = cur_offset + cur_len) {
        cur_len = wnet_order(*(uint32_t *)(sockbuf->data + i));

        if (cur_len > OS_MAXSTR) {
            return -2;
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

    return recv_len;
}
