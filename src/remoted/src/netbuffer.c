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
#include "os_net.h"
#include "remoted.h"
#include "state.h"

extern wnotify_t * notify;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

// Release a slot's resources and drop it from the unauthenticated count. Call with the mutex held.
static void nb_release_slot(netbuffer_t * buffer, int sock) {
    if (!buffer->buffers || sock < 0 || sock > buffer->max_fd) {
        return;
    }

    sockbuffer_t * sockbuf = &buffer->buffers[sock];

    if (sockbuf->bqueue) {
        if (buffer->tracks_authentication && !sockbuf->authenticated && buffer->unauthenticated > 0) {
            buffer->unauthenticated--;
        }

        bqueue_destroy(sockbuf->bqueue);
    }

    os_free(sockbuf->data);
    memset(sockbuf, 0, sizeof(sockbuffer_t));
}

// Whether sock indexes an open slot. Call with the mutex held.
static bool nb_is_open(const netbuffer_t * buffer, int sock) {
    return buffer->buffers && sock >= 0 && sock <= buffer->max_fd && buffer->buffers[sock].bqueue;
}

void nb_open(netbuffer_t * buffer, int sock, const struct sockaddr_storage * peer_info) {
    w_mutex_lock(&mutex);

    if (!buffer->buffers || sock > buffer->max_fd) {
        // Grow only: every slot from the old end through sock is new, and the expiry scan walks all
        // of them, so zero them so they read as closed.
        int old_slots = buffer->buffers ? buffer->max_fd + 1 : 0;
        os_realloc(buffer->buffers, sizeof(sockbuffer_t) * (sock + 1), buffer->buffers);
        memset(buffer->buffers + old_slots, 0, sizeof(sockbuffer_t) * (sock + 1 - old_slots));

        buffer->max_fd = sock;
    }

    // nb_close_socket() closes the descriptor under this mutex and releases both slots before
    // unlocking, so accept() cannot hand this number back while its old slot is still open. Release
    // it anyway as a safety net, so neither a queue nor the unauthenticated count can ever leak.
    nb_release_slot(buffer, sock);

    memcpy(&buffer->buffers[sock].peer_info, peer_info, sizeof(struct sockaddr_storage));

    buffer->buffers[sock].bqueue = bqueue_init(send_buffer_size, BQUEUE_SHRINK);
    buffer->buffers[sock].opened_at = time(NULL);

    if (buffer->tracks_authentication) {
        buffer->unauthenticated++;
    }

    w_mutex_unlock(&mutex);
}

bool nb_close_socket(netbuffer_t * recv, netbuffer_t * send, int sock) {
    bool released = false;

    w_mutex_lock(&mutex);

    // nb_recv() queues under this mutex, so no message of this connection can carry a counter past this fence
    rem_setCounter(sock, global_counter);

    // Closing under the mutex makes an accept() that reuses the fd wait in nb_open() until both slots are released
    const int close_ret = close(sock);
    const int close_errno = errno;

    // Release the slots even when close() fails: on Linux a failed close() still frees the descriptor, so
    // its number can be handed to anything else at once, and a slot left open would let the
    // unauthenticated-connection reaper close() that number again later. EBADF is the exception: the
    // descriptor was not open, so another nb_close_socket() already closed it and released the slots, and
    // by now its number may already belong to a newly accepted connection whose slots must survive.
    if (close_ret == 0 || close_errno != EBADF) {
        nb_release_slot(recv, sock);
        nb_release_slot(send, sock);
        released = true;
    }

    w_mutex_unlock(&mutex);

    return released;
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
            mdebug2("Unexpected message (hex): '%s'", hex);
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

// Push a framed message into an open slot's send queue and, if it was empty, start watching the
// socket for writability. Call with the mutex held. Returns 0 on success, -1 if the queue is full.
static int nb_push(netbuffer_t * buffer, int socket, const char * data, size_t length) {
    if (bqueue_push(buffer->buffers[socket].bqueue, (const void *) data, length, BQUEUE_NOFLAG)) {
        return -1;
    }

    if (bqueue_used(buffer->buffers[socket].bqueue) == length) {
        wnotify_modify(notify, socket, (WO_READ | WO_WRITE));
    }

    return 0;
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

        if (!nb_push(buffer, socket, data, (size_t)(msg_size + header_size))) {
            retval = 0;
        } else {
            mdebug1("Not enough buffer space. Retrying... [buffer_size=%lu, used=%lu, msg_size=%lu]",
                buffer->buffers[socket].bqueue->max_length, buffer->buffers[socket].bqueue->length, msg_size);

            w_mutex_unlock(&mutex);
            sleep(send_timeout_to_retry);
            w_mutex_lock(&mutex);

            if (buffer->buffers[socket].bqueue) {

                if (!nb_push(buffer, socket, data, (size_t)(msg_size + header_size))) {
                    retval = 0;
                }
            }
        }
    }

    w_mutex_unlock(&mutex);

    if (retval < 0) {
        rem_inc_send_discarded();
        mwarn("Package dropped. Could not append data into buffer.");
    }

    return retval;
}

int nb_queue_nowait(netbuffer_t * buffer, int socket, const char * msg, size_t msg_size) {
    int retval = -2;
    const size_t header_size = sizeof(uint32_t);
    char data[msg_size + header_size];
    const uint32_t bytes = wnet_order(msg_size);

    memcpy(data, &bytes, header_size);
    memcpy(data + header_size, msg, msg_size);

    w_mutex_lock(&mutex);

    if (nb_is_open(buffer, socket)) {
        retval = nb_push(buffer, socket, data, msg_size + header_size);
    }

    w_mutex_unlock(&mutex);

    return retval;
}

void nb_set_authenticated(netbuffer_t * buffer, int sock, size_t counter) {
    w_mutex_lock(&mutex);

    // A message older than the last close of this fd belongs to a previous connection
    if (nb_is_open(buffer, sock) && !buffer->buffers[sock].authenticated && counter > rem_getCounter(sock)) {
        buffer->buffers[sock].authenticated = true;

        if (buffer->tracks_authentication && buffer->unauthenticated > 0) {
            buffer->unauthenticated--;
        }
    }

    w_mutex_unlock(&mutex);
}

size_t nb_unauthenticated_count(netbuffer_t * buffer) {
    w_mutex_lock(&mutex);
    size_t count = buffer->unauthenticated;
    w_mutex_unlock(&mutex);

    return count;
}

int * nb_collect_unauthenticated(netbuffer_t * buffer, time_t deadline, size_t * count) {
    int * socks = NULL;

    *count = 0;

    w_mutex_lock(&mutex);

    if (buffer->buffers && buffer->unauthenticated > 0) {
        for (int sock = 0; sock <= buffer->max_fd; sock++) {
            sockbuffer_t * sockbuf = &buffer->buffers[sock];

            if (!sockbuf->bqueue || sockbuf->authenticated || sockbuf->opened_at > deadline) {
                continue;
            }

            if (!socks) {
                os_malloc(sizeof(int) * buffer->unauthenticated, socks);
            }

            socks[(*count)++] = sock;

            if (*count == buffer->unauthenticated) {
                break;
            }
        }
    }

    w_mutex_unlock(&mutex);

    return socks;
}
