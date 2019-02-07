/* Remoted queue handling library
 * Copyright (C) 2015-2019, Wazuh Inc.
 * April 2, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include "remoted.h"

static w_queue_t * queue;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t available = PTHREAD_COND_INITIALIZER;

// Init message queue
void rem_msginit(size_t size) {
    queue = queue_init(size);
}

// Push message into queue
int rem_msgpush(const char * buffer, unsigned long size, struct sockaddr_in * addr, int sock) {
    message_t * message;
    int result;
    static int reported = 0;

    os_malloc(sizeof(message_t), message);
    os_malloc(size, message->buffer);
    memcpy(message->buffer, buffer, size);
    message->size = size;
    memcpy(&message->addr, addr, sizeof(struct sockaddr_in));
    message->sock = sock;

    w_mutex_lock(&mutex);

    if (result = queue_push(queue, message), result == 0) {
        w_cond_signal(&available);
    }

    w_mutex_unlock(&mutex);

    if (result < 0) {
        rem_msgfree(message);
        mdebug2("Discarding event from host '%s'", inet_ntoa(addr->sin_addr));
        rem_inc_discarded();
        if (!reported) {
            mwarn("Message queue is full (%zu). Events may be lost.", queue->size);
            reported = 1;
        }
    }

    return result;
}

// Get current queue size
size_t rem_get_qsize() {
    size_t size = 0;
    w_mutex_lock(&mutex);
    size = (queue->begin - queue->end + queue->size) % queue->size;
    w_mutex_unlock(&mutex);
    return size;
}

// Get total queue size
size_t rem_get_tsize() {
    static size_t size = 0;
    if (!size) {
        w_mutex_lock(&mutex);
        size = queue->size;
        w_mutex_unlock(&mutex);
    }
    return size;
}

// Pop message from queue
message_t * rem_msgpop() {
    message_t * message;

    w_mutex_lock(&mutex);

    while (message = (message_t *)queue_pop(queue), !message) {
        w_cond_wait(&available, &mutex);
    }

    w_mutex_unlock(&mutex);
    return message;
}

// Free message
void rem_msgfree(message_t * message) {
    if (message) {
        free(message->buffer);
        free(message);
    }
}
