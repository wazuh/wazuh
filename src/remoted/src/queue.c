/* Remoted queue handling library
 * Copyright (C) 2015, Wazuh Inc.
 * April 2, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include "remoted.h"
#include "state.h"

static w_queue_t * queue;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t available = PTHREAD_COND_INITIALIZER;

static size_t rem_input_max_bytes = 0;   ///< 0 = unlimited
static size_t rem_input_bytes_used = 0;  ///< protected by mutex

// Init message queue
void rem_msginit(size_t size) {
    queue = queue_init(size);
}

// Free the message queue (used by unit tests to avoid leaks between test cases)
void rem_msgdestroy(void) {
    if (queue) {
        queue_free(queue);
        queue = NULL;
    }
    rem_input_bytes_used = 0;
    rem_input_max_bytes  = 0;
}

// Configure the byte capacity limit for the input queue (0 = unlimited)
void rem_set_input_queue_max_bytes(size_t max_bytes) {
    w_mutex_lock(&mutex);
    rem_input_max_bytes = max_bytes;
    w_mutex_unlock(&mutex);
}

// Push message into queue
int rem_msgpush(const char * buffer, unsigned long size, struct sockaddr_storage * addr, int sock) {
    message_t * message;
    int result;
    static time_t last_discard_warn = 0;
    static size_t pending_discards = 0;

    os_malloc(sizeof(message_t), message);
    os_malloc(size, message->buffer);
    memcpy(message->buffer, buffer, size);
    message->size = size;
    memcpy(&message->addr, addr, sizeof(struct sockaddr_storage));
    message->sock = sock;

    w_mutex_lock(&mutex);

    message->counter = ++global_counter;

    // Byte capacity check (must be inside mutex to keep rem_input_bytes_used consistent)
    if (rem_input_max_bytes > 0) {
        if (size > rem_input_max_bytes) {
            // Individual event exceeds the configured byte limit.
            w_mutex_unlock(&mutex);
            rem_msgfree(message);
            mdebug2("Discarding oversized event from host (%lu bytes > %zu byte limit).", size, rem_input_max_bytes);
            rem_inc_recv_discarded();
            pending_discards++;
            { time_t _t = time(NULL); if (_t - last_discard_warn >= 5) { mwarn("Input queue discarded %zu event(s) in the last 5 seconds.", pending_discards); pending_discards = 0; last_discard_warn = _t; } }
            return -1;
        }
        if (rem_input_bytes_used + size > rem_input_max_bytes) {
            // Byte quota full.
            w_mutex_unlock(&mutex);
            rem_msgfree(message);
            mdebug2("Discarding event from host: byte quota reached (%zu/%zu bytes).", rem_input_bytes_used, rem_input_max_bytes);
            rem_inc_recv_discarded();
            pending_discards++;
            { time_t _t = time(NULL); if (_t - last_discard_warn >= 5) { mwarn("Input queue discarded %zu event(s) in the last 5 seconds.", pending_discards); pending_discards = 0; last_discard_warn = _t; } }
            return -1;
        }
    }

    if (result = queue_push(queue, message), result == 0) {
        rem_input_bytes_used += size;
        w_cond_signal(&available);
    }

    w_mutex_unlock(&mutex);

    if (result < 0) {
        rem_msgfree(message);
        mdebug2("Discarding event from host.");
        rem_inc_recv_discarded();
        pending_discards++;
        { time_t _t = time(NULL); if (_t - last_discard_warn >= 5) { mwarn("Input queue discarded %zu event(s) in the last 5 seconds.", pending_discards); pending_discards = 0; last_discard_warn = _t; } }

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

    if (message->size <= rem_input_bytes_used) {
        rem_input_bytes_used -= message->size;
    } else {
        rem_input_bytes_used = 0;
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
