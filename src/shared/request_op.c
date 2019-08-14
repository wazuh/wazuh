/* Remote request structure
 * Copyright (C) 2015-2019, Wazuh Inc.
 * May 31, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <pthread.h>
#include <shared.h>
#include <request_op.h>

// Create node

req_node_t * req_create(int sock, const char * counter, const char * target, const char * buffer, size_t length) {
    req_node_t * node;

    os_malloc(sizeof(req_node_t), node);
    node->sock = sock;
    os_strdup(counter, node->counter);
    os_strdup(target, node->target);
    os_malloc(length + 1, node->buffer);
    memcpy(node->buffer, buffer, length);
    node->buffer[length] = '\0';
    node->length = length;
    w_mutex_init(&node->mutex, NULL);
    w_cond_init(&node->available, NULL);

    return node;
}

// Update node and signal available. It locks mutex.
void req_update(req_node_t * node, const char * buffer, size_t length) {
    w_mutex_lock(&node->mutex);
    free(node->buffer);
    os_malloc(length + 1, node->buffer);
    memcpy(node->buffer, buffer, length);
    node->buffer[length] = '\0';
    node->length = length;
    w_cond_signal(&node->available);
    w_mutex_unlock(&node->mutex);
}

// Free node
void req_free(req_node_t * node) {
    if (node) {
#ifndef WIN32
        if (node->sock >= 0) {
            close(node->sock);
        }
#endif
        free(node->target);
        free(node->buffer);
        free(node->counter);
        pthread_mutex_destroy(&node->mutex);
        pthread_cond_destroy(&node->available);
        free(node);
    }
}
