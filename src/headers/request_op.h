/* Remote request structure
 * Copyright (C) 2015-2019, Wazuh Inc.
 * May 31, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef REQUEST_OP_H
#define REQUEST_OP_H

#define REQ_RESPONSE_LENGTH 64
#define SOCKET_LOGCOLLECTOR "logcollector"
#define SOCKET_SYSCHECK "syscheck"
#define SOCKET_WMODULES "wmodules"
#define SOCKET_AGENT "agent"

typedef struct req_node_t {
    int sock;
    char *counter;
    char *target;
    char *buffer;
    size_t length;
    pthread_mutex_t mutex;
    pthread_cond_t available;
} req_node_t;

// Create node
req_node_t * req_create(int sock, const char * counter, const char * target, const char * buffer, size_t length);

// Update node and signal available. It locks mutex.
void req_update(req_node_t * node, const char * buffer, size_t length);

// Free node
void req_free(req_node_t * node);

#endif
