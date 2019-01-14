/* Remote request manager
 * Copyright (C) 2015-2019, Wazuh Inc.
 * June 2, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "agentd.h"
#include <shared.h>
#include <pthread.h>
#include <request_op.h>
#include <os_net/os_net.h>

#ifdef WIN32
#include "../os_execd/execd.h"
#include "../client-agent/agentd.h"
#include "../syscheckd/syscheck.h"
#include "../wazuh_modules/wmodules.h"
#include "../logcollector/logcollector.h"
#endif

static OSHash * req_table;
static req_node_t ** req_pool;
static volatile int pool_i = 0;
static volatile int pool_j = 0;

static pthread_mutex_t mutex_table = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mutex_pool = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pool_available = PTHREAD_COND_INITIALIZER;

int request_pool;
int rto_sec;
int rto_msec;
int max_attempts;

static OSHash * allowed_sockets;

// Initialize request module
void req_init() {
    int success = 0;
    char *socket_log = NULL;
    char *socket_sys = NULL;
    char *socket_wodle = NULL;
    char *socket_agent = NULL;
    
    // Get values from internal options

    request_pool = getDefine_Int("remoted", "request_pool", 1, 4096);
    rto_sec = getDefine_Int("remoted", "request_rto_sec", 0, 60);
    rto_msec = getDefine_Int("remoted", "request_rto_msec", 0, 999);
    max_attempts = getDefine_Int("remoted", "max_attempts", 1, 16);

    // Create hash table and request pool

    if (req_table = OSHash_Create(), !req_table) {
        merror_exit("At req_main(): OSHash_Create()");
    }
    OSHash_SetFreeDataPointer(req_table, (void (*)(void *))req_free);

    os_calloc(request_pool, sizeof(req_node_t *), req_pool);

    // Create hash table allowed sockets

    if (allowed_sockets = OSHash_Create(), !allowed_sockets) {
        merror("At req_main(): OSHash_Create()");
        goto ret;
    }
    
    socket_log = strdup(SOCKET_LOGCOLLECTOR);
    socket_sys = strdup(SOCKET_SYSCHECK);
    socket_wodle = strdup(SOCKET_WMODULES);
    socket_agent = strdup(SOCKET_AGENT);
    
    if (!socket_log || !socket_sys || !socket_wodle || !socket_agent) {
        merror("At req_main(): failed to allocate socket strings");
        goto ret;
    }
    
    if (OSHash_Add(allowed_sockets, SOCKET_LOGCOLLECTOR, socket_log) != 2 || OSHash_Add(allowed_sockets, SOCKET_SYSCHECK, socket_sys) != 2 || \
    OSHash_Add(allowed_sockets, SOCKET_WMODULES, socket_wodle) != 2 || OSHash_Add(allowed_sockets, SOCKET_AGENT, socket_agent) != 2) {
        merror("At req_main(): failed to add socket strings to hash list");
        goto ret;
    }
    
    success = 1;
    
ret:
    if (!success) {
        if (req_pool) free(req_pool);
        if (allowed_sockets) OSHash_Free(allowed_sockets);
        if (req_table) OSHash_Free(req_table);
        if (socket_log) free(socket_log);
        if (socket_sys) free(socket_sys);
        if (socket_wodle) free(socket_wodle);
        if (socket_agent) free(socket_agent);
        exit(1);
    }
}

// Push a request message into dispatching queue. Return 0 on success or -1 on error.
int req_push(char * buffer, size_t length) {
    char * counter;
    char * target;
    char * payload;
    char response[REQ_RESPONSE_LENGTH];
    int sock = -1;
    int error;
    req_node_t * node;

    counter = buffer;

    if (target = strchr(counter, ' '), !target) {
        merror("Request format is incorrect [target].");
        mdebug2("buffer = \"%s\"", buffer);
        return -1;
    }

    *(target++) = '\0';

    if (IS_ACK(target)) {
        w_mutex_lock(&mutex_table);

        if (node = OSHash_Get(req_table, counter), node) {
            req_update(node, target, length);
        } else {
            mdebug1("Request counter (%s) not found. Duplicated ACK?", counter);
        }

        w_mutex_unlock(&mutex_table);
    } else {
        if (payload = strchr(target, ' '), !payload) {
            merror("Request format is incorrect [payload].");
            mdebug2("target = \"%s\"", target);
            return -1;
        }

        *(payload++) = '\0';
        length -= (payload - buffer);

#ifndef WIN32

        if (strcmp(target, "agent")) {
            char sockname[PATH_MAX];
            snprintf(sockname, PATH_MAX, "/queue/ossec/%s", target);

            if (sock = OS_ConnectUnixDomain(sockname, SOCK_STREAM, OS_MAXSTR), sock < 0) {
                switch (errno) {
                case ECONNREFUSED:
                    merror("At req_push(): Target '%s' refused connection. The component might be disabled", target);
                    break;

                default:
                    merror("At req_push(): Could not connect to socket '%s': %s (%d).", target, strerror(errno), errno);
                }

                // Example: #!-req 16 err Permission denied
                snprintf(response, REQ_RESPONSE_LENGTH, CONTROL_HEADER HC_REQUEST "%s err %s", counter, strerror(errno));
                send_msg(response, -1);

                return -1;
            }
        }

#endif

        // Send ACK, only in UDP mode

        if (agt->server[agt->rip_id].protocol == UDP_PROTO) {
            mdebug2("req_push(): Sending ack (%s).", counter);
            // Example: #!-req 16 ack
            snprintf(response, REQ_RESPONSE_LENGTH, CONTROL_HEADER HC_REQUEST "%s ack", counter);
            send_msg(response, -1);
        }

        // Create and insert node
        node = req_create(sock, counter, target, payload, length);
        w_mutex_lock(&mutex_table);
        error = OSHash_Add(req_table, counter, node);
        w_mutex_unlock(&mutex_table);

        switch (error) {
        case 0:
            merror("At req_push(): OSHash_Add()");
            snprintf(response, REQ_RESPONSE_LENGTH, CONTROL_HEADER HC_REQUEST "%s err Internal error", counter);
            send_msg(response, -1);
            req_free(node);
            return -1;

        case 1:
            mdebug1("Duplicated counter. RTO too short?");
            req_free(node);
            return 0;

        case 2:
            w_mutex_lock(&mutex_pool);

            if (full(pool_i, pool_j, request_pool)) {
                merror("Too many requests. Rejecting counter %s.", counter);
                w_mutex_unlock(&mutex_pool);

                // Delete node from hash table
                w_mutex_lock(&mutex_table);
                OSHash_Delete(req_table, counter);
                w_mutex_unlock(&mutex_table);

                req_free(node);
                return -1;
            } else {
                req_pool[pool_i] = node;
                forward(pool_i, request_pool);
                w_cond_signal(&pool_available);
            }

            w_mutex_unlock(&mutex_pool);
        }
    }

    return 0;
}

// Request receiver thread start
void * req_receiver(__attribute__((unused)) void * arg) {
    int attempts;
    long nsec;
    ssize_t length = 0;
    req_node_t * node;
    char *buffer = NULL;
    char response[REQ_RESPONSE_LENGTH];
    int rlen;



    while (1) {

        // Get next node from queue

        w_mutex_lock(&mutex_pool);

        while (empty(pool_i, pool_j)) {
            w_cond_wait(&pool_available, &mutex_pool);
        }

        node = req_pool[pool_j];
        forward(pool_j, request_pool);
        w_mutex_unlock(&mutex_pool);

        w_mutex_lock(&node->mutex);
#ifdef WIN32
        // In Windows, forward request to target socket
        if (strncmp(node->target, "agent", 5) == 0) {
            length = agcom_dispatch(node->buffer, &buffer);
        } else if (strncmp(node->target, "logcollector", 12) == 0) {
            length = lccom_dispatch(node->buffer, &buffer);
        } else if (strncmp(node->target, "com", 3) == 0) {
            length = wcom_dispatch(node->buffer, node->length, &buffer);
        } else if (strncmp(node->target, "syscheck", 8) == 0) {
            length = syscom_dispatch(node->buffer, &buffer);
        } else if (strncmp(node->target, "wmodules", 8) == 0) {
            length = wmcom_dispatch(node->buffer, &buffer);
        } else {
            os_strdup("err Could not get requested section", buffer);
            length = strlen(buffer);
        }
#else
        // In Unix, forward request to target socket
        if (strncmp(node->target, "agent", 5) == 0) {
            length = agcom_dispatch(node->buffer, &buffer);
        }
        else {
            os_calloc(OS_MAXSTR, sizeof(char), buffer);
            mdebug2("req_receiver(): sending '%s' to socket", node->buffer);

            // Send data
            if (OS_SendSecureTCP(node->sock, node->length, node->buffer) != 0) {
                merror("OS_SendSecureTCP(): %s", strerror(errno));
                strcpy(buffer,"err Send data");
                length = strlen(buffer);
            } else {

                // Get response

                switch (length = OS_RecvSecureTCP(node->sock, buffer,OS_MAXSTR), length) {
                case -1:
                    merror("recv(): %s", strerror(errno));
                    strcpy(buffer,"err Receive data");
                    length = strlen(buffer);
                    break;

                case 0:
                    mdebug1("Empty message from local client.");
                    strcpy(buffer,"err Empty response");
                    length = strlen(buffer);
                    break;

                case OS_SOCKTERR:
                    mdebug1("Maximum buffer length reached.");
                    strcpy(buffer,"err Maximum buffer length reached");
                    length = strlen(buffer);
                    break;

                default:
                    buffer[length] = '\0';
                }
            }
        }

#endif
        if (length <= 0) {
            // Build error string
            strcpy(buffer,"err Disconnected");
            length = strlen(buffer);
        }

        // Build response string
        // Example: #!-req 16 Hello World
        rlen = snprintf(response, REQ_RESPONSE_LENGTH, CONTROL_HEADER HC_REQUEST "%s ", node->counter);
        length += rlen;
        os_realloc(buffer, length + 1, buffer);
        memmove(buffer + rlen, buffer, length - rlen);
        memcpy(buffer, response, rlen);
        buffer[length] = '\0';


        mdebug2("req_receiver(): sending '%s' to server", buffer);

        for (attempts = 0; attempts < max_attempts; attempts++) {
            struct timespec timeout;
            struct timeval now = { 0, 0 };

            // Try to send message

            if (send_msg(buffer, length)) {
                merror("Sending response to manager.");
                break;
            }

            // Wait for ACK, only in UDP mode

            if (agt->server[agt->rip_id].protocol == UDP_PROTO) {
                gettimeofday(&now, NULL);
                nsec = now.tv_usec * 1000 + rto_msec * 1000000;
                timeout.tv_sec = now.tv_sec + rto_sec + nsec / 1000000000;
                timeout.tv_nsec = nsec % 1000000000;

                if (pthread_cond_timedwait(&node->available, &node->mutex, &timeout) == 0 && IS_ACK(node->buffer)) {
                    break;
                }
            } else {
                // TCP handles ACK by itself
                break;
            }

            mdebug2("Timeout for waiting ACK from manager, resending.");
        }

        if (attempts == max_attempts) {
            merror("Couldn't send response to manager: number of attempts exceeded.");
        }

        w_mutex_unlock(&node->mutex);

        // Delete node from hash table
        w_mutex_lock(&mutex_table);
        OSHash_Delete(req_table, node->counter);
        w_mutex_unlock(&mutex_table);

        // Delete node
        free(buffer);
        req_free(node);
    }


    return NULL;
}
