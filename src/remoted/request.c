/* Remote request listener
 * Copyright (C) 2017 Wazuh Inc.
 * May 31, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <pthread.h>
#include <shared.h>
#include <os_net/os_net.h>
#include <request_op.h>
#include "remoted.h"

#define COUNTER_LENGTH 64

// Dispatcher theads entry point
static void * req_dispath(req_node_t * node);

// Increment request pool
static void req_pool_post();

// Wait for available pool. Returns 1 on success or 0 on error
static int req_pool_wait();

static OSHash * req_table;
static pthread_mutex_t mutex_table = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mutex_pool = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pool_available = PTHREAD_COND_INITIALIZER;
static int rto_sec;
static int rto_usec;
static int max_attempts;
static int request_pool;
static int request_timeout;
static int response_timeout;

// Request listener thread entry point
void * req_main(__attribute__((unused)) void * arg) {
    int sock;
    int error;
    int request_timeout;
    unsigned int counter = (unsigned int)os_random();
    char counter_s[COUNTER_LENGTH];
    req_node_t * node;

    mdebug1("Running request listener thread.");

    // Get values from internal options

    request_pool = getDefine_Int("remoted", "request_pool", 1, 64);
    request_timeout = getDefine_Int("remoted", "request_timeout", 1, 600);
    response_timeout = getDefine_Int("remoted", "response_timeout", 1, 3600);
    rto_sec = getDefine_Int("remoted", "request_rto_sec", 0, 60);
    rto_usec = getDefine_Int("remoted", "request_rto_usec", 0, 999999);
    max_attempts = getDefine_Int("remoted", "max_attempts", 1, 16);

    // Create hash table

    if (req_table = OSHash_Create(), !req_table) {
        merror_exit("At req_main(): OSHash_Create()");
    }

    // Create socket

    if (sock = OS_BindUnixDomain(REMOTE_REQ_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror("Unable to bind to socket '%s': %s", REMOTE_REQ_SOCK, strerror(errno));
        return NULL;
    }

    while (1) {
        int peer;
        int granted = 0;
        ssize_t length;
        char buffer[OS_MAXSTR + 1];

        // Wait for socket

        {
            fd_set fdset;
            struct timeval timeout = { request_timeout, 0 };

            FD_ZERO(&fdset);
            FD_SET(sock, &fdset);

            switch (select(sock + 1, &fdset, NULL, NULL, &timeout)) {
            case -1:
                if (errno != EINTR) {
                    merror("At req_main(): select(): %s", strerror(errno));
                    close(sock);
                    return NULL;
                }

                continue;

            case 0:
                continue;
            }
        }

        // Accept connection and fork

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                merror("At req_main(): accept(): %s", strerror(errno));
            }

            continue;
        }

        // Get request string

        switch (length = recv(peer, buffer, OS_MAXSTR, 0), length) {
        case -1:
            merror("recv(): %s", strerror(errno));
            break;

        case 0:
            mdebug1("Empty message from local client.");
            break;

        default:
            buffer[length] = '\0';

            // Wait for thread pool

            if (granted = req_pool_wait(), !granted) {
                break;
            }

            // Set counter, create node and insert into hash table

            snprintf(counter_s, COUNTER_LENGTH, "%x", counter++);
            node = req_create(peer, counter_s, buffer, length);

            w_mutex_lock(&mutex_table);
            error = OSHash_Add(req_table, counter_s, node);
            w_mutex_unlock(&mutex_table);

            switch (error) {
            case 0:
                merror("At req_main(): OSHash_Add()");
                req_free(node);
                break;

            case 1:
                merror("At req_main(): Duplicated counter.");
                req_free(node);
                break;

            case 2:
                // Run thread
                w_create_thread(req_dispath, node);
            }

            // Do not close peer
            continue;
        }

        // If we reached here, there was an error

        // If request pool was decremented, reset it

        if (granted) {
            req_pool_post();
        }

        close(peer);
    }

    return NULL;
}

// Dispatcher theads entry point
void * req_dispath(req_node_t * node) {
    int attempts;
    int ploff;
    size_t ldata;
    char * agentid = NULL;
    char * payload = NULL;
    char * _payload;
    char response[REQ_RESPONSE_LENGTH];

    mdebug2("Running request dispatcher thread. Counter=%s", node->counter);

    // Get agent ID and payload

    w_mutex_lock(&node->mutex);

    if (_payload = strchr(node->buffer, ' '), !_payload) {
        merror("Request has no agent id.");
        w_mutex_unlock(&node->mutex);
        goto cleanup;
    }

    *_payload = '\0';
    _payload++;

    os_strdup(node->buffer, agentid);
    ldata = strlen(CONTROL_HEADER) + strlen(HC_REQUEST) + strlen(node->counter) + 1 + node->length - (_payload - node->buffer);
    os_malloc(ldata + 1, payload);
    ploff = snprintf(payload, ldata, CONTROL_HEADER HC_REQUEST "%s ", node->counter);
    memcpy(payload + ploff, _payload, ldata - ploff);
    payload[ldata] = '\0';

    // Drain payload

    free(node->buffer);
    node->buffer = NULL;
    node->length = 0;

    w_mutex_unlock(&node->mutex);
    mdebug2("Sending request: '%s'", payload);

    for (attempts = 0; attempts < max_attempts; attempts++) {
        struct timespec timeout = { response_timeout, 0 };

        // Try to send message

        if (send_msg(agentid, payload, ldata)) {
            merror("Sending request to agent '%s'.", agentid);
            goto cleanup;
        }

        // Wait for ACK or response

        w_mutex_lock(&node->mutex);

        if (node->buffer) {
            w_mutex_unlock(&node->mutex);
            break;
        } else {
            if (pthread_cond_timedwait(&node->available, &node->mutex, &timeout) == 0) {
                w_mutex_unlock(&node->mutex);
                continue;
            } else {
                w_mutex_unlock(&node->mutex);
            }
        }
    }

    if (attempts == max_attempts) {
        merror("Couldn't send request to agent '%s': number of attempts exceeded.", agentid);
        goto cleanup;
    }

    // If buffer is ACK, wait for response

    w_mutex_lock(&node->mutex);

    while (IS_ACK(node->buffer)) {
        w_cond_wait(&node->available, &node->mutex);
    }

    // Send ACK, only in UDP mode

    if (logr.proto[logr.position] == UDP_PROTO) {
        // Example: #!-req 16 ack
        snprintf(response, REQ_RESPONSE_LENGTH, CONTROL_HEADER HC_REQUEST "%s ack", node->counter);
        send_msg(agentid, response, -1);
    }

    w_mutex_unlock(&node->mutex);

    // At this point, no other thread should write on node

    // Send response to local peer

    if (send(node->sock, node->buffer, node->length, 0) != (ssize_t)node->length) {
        merror("send(): %s", strerror(errno));
    }

    // Clean up

cleanup:

    w_mutex_lock(&mutex_table);

    if (!OSHash_Delete(req_table, node->counter)) {
        merror("At req_dispatch(): OSHash_Delete(): no such key.");
    }

    w_mutex_unlock(&mutex_table);
    req_free(node);
    free(agentid);

    req_pool_post();

    return NULL;
}

// Save request data (ack or response). Return 0 on success or -1 on error.
int req_save(const char * counter, const char * buffer, size_t length) {
    req_node_t * node;

    w_mutex_lock(&mutex_table);
    node = OSHash_Get(req_table, counter);
    w_mutex_unlock(&mutex_table);

    if (!node) {
        mdebug1("Request counter (%s) not found. Duplicated message?", counter);
        return -1;
    }

    req_update(node, buffer, length);
    return 0;
}

// Increment request pool
void req_pool_post() {
    w_mutex_lock(&mutex_pool);
    request_pool++;
    w_cond_signal(&pool_available);
    w_mutex_unlock(&mutex_pool);
}

// Wait for available pool. Returns 1 on success or 0 on error
int req_pool_wait() {
    struct timespec timeout = { request_timeout, 0 };
    int wait_ok = 1;

    w_mutex_lock(&mutex_pool);

    while (!request_pool && wait_ok) {
        switch (pthread_cond_timedwait(&pool_available, &mutex_pool, &timeout)) {
        case 0:
            break;

        case ETIMEDOUT:
            merror("Request pool is full. Rejecting request.");
            wait_ok = 0;
            break;

        default:
            merror("At req_main(): w_cond_timedwait(): %s", strerror(errno));
            wait_ok = 0;
            break;
        }
    }

    if (request_pool) {
        request_pool--;
    }

    w_mutex_unlock(&mutex_pool);
    return wait_ok;
}
