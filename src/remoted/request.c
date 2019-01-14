/* Remote request listener
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
#include <os_net/os_net.h>
#include <request_op.h>
#include "remoted.h"
#include "wazuh_modules/wmodules.h"

#define COUNTER_LENGTH 64

// Dispatcher theads entry point
static void * req_dispatch(req_node_t * node);

// Increment request pool
static void req_pool_post();

// Wait for available pool. Returns 1 on success or 0 on error
static int req_pool_wait();

static const char * WR_INTERNAL_ERROR = "err Internal error";
static const char * WR_SEND_ERROR = "err Cannot send request";
static const char * WR_ATTEMPT_ERROR = "err Maximum attempts exceeded";
static const char * WR_TIMEOUT_ERROR = "err Response timeout";

static OSHash * req_table;
static pthread_mutex_t mutex_table = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mutex_pool = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pool_available = PTHREAD_COND_INITIALIZER;
int rto_sec;
int rto_msec;
int max_attempts;
int request_pool;
int request_timeout;
int response_timeout;
int guess_agent_group;

// Request listener thread entry point
void * req_main(__attribute__((unused)) void * arg) {
    int sock;
    int error;
    unsigned int counter = (unsigned int)os_random();
    char counter_s[COUNTER_LENGTH];
    req_node_t * node;
    const char * path = isChroot() ? REMOTE_REQ_SOCK : DEFAULTDIR REMOTE_REQ_SOCK;

    mdebug1("Running request listener thread.");

    // Get values from internal options

    request_pool = getDefine_Int("remoted", "request_pool", 1, 4096);
    request_timeout = getDefine_Int("remoted", "request_timeout", 1, 600);
    response_timeout = getDefine_Int("remoted", "response_timeout", 1, 3600);
    rto_sec = getDefine_Int("remoted", "request_rto_sec", 0, 60);
    rto_msec = getDefine_Int("remoted", "request_rto_msec", 0, 999);
    max_attempts = getDefine_Int("remoted", "max_attempts", 1, 16);
    guess_agent_group = getDefine_Int("remoted", "guess_agent_group", 0, 1);

    // Create hash table

    if (req_table = OSHash_Create(), !req_table) {
        merror_exit("At req_main(): OSHash_Create()");
    }

    // Create socket

    if (sock = OS_BindUnixDomain(path, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror("Unable to bind to socket '%s': %s", path, strerror(errno));
        return NULL;
    }

    while (1) {
        int peer;
        ssize_t length;
        char *buffer = NULL;

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

        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        switch (length = OS_RecvSecureTCP(peer, buffer,OS_MAXSTR), length) {
        case -1:
            merror("OS_RecvSecureTCP(): %s", strerror(errno));
            free(buffer);
            break;

        case 0:
            mdebug1("Empty message from local client.");
            free(buffer);
            break;

        default:
            buffer[length] = '\0';
            const char* target = "";

            // Set counter, create node and insert into hash table

            snprintf(counter_s, COUNTER_LENGTH, "%x", counter++);
            node = req_create(peer, counter_s, target, buffer, length);
            free(buffer);

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

                // Wait for thread pool

                if (!req_pool_wait()) {
                    break;
                }

                // Run thread
                w_create_thread(req_dispatch, node);

                // Do not close peer
                continue;
            }
        }

        // If we reached here, there was an error

        OS_SendSecureTCP(peer, strlen(WR_INTERNAL_ERROR), WR_INTERNAL_ERROR);
        close(peer);
    }

    return NULL;
}

// Dispatcher theads entry point
void * req_dispatch(req_node_t * node) {
    int attempts;
    int ploff;
    long nsec;
    size_t ldata;
    char * agentid = NULL;
    char * payload = NULL;
    char * _payload;
    char response[REQ_RESPONSE_LENGTH];
    char *output = NULL;
    struct timespec timeout;
    struct timeval now = { 0, 0 };

    mdebug2("Running request dispatcher thread. Counter=%s", node->counter);

    // Get agent ID and payload

    w_mutex_lock(&node->mutex);

    if (_payload = strchr(node->buffer, ' '), !_payload) {
        merror("Request has no agent id.");
        goto cleanup;
    }

    *_payload = '\0';
    _payload++;

    if (strcmp(node->buffer, "getconfig") == 0) {

        node->length = rem_getconfig(_payload, &output);

        if (OS_SendSecureTCP(node->sock, node->length, output) != 0) {
            merror("At req_dispatch(): OS_SendSecureTCP(): %s", strerror(errno));
            goto cleanup;
        }
    }
    else {

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

        mdebug2("Sending request: '%s'", payload);

        for (attempts = 0; attempts < max_attempts; attempts++) {

            // Try to send message

            if (send_msg(agentid, payload, ldata)) {
                mwarn("Sending request to agent '%s'.", agentid);

                if (OS_SendSecureTCP(node->sock, strlen(WR_SEND_ERROR), WR_SEND_ERROR) < 0) {
                    mwarn("Couldn't report sending error to client.");
                }
                goto cleanup;
            }

            // Wait for ACK or response, only in UDP mode

            if (logr.proto[logr.position] == UDP_PROTO) {
                gettimeofday(&now, NULL);
                nsec = now.tv_usec * 1000 + rto_msec * 1000000;
                timeout.tv_sec = now.tv_sec + rto_sec + nsec / 1000000000;
                timeout.tv_nsec = nsec % 1000000000;

                if (pthread_cond_timedwait(&node->available, &node->mutex, &timeout) == 0 && node->buffer) {
                    break;
                }
            } else {
                // TCP handles ACK by itself
                break;
            }

            mdebug2("Timeout for waiting ACK from agent '%s', resending.", agentid);
        }

        if (attempts == max_attempts) {
            merror("Couldn't send request to agent '%s': number of attempts exceeded.", agentid);

            if (OS_SendSecureTCP(node->sock, strlen(WR_ATTEMPT_ERROR), WR_ATTEMPT_ERROR) < 0) {
                mwarn("Couldn't report error about number of attempts exceeded to client.");
            }

            goto cleanup;
        }

        // If buffer is ACK, wait for response

        for (attempts = 0; attempts < max_attempts && (!node->buffer || IS_ACK(node->buffer)); attempts++) {
            gettimeofday(&now, NULL);
            timeout.tv_sec = now.tv_sec + response_timeout;
            timeout.tv_nsec = now.tv_usec * 1000;

            if (pthread_cond_timedwait(&node->available, &node->mutex, &timeout) == 0) {
                continue;
            } else {
                merror("Response timeout for request counter '%s'.", node->counter);
                OS_SendSecureTCP(node->sock, strlen(WR_TIMEOUT_ERROR), WR_TIMEOUT_ERROR);
                goto cleanup;
            }
        }

        if (attempts == max_attempts) {
            merror("Couldn't get response from agent '%s': number of attempts exceeded.", agentid);
            OS_SendSecureTCP(node->sock, strlen(WR_ATTEMPT_ERROR), WR_ATTEMPT_ERROR);
            goto cleanup;
        }

        // Send ACK, only in UDP mode

        if (logr.proto[logr.position] == UDP_PROTO) {
            // Example: #!-req 16 ack
            mdebug2("req_dispatch(): Sending ack (%s).", node->counter);
            snprintf(response, REQ_RESPONSE_LENGTH, CONTROL_HEADER HC_REQUEST "%s ack", node->counter);
            send_msg(agentid, response, -1);
        }

        // Send response to local peer

        mdebug2("Sending response: '%s'", node->buffer);

        if (OS_SendSecureTCP(node->sock, node->length, node->buffer) != 0) {
            mwarn("At req_dispatch(): OS_SendSecureTCP(): %s", strerror(errno));
        }
    }

cleanup:

    // Clean up

    w_mutex_unlock(&node->mutex);
    w_mutex_lock(&mutex_table);

    if(output){
        free(output);
    }

    if (!OSHash_Delete(req_table, node->counter)) {
        merror("At req_dispatch(): OSHash_Delete(): no such key.");
    }

    w_mutex_unlock(&mutex_table);
    req_free(node);
    if (agentid) free(agentid);
    if (payload) free(payload);
    req_pool_post();
    return NULL;
}

// Save request data (ack or response). Return 0 on success or -1 on error.
int req_save(const char * counter, const char * buffer, size_t length) {
    req_node_t * node;
    int retval = 0;

    mdebug2("req_save(): Saving '%s:%s'", counter, buffer);

    w_mutex_lock(&mutex_table);

    if (node = OSHash_Get(req_table, counter), node) {
        req_update(node, buffer, length);
    } else {
        mdebug1("Request counter (%s) not found. Duplicated message?", counter);
        retval = -1;
    }

    w_mutex_unlock(&mutex_table);
    return retval;
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
    struct timespec timeout;
    struct timeval now = { 0, 0 };
    int wait_ok = 1;

    w_mutex_lock(&mutex_pool);

    while (!request_pool && wait_ok) {
        gettimeofday(&now, NULL);
        timeout.tv_sec = now.tv_sec + request_timeout;
        timeout.tv_nsec = now.tv_usec * 1000;

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


size_t rem_getconfig(const char * section, char ** output) {

    cJSON *cfg;
    char *json_str;

    if (strcmp(section, "remote") == 0){
        if (cfg = getRemoteConfig(), cfg) {
            *output = strdup("ok");
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_free(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "internal") == 0){
        if (cfg = getRemoteInternalConfig(), cfg) {
            *output = strdup("ok");
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_free(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else {
        goto error;
    }
error:
    merror("At request getconfig: Could not get '%s' section", section);
    *output = strdup("err Could not get requested section");
    return strlen(*output);
}
