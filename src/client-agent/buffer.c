/*
 * Anti-flooding mechanism
 * Copyright (C) 2015, Wazuh Inc.
 * July 4, 2017
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include <pthread.h>
#include "shared.h"
#include "agentd.h"

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

STATIC volatile int i = 0;
STATIC volatile int j = 0;
static volatile int state = NORMAL;

int warn_level;
int normal_level;
int tolerance;

struct{
  unsigned int full:1;
  unsigned int warn:1;
  unsigned int flood:1;
  unsigned int normal:1;
} buff;

/**
 * @brief Represents a single message stored in the event buffer.
 *
 * This structure is used to hold a message that can be either a null-terminated
 * text string or a raw binary data buffer. It pairs a pointer to the data with
 * its explicit size, allowing the system to handle binary content safely
 * without truncation at null bytes.
 */
typedef struct {
    /** @brief Pointer to the dynamically allocated message data. */
    void *data;

    /** @brief The exact size of the data in bytes. */
    size_t size;
} buffered_message;

/**
 * @brief The agent's main event buffer.
 */
static buffered_message *buffer;

static pthread_mutex_t mutex_lock;
static pthread_cond_t cond_no_empty;

static time_t start, end;

/**
 * @brief Sleep according to max_eps parameter
 *
 * Sleep (1 / max_eps) - ts_loop
 *
 * @param ts_loop Loop time.
 */
static void delay(struct timespec * ts_loop);

/* Create agent buffer */
void buffer_init(){

    if (!buffer) {
        os_calloc(agt->buflength + 1, sizeof(buffered_message), buffer);
    }

    /* Read internal configuration */
    warn_level = getDefine_Int("agent", "warn_level", 1, 100);
    normal_level = getDefine_Int("agent", "normal_level", 0, warn_level-1);
    tolerance = getDefine_Int("agent", "tolerance", 0, 600);

    w_mutex_init(&mutex_lock, NULL);
    w_cond_init(&cond_no_empty, NULL);

    if (tolerance == 0)
        mwarn(TOLERANCE_TIME);

    mdebug1("Agent buffer created.");
}

/* Send messages to buffer. */
int buffer_append(const char *msg, ssize_t msg_len) {

    w_mutex_lock(&mutex_lock);

    /* Check if buffer usage reaches any higher level */
    switch (state) {

        case NORMAL:
            if (full(i, j, agt->buflength + 1)){
                buff.full = 1;
                state = FULL;
                start = time(0);
            }else if (warn(i, j)){
                state = WARNING;
                buff.warn = 1;
            }
            break;

        case WARNING:
            if (full(i, j, agt->buflength + 1)){
                buff.full = 1;
                state = FULL;
                start = time(0);
            }
            break;

        case FULL:
            end = time(0);
            if (end - start >= tolerance){
                state = FLOOD;
                buff.flood = 1;
            }
            break;

        case FLOOD:
            break;
    }

    w_agentd_state_update(INCREMENT_MSG_COUNT, NULL);

    /* When buffer is full, event is dropped */

    if (full(i, j, agt->buflength + 1)){

        w_mutex_unlock(&mutex_lock);
        mdebug2("Unable to store new packet: Buffer is full.");
        return(-1);

    }else{

        size_t size_to_alloc;
        if (msg_len < 0) { // It's a null-terminated string.
            size_to_alloc = strlen(msg) + 1;
        } else { // It's a binary buffer with a known length.
            size_to_alloc = (size_t)msg_len;
        }

        os_malloc(size_to_alloc, buffer[i].data);
        memcpy(buffer[i].data, msg, size_to_alloc);
        buffer[i].size = size_to_alloc;

        forward(i, agt->buflength + 1);
        w_cond_signal(&cond_no_empty);
        w_mutex_unlock(&mutex_lock);

        return(0);
    }
}

/* Send messages from buffer to the server */
#ifdef WIN32
DWORD WINAPI dispatch_buffer(__attribute__((unused)) LPVOID arg) {
#else
void *dispatch_buffer(__attribute__((unused)) void * arg){
#endif
    char flood_msg[OS_MAXSTR];
    char full_msg[OS_MAXSTR];
    char warn_msg[OS_MAXSTR];
    char normal_msg[OS_MAXSTR];

    char warn_str[OS_SIZE_2048];
    struct timespec ts0;
    struct timespec ts1;

    while(1){
        gettime(&ts0);

        w_mutex_lock(&mutex_lock);

        while(empty(i, j)){
            w_cond_wait(&cond_no_empty, &mutex_lock);
        }
        /* Check if buffer usage reaches any lower level */
        switch (state) {

            case NORMAL:
                break;

            case WARNING:
                if (normal(i, j)){
                    state = NORMAL;
                    buff.normal = 1;
                }
                break;

            case FULL:
                if (nowarn(i, j))
                    state = WARNING;

                if (normal(i, j)){
                    state = NORMAL;
                    buff.normal = 1;
                }
                break;

            case FLOOD:
                if (nowarn(i, j))
                    state = WARNING;

                if (normal(i, j)){
                    state = NORMAL;
                    buff.normal = 1;
                }
                break;
        }

        buffered_message msg_to_dispatch = buffer[j];
        forward(j, agt->buflength + 1);
        w_mutex_unlock(&mutex_lock);

        if (buff.warn){

            buff.warn = 0;
            mwarn(WARN_BUFFER, warn_level);
            snprintf(warn_str, OS_SIZE_2048, OS_WARN_BUFFER, warn_level);
            snprintf(warn_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", warn_str);
            send_msg(warn_msg, -1);
        }

        if (buff.full){

            buff.full = 0;
            mwarn(FULL_BUFFER);
            snprintf(full_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", OS_FULL_BUFFER);
            send_msg(full_msg, -1);
        }

        if (buff.flood){

            buff.flood = 0;
            mwarn(FLOODED_BUFFER);
            snprintf(flood_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", OS_FLOOD_BUFFER);
            send_msg(flood_msg, -1);
        }

        if (buff.normal){

            buff.normal = 0;
            minfo(NORMAL_BUFFER, normal_level);
            snprintf(normal_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", OS_NORMAL_BUFFER);
            send_msg(normal_msg, -1);
        }

        os_wait();
        send_msg(msg_to_dispatch.data, msg_to_dispatch.size);
        os_free(msg_to_dispatch.data);

        gettime(&ts1);
        time_sub(&ts1, &ts0);

        if (ts1.tv_sec >= 0) {
            delay(&ts1);
        }
    }
}

void delay(struct timespec * ts_loop) {
    long interval_ns = 1000000000 / agt->events_persec;
    struct timespec ts_timeout = { interval_ns / 1000000000, interval_ns % 1000000000 };
    time_sub(&ts_timeout, ts_loop);

    if (ts_timeout.tv_sec >= 0) {
        nanosleep(&ts_timeout, NULL);
    }
}

int w_agentd_get_buffer_lenght() {

    int retval = -1;

    if (agt->buffer > 0) {
        w_mutex_lock(&mutex_lock);
        retval = (i - j) % (agt->buflength + 1);
        w_mutex_unlock(&mutex_lock);

        retval = (retval < 0) ? (retval + agt->buflength + 1) : retval;
    }

    return retval;
}
