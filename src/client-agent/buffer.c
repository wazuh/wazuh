/*
 * Anti-flooding mechanism
 * Copyright (C) 2015-2019, Wazuh Inc.
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

static volatile int i = 0;
static volatile int j = 0;
static volatile int state = NORMAL;

int ms_slept;

struct{
  unsigned int full:1;
  unsigned int warn:1;
  unsigned int flood:1;
  unsigned int normal:1;
} buff;

static char ** buffer;
static pthread_mutex_t mutex_lock;
static pthread_cond_t cond_no_empty;

static time_t start, end;

static void delay(unsigned int ms);

/* Create agent buffer */
void buffer_init(){

    if (!buffer)
        os_calloc(agt->buflength+1, sizeof(char *), buffer);

    w_mutex_init(&mutex_lock, NULL);
    w_cond_init(&cond_no_empty, NULL);

    if (agt->tolerance == 0)
        mwarn(TOLERANCE_TIME);

    mdebug1("Agent buffer created.");
}
/* Send messages to buffer. */
int buffer_append(const char *msg){

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
            if (end - start >= agt->tolerance){
                state = FLOOD;
                buff.flood = 1;
            }
            break;

        case FLOOD:
            break;
    }

    agent_state.msg_count++;

    /* When buffer is full, event is dropped */

    if (full(i, j, agt->buflength + 1)){

        w_mutex_unlock(&mutex_lock);
        mdebug2("Unable to store new packet: Buffer is full.");
        return(-1);

    }else{

        buffer[i] = strdup(msg);
        forward(i, agt->buflength + 1);
        w_cond_signal(&cond_no_empty);
        w_mutex_unlock(&mutex_lock);

        return(0);
    }
}

/* Send messages from buffer to the server */
void *dispatch_buffer(__attribute__((unused)) void * arg){

    char flood_msg[OS_MAXSTR];
    char full_msg[OS_MAXSTR];
    char warn_msg[OS_MAXSTR];
    char normal_msg[OS_MAXSTR];

    char warn_str[OS_SIZE_2048];
    int wait_ms = 1000 / agt->events_persec;

    while(1){
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

        char * msg_output = buffer[j];
        forward(j, agt->buflength + 1);
        w_mutex_unlock(&mutex_lock);

        if (buff.warn){

            buff.warn = 0;
            mwarn(WARN_BUFFER, agt->warn_level);
            snprintf(warn_str, OS_SIZE_2048, OS_WARN_BUFFER, agt->warn_level);
            snprintf(warn_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "ossec-agent", warn_str);
            delay(wait_ms);
            send_msg(warn_msg, -1);
        }

        if (buff.full){

            buff.full = 0;
            mwarn(FULL_BUFFER);
            snprintf(full_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "ossec-agent", OS_FULL_BUFFER);
            delay(wait_ms);
            send_msg(full_msg, -1);
        }

        if (buff.flood){

            buff.flood = 0;
            mwarn(FLOODED_BUFFER);
            snprintf(flood_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "ossec-agent", OS_FLOOD_BUFFER);
            delay(wait_ms);
            send_msg(flood_msg, -1);
        }

        if (buff.normal){

            buff.normal = 0;
            minfo(NORMAL_BUFFER, agt->normal_level);
            snprintf(normal_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "ossec-agent", OS_NORMAL_BUFFER);
            delay(wait_ms);
            send_msg(normal_msg, -1);
        }

        delay(wait_ms);
        os_wait();
        send_msg(msg_output, -1);
        free(msg_output);
    }
}

void delay(unsigned int ms) {
#ifdef WIN32
    Sleep(ms);
#else
    struct timeval timeout = { 0, ms * 1000 };
    select(0 , NULL, NULL, NULL, &timeout);
#endif

    ms_slept += ms;
}
