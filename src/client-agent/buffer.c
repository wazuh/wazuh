/*
 * Anti-flooding mechanism
 * Copyright (C) 2017 Wazuh Inc.
 * July 4, 2017
 *
 * This program is a free software; you can redistribute it
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

static int warn_level;
static int normal_level;
static int tolerance;

struct{
  unsigned int full:1;
  unsigned int warn:1;
  unsigned int flood:1;
  unsigned int normal:1;
} buff;

char ** buffer;
pthread_mutex_t mutex_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_no_empty = PTHREAD_COND_INITIALIZER;

time_t start, end;

/* Create agent buffer */
void buffer_init(){

    if (!buffer)
        os_calloc(agt->buflength+1, sizeof(char *), buffer);

    warn_level = getDefine_Int("agent", "warn_level", 1, 100);
    normal_level = getDefine_Int("agent", "normal_level", 0, warn_level-1);
    tolerance = getDefine_Int("agent", "tolerance", 0, 600);

    if (tolerance == 0)
        mwarn(TOLERANCE_TIME);

}

/* Send messages to buffer. */
int buffer_append(const char *msg){

    pthread_mutex_lock(&mutex_lock);

    switch (state) {

        case NORMAL:
            if (full(i, j)){
                buff.full = 1;
                state = FULL;
                start = time(0);
            }else if (warn(i, j)){
                state = WARNING;
                buff.warn = 1;
            }
            break;

        case WARNING:
            if (full(i, j)){
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

    if (full(i, j)){

        pthread_mutex_unlock(&mutex_lock);
        mdebug2("Unable to store new packet: Buffer is full.");
        return(-1);

    }else{

        buffer[i] = strdup(msg);
        forward(i);
        pthread_cond_signal(&cond_no_empty);
        pthread_mutex_unlock(&mutex_lock);

        return(0);
    }
}

/* Send messages from buffer to the server */
void *dispatch_buffer(__attribute__((unused)) void * arg){

    char flood_msg[OS_MAXSTR];
    char full_msg[OS_MAXSTR];
    char warn_msg[OS_MAXSTR];
    char normal_msg[OS_MAXSTR];

    char warn_str[OS_MAXSTR];

    while(1){

  #ifdef WIN32
        int time_wait = 1000 / (agt->events_persec);
  #else
        int usec = 1000000 / (agt->events_persec);
        struct timeval timeout = {0, usec};
  #endif

        pthread_mutex_lock(&mutex_lock);

        while(empty(i, j)){
            mdebug2("Agent buffer empty.");
            pthread_cond_wait(&cond_no_empty, &mutex_lock);
        }

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
        forward(j);
        pthread_mutex_unlock(&mutex_lock);

        if (buff.warn){

            buff.warn = 0;
            mwarn(WARN_BUFFER, warn_level);
            snprintf(warn_str, OS_MAXSTR, OS_WARN_BUFFER, warn_level);
            snprintf(warn_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "ossec", warn_str);
    #ifdef WIN32
            Sleep(time_wait);
    #else
            select(0 , NULL, NULL, NULL, &timeout);
    #endif
            send_msg(0, warn_msg);
        }

        if (buff.full){

            buff.full = 0;
            mwarn(FULL_BUFFER);
            snprintf(full_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "ossec", OS_FULL_BUFFER);
    #ifdef WIN32
            Sleep(time_wait);
    #else
            select(0 , NULL, NULL, NULL, &timeout);
    #endif
            send_msg(0, full_msg);
        }

        if (buff.flood){

            buff.flood = 0;
            mwarn(FLOODED_BUFFER);
            snprintf(flood_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "ossec", OS_FLOOD_BUFFER);
    #ifdef WIN32
            Sleep(time_wait);
    #else
            select(0 , NULL, NULL, NULL, &timeout);
    #endif
            send_msg(0, flood_msg);
        }

        if (buff.normal){

            buff.normal = 0;
            minfo(NORMAL_BUFFER, normal_level);
            snprintf(normal_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "ossec", OS_NORMAL_BUFFER);
    #ifdef WIN32
            Sleep(time_wait);
    #else
            select(0 , NULL, NULL, NULL, &timeout);
    #endif
            send_msg(0, normal_msg);
        }

#ifdef WIN32
        Sleep(time_wait);
#else
        select(0 , NULL, NULL, NULL, &timeout);
#endif
        send_msg(0, msg_output);
        free(msg_output);
    }
}
