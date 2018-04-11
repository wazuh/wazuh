/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __LOGREMOTE_H
#define __LOGREMOTE_H

#ifndef ARGV0
#define ARGV0 "ossec-remoted"
#endif

#include "config/config.h"
#include "config/remote-config.h"
#include "sec.h"

/* Queue management macros */

#define full(i, j) ((i + 1) % MAX_AGENTS == j)
#define empty(i, j) (i == j)
#define forward(x) x = (x + 1) % MAX_AGENTS

/* Pending data structure */

typedef struct pending_data_t {
    char *message;
    char *keep_alive;
    int changed;
} pending_data_t;

typedef struct message_t {
    char * buffer;
    unsigned int size;
    struct sockaddr_in addr;
    int sock;
} message_t;

/** Function prototypes **/

/* Read remoted config */
int RemotedConfig(const char *cfgfile, remoted *cfg);

/* Handle Remote connections */
void HandleRemote(int uid) __attribute__((noreturn));

/* Handle Syslog */
void HandleSyslog(void) __attribute__((noreturn));

/* Handle Syslog TCP */
void HandleSyslogTCP(void) __attribute__((noreturn));

/* Handle Secure connections */
void HandleSecure() __attribute__((noreturn));

/* Forward active response events */
void *AR_Forward(void *arg) __attribute__((noreturn));

/* Initialize the manager */
void manager_init();

/* Wait for messages from the agent to analyze */
void *wait_for_msgs(void *none);

/* Update shared files */
void *update_shared_files(void *none);

/* Save control messages */
void save_controlmsg(unsigned int agentid, char *msg, size_t msg_length);

// Request listener thread entry point
void * req_main(void * arg);

// Save request data (ack or response). Return 0 on success or -1 on error.
int req_save(const char * counter, const char * buffer, size_t length);

/* Send message to agent */
/* Must not call key_lock() before this */
int send_msg(const char *agent_id, const char *msg, ssize_t msg_length);

int check_keyupdate(void);

void key_lock_read(void);

void key_lock_write(void);

void key_unlock(void);

// Init message queue
void rem_msginit(size_t size);

// Push message into queue
int rem_msgpush(const char * buffer, unsigned long size, struct sockaddr_in * addr, int sock);

// Pop message from queue
message_t * rem_msgpop();

// Free message
void rem_msgfree(message_t * message);

/** Global variables **/

extern keystore keys;
extern remoted logr;
extern char* node_name;

#endif /* __LOGREMOTE_H */
