/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __AGENTD_H
#define __AGENTD_H

#include "shared.h"
#include "sec.h"
#include "config/config.h"
#include "config/client-config.h"

/* Buffer functions */
#define full(i, j, n) ((i + 1) % (n) == j)
#define warn(i, j) ((float)((i - j + agt->buflength + 1) % (agt->buflength + 1)) / (float)agt->buflength >= ((float)warn_level/100.0))
#define nowarn(i, j) ((float)((i - j + agt->buflength + 1) % (agt->buflength + 1)) / (float)agt->buflength <= ((float)warn_level/100.0))
#define normal(i, j) ((float)((i - j + agt->buflength + 1) % (agt->buflength + 1)) / (float)agt->buflength <= ((float)normal_level/100.0))
#define capacity(i, j) (float)((i - j + agt->buflength + 1) % (agt->buflength + 1)) / (float)agt->buflength
#define empty(i, j) (i == j)
#define forward(x, n) x = (x + 1) % (n)

/* Buffer statuses */
#define NORMAL 0
#define WARNING 1
#define FULL 2
#define FLOOD 3

/* Agent status structure */

typedef struct agent_state_t {
    agent_status_t status;
    time_t last_keepalive;
    time_t last_ack;
    unsigned int msg_count;
    unsigned int msg_sent;
} agent_state_t;

/* Client configuration */
int ClientConf(const char *cfgfile);

/* Parse readed config into JSON format */
cJSON *getClientConfig(void);
cJSON *getBufferConfig(void);
cJSON *getLabelsConfig(void);
cJSON *getAgentInternalOptions(void);

/* Agentd init function */
void AgentdStart(const char *dir, int uid, int gid, const char *user, const char *group) __attribute__((noreturn));

/* Event Forwarder */
void *EventForward(void);

/* Receiver messages */
int receive_msg(void);

/* Receiver messages for Windows */
void *receiver_thread(void *none);

/* Send integrity checking information about a file to the server */
int intcheck_file(const char *file_name, const char *dir);

/* Initialize agent buffer */
void buffer_init();

/* Send message to a buffer with the aim to avoid flooding issues */
int buffer_append(const char *msg);

/* Thread to dispatch messages from the buffer */
void *dispatch_buffer(void * arg);

/* Send message to server */
int send_msg(const char *msg, ssize_t msg_length);

/* Extract the shared files */
char *getsharedfiles(void);

/* Initialize handshake to server */
void start_agent(int is_startup);

/* Connect to the server */
int connect_server(int initial_id);

/* Notify server */
void run_notify(void);

/* Format labels from config into string. Return 0 on success or -1 on error. */
int format_labels(char *str, size_t size);

// Thread to rotate internal log
void * w_rotate_log_thread(void * arg);

// Initialize request module
void req_init();

// Push a request message into dispatching queue. Return 0 on success or -1 on error.
int req_push(char * buffer, size_t length);

// Request receiver thread start
void * req_receiver(void * arg);

// Restart agent
void * restartAgent();

// Verify remote configuration. Return 0 on success or -1 on error.
int verifyRemoteConf();

// Agent status functions
void * state_main(void * args);
void update_status(agent_status_t status);
void update_keepalive(time_t curr_time);
void update_ack(time_t curr_time);

#ifndef WIN32
// Com request thread dispatcher
void * agcom_main(void * arg);
#endif
size_t agcom_dispatch(char * command, char ** output);
size_t agcom_getconfig(const char * section, char ** output);

/*** Global variables ***/
extern int agent_debug_level;
extern int win_debug_level;
extern int warn_level;
extern int normal_level;
extern int tolerance;
extern int rotate_log;
extern int request_pool;
extern int rto_sec;
extern int rto_msec;
extern int max_attempts;
extern int log_compress;
extern int keep_log_days;
extern int day_wait;
extern int daily_rotations;
extern int size_rotate_read;
extern int timeout;
extern int interval;
extern int remote_conf;
extern int min_eps;


/* Global variables. Only modified during startup. */

extern time_t available_server;
extern int run_foreground;
extern keystore keys;
extern agent *agt;
extern agent_state_t agent_state;

static const char AG_IN_UNMERGE[] = "wazuh: Could not unmerge shared file.";

#endif /* __AGENTD_H */
