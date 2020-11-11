/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LOGREMOTE_H
#define LOGREMOTE_H

#ifndef ARGV0
#define ARGV0 "ossec-remoted"
#endif

#include "config/config.h"
#include "config/remote-config.h"
#include "sec.h"

#define FD_LIST_INIT_VALUE 1024

/* Pending data structure */

typedef struct pending_data_t {
    char *message;
    int changed;
} pending_data_t;

typedef struct message_t {
    char * buffer;
    unsigned int size;
    struct sockaddr_in addr;
    int sock;
    size_t counter;
} message_t;

/* Status structure */

typedef struct remoted_state_t {
    unsigned int discarded_count;
    unsigned int tcp_sessions;
    unsigned int evt_count;
    unsigned int ctrl_msg_count;
    unsigned int msg_sent;
    unsigned long recv_bytes;
    unsigned int dequeued_after_close;
} remoted_state_t;

/* Network buffer structure */

typedef struct sockbuffer_t {
    struct sockaddr_in peer_info;
    char * data;
    unsigned long data_size;
    unsigned long data_len;
} sockbuffer_t;

typedef struct netbuffer_t {
    int max_fd;
    sockbuffer_t * buffers;
} netbuffer_t;

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

/* Forward Security configuration assessment events */
void *SCFGA_Forward(void *arg) __attribute__((noreturn));

/* Initialize the manager */
void manager_init();

/* Free the manager */
void manager_free();

/* Wait for messages from the agent to analyze */
void *wait_for_msgs(void *none);

/* Update shared files */
void *update_shared_files(void *none);

/* Parse control messages */
void parse_agent_controlmsg(const keyentry * key, char *msg, size_t msg_length);

/* Save control messages */
void save_controlmsg(const keyentry * key, char *msg, size_t msg_length, int *wdb_sock);

// Request listener thread entry point
void * req_main(void * arg);

// Save request data (ack or response). Return 0 on success or -1 on error.
int req_save(const char * counter, const char * buffer, size_t length);

/* Send message to agent */
/* Must not call key_lock() before this */
int send_msg(const char *agent_id, const char *msg, ssize_t msg_length);

int check_keyupdate(void);

void key_lock_init(void);

void key_lock_read(void);

void key_lock_write(void);

void key_unlock(void);

// Init message queue
void rem_msginit(size_t size);

// Push message into queue
int rem_msgpush(const char * buffer, unsigned long size, struct sockaddr_in * addr, int sock);

// Pop message from queue
message_t * rem_msgpop();

// Get queue size
size_t rem_get_qsize();

// Get total queue size
size_t rem_get_tsize();

// Free message
void rem_msgfree(message_t * message);

// Status functions
void * rem_state_main();
void rem_inc_tcp();
void rem_dec_tcp();
void rem_inc_evt();
void rem_inc_ctrl_msg();
void rem_inc_msg_sent();
void rem_inc_discarded();
void rem_add_recv(unsigned long bytes);
void rem_inc_dequeued();

// Read config
size_t rem_getconfig(const char * section, char ** output);
cJSON *getRemoteConfig(void);
cJSON *getRemoteInternalConfig(void);

/* Network buffer */

void nb_open(netbuffer_t * buffer, int sock, const struct sockaddr_in * peer_info);
int nb_close(netbuffer_t * buffer, int sock);
int nb_recv(netbuffer_t * buffer, int sock);

/* Network counter */

void rem_initList(size_t initial_size);
void rem_setCounter(int fd, size_t counter);
size_t rem_getCounter(int fd);

/** Global variables **/

extern keystore keys;
extern remoted logr;
extern char* node_name;
extern int timeout;
extern int pass_empty_keyfile;
extern int sender_pool;
extern int rto_sec;
extern int rto_msec;
extern int max_attempts;
extern int request_pool;
extern int request_timeout;
extern int response_timeout;
extern int INTERVAL;
extern rlim_t nofile;
extern int guess_agent_group;
extern int group_data_flush;
extern unsigned receive_chunk;
extern int buffer_relax;
extern int tcp_keepidle;
extern int tcp_keepintvl;
extern int tcp_keepcnt;
extern size_t global_counter;

#endif /* LOGREMOTE_H */
