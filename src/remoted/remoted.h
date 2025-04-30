/* Copyright (C) 2015, Wazuh Inc.
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
#define ARGV0 "wazuh-remoted"
#endif

#include "../config/config.h"
#include "../config/remote-config.h"
#include "../config/global-config.h"
#include "../os_crypto/md5/md5_op.h"
#include "sec.h"

#define FD_LIST_INIT_VALUE 1024
#define REMOTED_MSG_HEADER "1:" ARGV0 ":"
#define AG_STOP_MSG REMOTED_MSG_HEADER OS_AG_STOPPED
#define MAX_SHARED_PATH 200

/* Hash table for agent data */
extern OSHash *agent_data_hash;

/* Pending data structure */

typedef struct pending_data_t {
    char *message;
    char *group;
    os_md5 merged_sum;
    int changed;
} pending_data_t;

typedef struct message_t {
    char * buffer;
    unsigned int size;
    struct sockaddr_storage addr;
    int sock;
    size_t counter;
} message_t;

/* Network buffer structure */

typedef struct sockbuffer_t {
    struct sockaddr_storage peer_info;
    char * data;
    unsigned long data_size;
    unsigned long data_len;
    bqueue_t * bqueue;
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

/* Save control messages */
void save_controlmsg(const keyentry * key, char *msg, size_t msg_length, int *wdb_sock);

// Initialize request module
void req_init();

// Request sender
void req_sender(int peer, char *buffer, ssize_t length);

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
int rem_msgpush(const char * buffer, unsigned long size, struct sockaddr_storage * addr, int sock);

// Pop message from queue
message_t * rem_msgpop();

// Get queue size
size_t rem_get_qsize();

// Get total queue size
size_t rem_get_tsize();

// Free message
void rem_msgfree(message_t * message);

// Read config
cJSON *getRemoteConfig(void);
cJSON *getRemoteInternalConfig(void);
cJSON *getRemoteGlobalConfig(void);

/* Network buffer */

void nb_open(netbuffer_t * buffer, int sock, const struct sockaddr_storage * peer_info);
void nb_close(netbuffer_t * buffer, int sock);
int nb_recv(netbuffer_t * buffer, int sock);

/**
 * @brief Send message through TCP protocol.
 *
 * @param buffer buffer where messages are stored.
 * @param socket socket id where send message.
 *
 * @return -1 on system call error: send().
 * @return number of bytes sent on success.
 */
int nb_send(netbuffer_t * buffer, int socket);

/**
 * @brief Queue message through TCP protocol.
 *
 * @param buffer buffer where messages will be stored.
 * @param socket socket id where send message.
 * @param crypt_msg msg to send.
 * @param msg_size message size.
 * @param agent_id message agent id.
 *
 * @return -1 on error.
 * @return 0 on success.
 */
int nb_queue(netbuffer_t * buffer, int socket, char * crypt_msg, ssize_t msg_size, char * agent_id);

/* Network counter */

void rem_initList(int initial_size);
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
extern int disk_storage;
extern rlim_t nofile;
extern int guess_agent_group;
extern unsigned receive_chunk;
extern unsigned send_chunk;
extern int buffer_relax;
extern unsigned send_buffer_size;
extern int send_timeout_to_retry;
extern int tcp_keepidle;
extern int tcp_keepintvl;
extern int tcp_keepcnt;
extern size_t global_counter;

#endif /* LOGREMOTE_H */
