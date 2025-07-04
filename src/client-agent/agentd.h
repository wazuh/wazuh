/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef AGENTD_H
#define AGENTD_H

#include "shared.h"
#include "sec.h"
#include "../config/config.h"
#include "../config/client-config.h"
#include "state.h"

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

/* Client configuration */
int ClientConf(const char *cfgfile);

/* Parse read config into JSON format */
cJSON *getClientConfig(void);
cJSON *getBufferConfig(void);
cJSON *getLabelsConfig(void);
cJSON *getAgentInternalOptions(void);
#ifndef WIN32
cJSON *getAntiTamperingConfig(void);
#endif

/* Agentd init function */
void AgentdStart(int uid, int gid, const char *user, const char *group) __attribute__((noreturn));

/* Event Forwarder */
void *EventForward(void);

/* Receiver messages */
int receive_msg(void);

/* Receiver messages for Windows */
#ifdef WIN32
int receiver_messages(void);
#endif

/* Initialize agent buffer */
void buffer_init();

/* Send message to a buffer with the aim to avoid flooding issues */
int buffer_append(const char *msg);

/**
 * @brief Resizes the internal circular buffer to a desired capacity.
 *
 * @param current_capacity The current allocated capacity of the buffer before resizing.
 * @param desired_capacity The new capacity to which the buffer should be resized.
 *
 * @retval 0 on success.
 * @retval -1 on failure (e.g., invalid capacity, memory allocation error).
 *
 * @note If the desired capacity is smaller than the current number of messages,
 * the buffer will truncate the newest messages to preserve the oldest ones.
 */
int w_agentd_buffer_resize(unsigned int current_capacity, unsigned int desired_capacity);

/**
 * @brief Frees all dynamically allocated memory associated with the agent's message buffer.
 *
 * This function performs a complete cleanup of the circular message buffer.
 * It iterates through all allocated slots up to the provided `current_capacity`,
 * freeing individual messages first to prevent memory leaks. After clearing
 * the contents, it deallocates the buffer array itself. Finally, it resets
 * global buffer-related state variables (like `agt->buflength`, `i`, and `j`)
 * to indicate an unallocated and empty state.
 *
 * This function is thread-safe, utilizing a mutex to protect access to shared buffer state.
 *
 * @param current_capacity The current allocated capacity of the buffer to be freed.
 * This parameter is crucial for iterating over the correct number of slots.
 */
void w_agentd_buffer_free(unsigned int current_capacity);

/* Thread to dispatch messages from the buffer */
#ifdef WIN32
DWORD WINAPI dispatch_buffer(LPVOID arg);
#else
void *dispatch_buffer(void * arg);
#endif
/**
 * @brief get the number of events in buffer
 *
 * @retval number of events in the buffer
 * @retval -1 if the anti-flooding mechanism is disabled
 */
int w_agentd_get_buffer_lenght();

/* Initialize sender structure */
void sender_init();

/* Send message to server */
int send_msg(const char *msg, ssize_t msg_length);

/* Extract the shared files */
char *getsharedfiles(void);

/* Get agent IP */
char *get_agent_ip();

/* Initialize handshake to server */
void start_agent(int is_startup);

/* Connect to the server */
bool connect_server(int initial_id, bool verbose);

/* Send agent stopped message to server */
void send_agent_stopped_message();

/**
 * Tries to enroll to a server indicated by server_rip
 * @return 0 on success -1 on error
 * @param server_rip the server ip where enrollment is attempted
 * @param network_interface network interface through which enrollment is attempted. (Required for IPv6 link-local addresses)
 * */
int try_enroll_to_server(const char *server_rip, uint32_t network_interface);

#if !defined(HPUX) && !defined(AIX) && !defined(SOLARIS)
/**
 * Function that makes the request to the API for the request of uninstallation permissions.
 * @return true if validation is granted, false if denied
 * @param token API token used for the request
 * @param host host and port used for the request
 * @param ssl_verify Enable SSL verification
 * */
bool check_uninstall_permission(const char *token, const char *host, bool ssl_verify);

/**
 * Function to get the API token using a username and password
 * @return API token or NULL
 * @param userpass API user and password separated by colon
 * @param host host and port used for the request
 * @param ssl_verify Enable SSL verification
 * */
char* authenticate_and_get_token(const char *userpass, const char *host, bool ssl_verify);

/**
 * Function with all the necessary functionality to process the uninstallation validation of the Wazuh agent package.
 * @param uninstall_auth_token API token used for the request
 * @param uninstall_auth_login API user and password separated by colon
 * @param uninstall_auth_host host and port used for the request
 * @param ssl_verify Enable SSL verification
 * @return true if validation is granted, false if denied
 * */
bool package_uninstall_validation(const char *uninstall_auth_token, const char *uninstall_auth_login, const char *uninstall_auth_host, bool ssl_verify);
#endif

/* Notify server */
void run_notify(void);

/* Format labels from config into string. Return 0 on success or -1 on error. */
int format_labels(char *str, size_t size);

// Thread to rotate internal log
#ifdef WIN32
DWORD WINAPI w_rotate_log_thread(LPVOID arg);
#else
void * w_rotate_log_thread(void * arg);
#endif

// Initialize request module
void req_init();

// Push a request message into dispatching queue. Return 0 on success or -1 on error.
int req_push(char * buffer, size_t length);

// Request receiver thread start
#ifdef WIN32
DWORD WINAPI req_receiver(LPVOID arg);
#else
void * req_receiver(void * arg);
#endif

// Restart agent
void * restartAgent();

// Verify remote configuration. Return 0 on success or -1 on error.
int verifyRemoteConf();

// Clear merged.mg hash cache value.
void clear_merged_hash_cache();

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
extern time_t last_connection_time;
extern int run_foreground;
extern keystore keys;
extern agent *agt;
extern anti_tampering *atc;

static const char AG_IN_UNMERGE[] = "wazuh: Could not unmerge shared file.";

#endif /* AGENTD_H */
