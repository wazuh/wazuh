/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/**
 * @file key_request_op.h
 * @date 21 October 2020
 * @brief Library that handles the key request process of an manager
 *
 * Wazuh agents need to register to a manager before being able to start sending messages
 * There are several way of registering according to manager's configuration
 * This library receives a key request configuration and registers to the manager
 * through a socket or a DB integration, or failing that, it shows various failure messages
 * For details on key request process @see https://documentation.wazuh.com/current/user-manual/capabilities/agent-key-request.html
 */
#ifndef KEY_REQUEST_H
#define KEY_REQUEST_H

#define KEY_REQUEST_NAME "key-request"
#define KEY_REQUEST_LOGTAG ARGV0 ":" KEY_REQUEST_NAME

#include <os_net/os_net.h>

#define EXECVE_ERROR 0x7F
#define RELAUNCH_TIME 300
#define KR_ERROR_TIMEOUT 1  // Error code for timeout.

/**
 * @brief Enum...
 * */
typedef enum _request_type {
    W_TYPE_ID,W_TYPE_IP
} request_type_t;

/**
 * @brief Struct... 
 * */
typedef struct _key_request_agent_info {
    char *id;
    char *name;
    char *ip;
    char *key;
} key_request_agent_info;

/* Execute command with timeout of secs. exitcode can be NULL.
 *
 * command is a mutable string.
 * output is a pointer to dynamic string. Caller is responsible for freeing it!
 * On success, return 0. On another error, returns -1.
 * If the called program timed-out, returns WM_ERROR_TIMEOUT and output may
 * contain data.
 * env_path is a pointer to an string to add to the PATH environment variable.
 */
extern int wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path);


// Module main function. It won't return
void* run_key_request_main(w_queue_t * request_queue);

// Thread for key request connection pool
void * w_request_thread(w_queue_t * request_queue);

// Dispatch request. Write the output into the same input buffer.
int w_key_request_dispatch(char * buffer);

// Init key request integration
void * w_socket_launcher(void * args);

// key_request_agent_info structure initializer
key_request_agent_info * w_key_request_agent_info_init();

// Get the neccesary agent info from a json message
key_request_agent_info * get_agent_info_from_json(cJSON *agent_infoJSON, char **error_msg);

// Run the integration DB script to get the output
char * keyrequest_exec_output(request_type_t type, char *request);

// Connect with a socket to get the output
char * keyrequest_socket_output(request_type_t type, char *request);

#endif //KEY_REQUEST_H
