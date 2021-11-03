/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/**
 * @file key_request.h
 * @date 29 October 2021
 * @brief Agent key request feature
 *
 * This feature receives a key request configuration and registers to the manager
 * through a socket or a DB integration, or failing that, it shows various failure messages
 * For details on key request process @see https://documentation.wazuh.com/4.4/user-manual/capabilities/agent-key-request.html
 */
#ifndef KEY_REQUEST_H
#define KEY_REQUEST_H

#define EXECVE_ERROR 0x7F
#define RELAUNCH_TIME 300
#define KR_ERROR_TIMEOUT 1  // Error code for timeout.

/**
 * @brief Enum that define the request type
 * */
typedef enum _request_type {
    W_TYPE_ID,W_TYPE_IP
} request_type_t;

/**
 * @brief Struct that define the add agent parameters 
 * */
typedef struct _key_request_agent_info {
    char *id;
    char *name;
    char *ip;
    char *key;
} key_request_agent_info;

/**
 * Module main function. It won't return
 * */
void* run_key_request_main(void *arg);

/**
 * Thread for key request connection pool
 * */
void * w_request_thread(void *arg);

/**
 * Dispatch request. Write the output into the same input buffer.
 * */
int w_key_request_dispatch(char * buffer);

/**
 * Default key_request_agent_info structure initializer
 * */
key_request_agent_info * w_key_request_agent_info_init();

/**
 * Free key_request_agent_info structure
 * */
void w_key_request_agent_info_destroy(key_request_agent_info *agent);

/**
 * Get the neccesary agent info from a json message
 * */
key_request_agent_info * get_agent_info_from_json(cJSON *agent_infoJSON, char **error_msg);

/**
 * Run the integration DB script to get the output
 * */
char * keyrequest_exec_output(request_type_t type, char *request);

/**
 * Connect with a socket to get the output
 * */
char * keyrequest_socket_output(request_type_t type, char *request);

extern int wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path);

#endif  /* KEY_REQUEST_H */
