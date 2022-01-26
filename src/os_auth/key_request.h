/* Copyright (C) 2015, Wazuh Inc.
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
 * For details on key request process @see https://documentation.wazuh.com/current/user-manual/capabilities/agent-key-request.html
 */
#ifndef KEY_REQUEST_H
#define KEY_REQUEST_H

#define EXECVE_ERROR 0x7F
#define KR_ERROR_TIMEOUT 1  // Error code for timeout.

/**
 * @brief Enum that define the request type
 * */
typedef enum _request_type {
    K_TYPE_ID,
    K_TYPE_IP,
    K_TYPE_UNKNOWN
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
 * @brief Default key_request_agent_info structure initializer
 * @return Pointer to an inizialized key_request_agent_info structure
 * */
key_request_agent_info * key_request_agent_info_init();

/**
 * @brief Free key_request_agent_info structure
 * @param agent A key_request_agent_info structure to be freed
 * */
void key_request_agent_info_destroy(key_request_agent_info *agent);

/**
 * @brief Read the neccesary agent info from a JSON message
 * @param agent_infoJSON JSON message with the agent information
 * @param error_msg String to print the error if failure
 * @return key_request_agent_info structure with the parsed agent data
 * @return NULL on error
 * */
key_request_agent_info * get_agent_info_from_json(cJSON *agent_infoJSON, char **error_msg);

/**
 * @brief Module main function. It won't return
 * @param arg NULL
 * */
void* run_key_request_main(void *arg);

/**
 * @brief Thread for key request connection pool
 * @param arg NULL
 * */
void * key_request_dispatch_thread(void *arg);

/**
 * @brief Dispatch request. Write the output into the same input buffer.
 * @param buffer Request for an agent key
 * @return 0 on success. -1 on error.
 * */
int key_request_dispatch(char * buffer);

/**
 * @brief Run the integration DB script to get the agent data
 * @param type Type of agent request [ip/id]
 * @param request Request with the agent information (IP or ID values)
 * @return Request response with the agent key on success
 * @return NULL on error or missing data
 * */
char * key_request_exec_output(request_type_t type, char *request);

/**
 * @brief Request to an external socket the agent data
 * @param type Type of agent request [ip/id]
 * @param request Request with the agent information (IP or ID values)
 * @return Request response with the agent key on success
 * @return NULL on error or missing data
 * */
char * key_request_socket_output(request_type_t type, char *request);

extern int wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path);

#endif  /* KEY_REQUEST_H */
