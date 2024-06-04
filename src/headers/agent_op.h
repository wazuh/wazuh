/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef AGENT_OP_H
#define AGENT_OP_H

#include <cJSON.h>
#include "../config/authd-config.h"

/* Attempts to send a message through the cluster */
#define CLUSTER_SEND_MESSAGE_ATTEMPTS   10

/**
 * @brief Check if syscheck is to be executed/restarted
 * @return 1 on success or 0 on failure (shouldn't be executed now).
 */
int os_check_restart_syscheck(void);

/**
 * @brief Check if rootcheck is to be executed/restarted
 * @return 1 on success or 0 on failure (shouldn't be executed now).
 */
int os_check_restart_rootcheck(void);

/**
 * @brief Set syscheck and rootcheck to be restarted
 */
void os_set_restart_syscheck(void);

/* Read the agent name for the current agent
 * Returns NULL on error
 */
char *os_read_agent_name(void);

/* Read the agent IP for the current agent
 * Returns NULL on error
 */
char *os_read_agent_ip(void);

/* Read the agent ID for the current agent
 * Returns NULL on error
 */
char *os_read_agent_id(void);

/* Read the agent profile name for the current agent
 * Returns NULL on error
 */
char *os_read_agent_profile(void);

/* Write the agent info inside the queue, for the other processes to read
 * Returns 1 on success or <= 0 on failure
 */
int os_write_agent_info(const char *agent_name, const char *agent_ip, const char *agent_id,
                        const char *cfg_profile_name) __attribute__((nonnull(1, 3)));

/* Validates the group name
 * @params response must be a 2048 buffer or NULL
 * Returns 0 on success or  -x on failure
 */
int w_validate_group_name(const char *group, char *response);

// Connect to Agentd. Returns socket or -1 on error.
int auth_connect();

// Close socket if valid.
int auth_close(int sock);

/**
 * @brief Send a local agent "add" request.
 * @param sock Socket where the request connection will be done.
 * @param id ID of the newly generated key.
 * @param name Name of the agent to request the new key.
 * @param ip IP of the agent to request the new key.
 * @param groups Groups list of the agent to request the new key.
 * @param key KEY of the newly generated key.
 * @param force_options Force options to be used during the registration.
 * @param json_format Flag to identify if the response should be printed in JSON format.
 * @param agent_id ID of the agent when requesting a new key for a specific ID.
 * @param exit_on_error Flag to identify if the application should exit on any error.
 * @return 0 on success or a negative code on error.
 */
int w_request_agent_add_local(int sock,
                              char *id,
                              const char *name,
                              const char *ip,
                              const char * groups,
                              const char *key,
                              authd_force_options_t *force_options,
                              const int json_format,
                              const char *agent_id,
                              int exit_on_error);

#ifndef WIN32

/**
 * @brief Send a clustered agent "add" request.
 * @param err_response A buffer where the error message will be stored in case of failure. If NULL, the message is ignored.
 * @param name Name of the agent to request the new key.
 * @param ip IP of the agent to request the new key.
 * @param groups Groups list of the agent to request the new key.
 * @param key_hash Hash of the key if the agent already has one.
 * @param id ID of the newly generated key.
 * @param key KEY of the newly generated key.
 * @param force Force option to be used during the registration. -1 means disabled. 0 or a positive value means enabled.
 * @param agent_id ID of the agent when requesting a new key for a specific ID.
 * @return 0 on success or a negative code on error.
 */
int w_request_agent_add_clustered(char *err_response,
                                  const char *name,
                                  const char *ip,
                                  const char *groups,
                                  const char *key_hash,
                                  char **id,
                                  char **key,
                                  authd_force_options_t *force_options,
                                  const char *agent_id);

// Send a clustered agent remove request.
int w_request_agent_remove_clustered(char *err_response, const char* agent_id, int purge);

// Sends message thru the cluster
int w_send_clustered_message(const char* command, const char* payload, char* response);

// Alloc and create sendsync command payload
cJSON* w_create_sendsync_payload(const char *daemon_name, cJSON *message);

#endif

// Get the agent id
char * get_agent_id_from_name(const char *agent_name);

/**
* @brief Returns an authd force options structure translated into a cJSON object
* @param force_options The structure to be converted
* @returns A cJSON object with all the parameters of the structure
**/
cJSON* w_force_options_to_json(authd_force_options_t *force_options);

/* Check control module availability */
#if defined (__linux__) || defined (__MACH__) || defined (sun) || defined(FreeBSD) || defined(OpenBSD)
int control_check_connection();
#endif

#endif /* AGENT_OP_H */
