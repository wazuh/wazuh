/* Copyright (C) 2015-2020, Wazuh Inc.
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

#include "external/cJSON/cJSON.h"

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

/* Read agent group. Returns 0 on success or -1 on failure. */
int get_agent_group(const char *id, char *group, size_t size);

/* Set agent group. Returns 0 on success or -1 on failure. */
int set_agent_group(const char * id, const char * group);

/* Create multigroup dir. Returns 0 on success or -1 on failure. */
int create_multigroup_dir(const char * multigroup);

/*
 * Parse manager hostname from agent-info file.
 * If no such file, returns NULL.
 */

char* hostname_parse(const char *path);

/* Validates the group name
 * @params response must be a 2048 buffer or NULL
 * Returns 0 on success or  -x on failure
 */

int w_validate_group_name(const char *group, char *response);

int set_agent_multigroup(char * group);

void w_remove_multigroup(const char *group);

// Connect to Agentd. Returns socket or -1 on error.
int auth_connect();

// Close socket if valid.
int auth_close(int sock);

// Send a local agent add request.
int w_request_agent_add_local(int sock, char *id, const char *name, const char *ip, const char * groups, const char *key, const int force, const int json_format, const char *agent_id, int exit_on_error);

#ifndef WIN32
// Send a clustered agent add request.
int w_request_agent_add_clustered(char *err_response, const char *name, const char *ip, const char * groups, char **id, char **key, const int force, const char *agent_id);

// Send a clustered agent remove request.
int w_request_agent_remove_clustered(char *err_response, const char* agent_id, int purge);

// Sends message thru the cluster
int w_send_clustered_message(const char* command, const char* payload, char* response);

// Alloc and create sendsync command payload
cJSON* w_create_sendsync_payload(const char *daemon_name, cJSON *message);

#endif

// Get the agent id
char * get_agent_id_from_name(const char *agent_name);

/* Check control module availability */
#if defined (__linux__) || defined (__MACH__) || defined (sun)
int control_check_connection();
#endif

#endif /* AGENT_OP_H */
