/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CRAGENT_H
#define CRAGENT_H

#include <cJSON.h>

/* Status */
typedef enum agent_status_t {
    GA_STATUS_ACTIVE = 12,
    GA_STATUS_NACTIVE,
    GA_STATUS_NEVER,
    GA_STATUS_PENDING,
    GA_STATUS_UNKNOWN
} agent_status_t;

/* Unique key for each agent */
typedef struct _agent_info {
    char *last_keepalive;
    char *syscheck_time;
    char *syscheck_endtime;
    char *os;
    char *version;
    char *config_sum;
    char *merged_sum;
    agent_status_t connection_status;
} agent_info;

/* Delete diff folders */
void delete_diff(const char *name);

/* Get all available agents */
char **get_agents(int flag);

/* Free the agent list */
void free_agents(char **agent_list);

/* Print the text representation of the agent status */
const char *print_agent_status(agent_status_t status);

/* Gets the status of an agent, based on the agent ID */
agent_status_t get_agent_status(int agent_id);

/* Get information from an agent */
agent_info *get_agent_info(const char *agent_id) __attribute__((nonnull(1)));

/* Connect to remoted to be able to send messages to the agents
 * Returns the socket on success or -1 on failure
 */
int connect_to_remoted(void);

#ifndef WIN32
/* Return the unix permission string
 * Returns a pointer to a local static array
 */
char *agent_file_perm(mode_t mode);
#endif

/* Sends a message to an agent
 * Returns -1 on error
 */
int send_msg_to_agent(int msocket, const char *msg, const char *agt_id, const char *exec) __attribute__((nonnull(2)));

/*
 * Gets FIM scan-time
 * Returns -1 on error
 */
time_t scantime_fim (const char *agent_id, const char *scan);

#define GA_NOTACTIVE        2
#define GA_ACTIVE           3
#define GA_ALL              5
#define GA_ALL_WSTATUS      7

#endif /* CRAGENT_H */
