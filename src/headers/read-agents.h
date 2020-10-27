/* Copyright (C) 2015-2020, Wazuh Inc.
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

#include <external/cJSON/cJSON.h>

/* Unique key for each agent */
typedef struct _agent_info {
    char *last_keepalive;
    char *syscheck_time;
    char *syscheck_endtime;
    char *rootcheck_time;
    char *rootcheck_endtime;
    char *os;
    char *version;
    char *config_sum;
    char *merged_sum;
} agent_info;

/* Status */

typedef enum agent_status_t {
    GA_STATUS_ACTIVE = 12,
    GA_STATUS_NACTIVE,
    GA_STATUS_INV,
    GA_STATUS_PENDING
} agent_status_t;

/* Print syscheck db (of modified files) */
int print_syscheck(const char *sk_name, const char *sk_ip, const char *fname, int print_registry,
                   int all_files, int csv_output, cJSON *json_output, int update_counter);

/* Print rootcheck db */
int print_rootcheck(const char *sk_name, const char *sk_ip, const char *fname, int resolved,
                    int csv_output, cJSON *json_output, int show_last);

/* Delete syscheck db */
int delete_syscheck(const char *sk_name, const char *sk_ip, int full_delete) __attribute__((nonnull));

/* Delete rootcheck db */
int delete_rootcheck(const char *sk_name, const char *sk_ip, int full_delete) __attribute__((nonnull));

/* Delete agent information */
int delete_agentinfo(const char *id, const char *name) __attribute__((nonnull));

/* Delete agent SQLite db */
void delete_sqlite(const char *id, const char *name);

/* Delete diff folders */
void delete_diff(const char *name);

/* Get all available agents */
char **get_agents(int flag);

/* List agents for monitord */
char **get_agents_by_last_keepalive(int flag, int delta);

/* Free the agent list */
void free_agents(char **agent_list);

/* Print the text representation of the agent status */
const char *print_agent_status(agent_status_t status);

/* Gets the status of an agent, based on the agent ID */
agent_status_t get_agent_status(int agent_id);

/* Get information from an agent */
agent_info *get_agent_info(const char *agent_name, const char *agent_ip, const char *agent_id) __attribute__((nonnull(2)));

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
