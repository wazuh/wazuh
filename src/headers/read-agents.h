/* @(#) $Id: ./src/headers/read-agents.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#ifndef __CRAGENT_H
#define __CRAGENT_H


/* Unique key for each agent. */
typedef struct _agent_info
{
    char *last_keepalive;
    char *syscheck_time;
    char *syscheck_endtime;
    char *rootcheck_time;
    char *rootcheck_endtime;
    char *os;
    char *version;
}agent_info;


/* Print syscheck db (of modified files). */
int print_syscheck(const char *sk_name, const char *sk_ip, const char *fname, int print_registry,
                   int all_files, int csv_output, int update_counter);

/* Print rootcheck db. */
int print_rootcheck(const char *sk_name, const char *sk_ip, const char *fname, int resolved,
                    int csv_output, int show_last);

/* Delete syscheck db */
int delete_syscheck(const char *sk_name, const char *sk_ip, int full_delete) __attribute__((nonnull));

/* Delete rootcheck db. */
int delete_rootcheck(const char *sk_name, const char *sk_ip, int full_delete) __attribute__((nonnull));

/* Delete agent information */
int delete_agentinfo(const char *name) __attribute__((nonnull));

/* Get all available agents */
char **get_agents(int flag);

/* Free the agent list */
void free_agents(char **agent_list);

/** char *print_agent_status(int status)
 * Prints the text representation of the agent status.
 */
const char *print_agent_status(int status);

/** int get_agent_status(char *agent_name, char *agent_ip)
 * Gets the status of an agent, based on the name/ip.
 */
int get_agent_status(const char *agent_name, const char *agent_ip);

/** agent_info *get_agent_info(char *agent_name, char *agent_ip)
 * Get information from an agent.
 */
agent_info *get_agent_info(const char *agent_name, const char *agent_ip) __attribute__((nonnull(2)));


/** int connect_to_remoted()
 * Connects to remoted to be able to send messages to the agents.
 * Returns the socket on success or -1 on failure.
 */
int connect_to_remoted(void);

/** int send_msg_to_agent(int socket, char *msg)
 * Sends a message to an agent.
 * returns -1 on error.
 */
int send_msg_to_agent(int msocket, const char *msg, const char *agt_id, const char *exec) __attribute__((nonnull(2)));




#define GA_NOTACTIVE    2
#define GA_ACTIVE       3
#define GA_ALL          5
#define GA_ALL_WSTATUS  7

/* Status */
#define GA_STATUS_ACTIVE    12
#define GA_STATUS_NACTIVE   13
#define GA_STATUS_INV       14



#endif
