/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CAGENTD_H
#define CAGENTD_H

typedef struct agent_flags_t {
    unsigned int auto_restart:1;
    unsigned int remote_conf;
} agent_flags_t;

typedef struct agent_server {
    char * rip;
    int port;
    int protocol;
} agent_server;

/* Configuration structure */
typedef struct _agent {
    agent_server * server;
    int m_queue;
    int sock;
    int execdq;
    int cfgadq;
    int rip_id;
    char *lip;
    int notify_time;
    int max_time_reconnect_try;
    char *profile;
    int buffer;
    int buflength;
    int events_persec;
    int crypto_method;
    wlabel_t *labels; /* null-ended label set */
    agent_flags_t flags;
    /* Internal options */
    /* Client buffer */
    int tolerance;
    int min_eps;
    int warn_level;
    int normal_level;
    /* Client */
    int state_interval;
    int recv_timeout;
    int log_level;
    int recv_counter_flush;
    int comp_average_printout;
    int verify_msg_id;
    int request_pool;
    int rto_sec;
    int rto_msec;
    int max_attempts;
    int thread_stack_size;
} agent;

/* Frees the Client struct  */
void Free_Client(agent * config);

/**
 * @brief Check if address has default values
 * @param servers Server(s) configuration block in agent ossec.conf
 * @return Returns true if successful and false if not success
 */
bool Validate_Address(agent_server *servers);

#endif /* CAGENTD_H */
