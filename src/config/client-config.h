/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __CAGENTD_H
#define __CAGENTD_H

typedef struct agent_flags_t {
    unsigned int auto_restart:1;
    unsigned int remote_conf:1;
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
} agent;

/* Frees the Client struct  */
void Free_Client(agent * config);

#endif /* __CAGENTD_H */
