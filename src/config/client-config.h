/* Copyright (C) 2015-2020, Wazuh Inc.
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
    unsigned int remote_conf:1;
} agent_flags_t;

typedef struct agent_server {
    char * rip;
    int port;
    int protocol;
} agent_server;

typedef struct w_enrollment_target {
    char *manager_name;
    int port;
    char *agent_name;
    char *centralized_group;
    char *sender_ip;
} w_enrollment_target;

typedef struct w_enrollment_cert {
    char *ciphers;
    char *authpass;
    char *agent_cert;
    char *agent_key;
    char *ca_cert;
    unsigned int auto_method:1;
} w_enrollment_cert;

typedef struct w_enrollment_cfg {
    w_enrollment_target target;
    w_enrollment_cert certificates;
    unsigned int enabled:1;
} w_enrollment_cfg;

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
    w_enrollment_cfg enrollment_cfg;
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
