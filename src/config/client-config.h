/* Copyright (C) 2015, Wazuh Inc.
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

#include "shared.h"

typedef struct agent_flags_t {
    unsigned int auto_restart:1;
    unsigned int remote_conf:1;
} agent_flags_t;

typedef struct agent_server {
    char * rip;
    int port;
    int protocol;
    uint32_t network_interface;
    int max_retries; ///< Maximum number of connection retries.
    int retry_interval; ///< Time interval between connection attempts.
} agent_server;

/* Configuration structure */
typedef struct _agent {
    agent_server * server;
    int m_queue;
    int sock;
    int execdq;
    int cfgadq;
    int rip_id; ///< Holds the index of the current connected server
    int server_count; ///< Holds the total amount of servers
    int notify_time;
    int max_time_reconnect_try;
    long force_reconnect_interval;
    int main_ip_update_interval;
    char *profile;
    volatile int buffer;
    int buflength;
    int events_persec;
    int crypto_method;
    int package_uninstallation;
    wlabel_t *labels; /* null-ended label set */
    agent_flags_t flags;
    w_enrollment_ctx *enrollment_cfg;
} agent;

/* Anti tampering config */
typedef struct _anti_tampering {
    bool package_uninstallation;
} anti_tampering;

/* Frees the Client struct  */
void Free_Client(agent * config);

/**
 * @brief Check if address has default values
 * @param servers Server(s) configuration block in agent ossec.conf
 * @return Returns true if successful and false if not success
 */
bool Validate_Address(agent_server *servers);

/**
 * @brief Checks if at least one <server> block is not a link-local ipv6 address or it has a network interface configured.
 * @param servers Server(s) configuration block in agent ossec.conf
 * @return Returns true if successful and false if not success.
 */
bool Validate_IPv6_Link_Local_Interface(agent_server *servers);

#define DEFAULT_MAX_RETRIES 5
#define DEFAULT_RETRY_INTERVAL 10

#endif /* CAGENTD_H */
