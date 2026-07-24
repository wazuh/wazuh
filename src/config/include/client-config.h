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
#include <stdatomic.h>

typedef struct agent_flags_t {
    unsigned int auto_restart:1;
    unsigned int remote_conf:1;
} agent_flags_t;

typedef struct agent_server {
    char * rip;
    int port;
    uint32_t network_interface;
    int max_retries; ///< Maximum number of connection retries (legacy TCP; removed with the cutover).
    int retry_interval; ///< Time interval between connection attempts (legacy TCP; removed with the cutover).
} agent_server;

/* TLS verification posture for the HTTPS transport.
 * Values mirror the module ABI's hc_verify_mode_t so the bridge can copy them
 * verbatim into hc_config_t. FULL is 0 so a zero-initialized config fails closed. */
typedef enum agent_verify_mode_t {
    AGENT_VERIFY_FULL = 0, ///< Verify peer against the CA and check the hostname (default).
    AGENT_VERIFY_CERT = 1, ///< Verify peer against the CA only.
    AGENT_VERIFY_NONE = 2  ///< No TLS verification (explicit opt-out).
} agent_verify_mode_t;

/* Agent-side HTTPS transport TLS settings: the <client><ssl> block (FR10 / #37702 §10). */
typedef struct agent_ssl {
    char * certificate;             ///< <certificate>: optional client (mTLS) certificate.
    char * key;                     ///< <key>: optional client (mTLS) private key.
    char * certificate_authorities; ///< <certificate_authorities>: CA bundle used to verify the manager.
    int verification_mode;          ///< <verification_mode>: agent_verify_mode_t; default FULL.
    char * ciphers;                 ///< <ciphers>: optional cipher list.
} agent_ssl;

/**
 * @brief <client><batch>: the /stateless send-rate model (#37835).
 *
 * Replaces the leaky bucket's <client_buffer><events_per_second> pacing for
 * stateless traffic. Zero means "unset": the transport module applies its own
 * default (1 MiB, 10 s).
 */
typedef struct agent_batch {
    long long size; ///< <size>: max /stateless request payload, in bytes.
    long interval;  ///< <interval>: longest an event waits before a flush, seconds.
} agent_batch;

/* Configuration structure */
typedef struct _agent {
    agent_server * server;
    int m_queue;
    _Atomic int sock;
    int execdq;
    int rip_id; ///< Holds the index of the current connected server
    int server_count; ///< Holds the total amount of servers
    int notify_time;
    int max_time_reconnect_try;
    int main_ip_update_interval;
    char *profile;
    volatile int buffer;
    int buflength;
    int events_persec;
    int package_uninstallation;
    agent_flags_t flags;
    agent_ssl ssl;     ///< HTTPS transport TLS settings (<client><ssl>).
    agent_batch batch; ///< /stateless batching limits (<client><batch>).
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
 * @brief Checks if at least one <manager> block is not a link-local ipv6 address or it has a network interface configured.
 * @param servers Server(s) configuration block in agent ossec.conf
 * @return Returns true if successful and false if not success.
 */
bool Validate_IPv6_Link_Local_Interface(agent_server *servers);

#define DEFAULT_MAX_RETRIES 5
#define DEFAULT_RETRY_INTERVAL 10

#endif /* CAGENTD_H */
