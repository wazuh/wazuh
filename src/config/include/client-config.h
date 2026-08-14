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
 * verbatim into hc_config_t. FULL is 0, so a zero-initialized struct that never
 * goes through the agent's own default-setting path (ClientConf) still fails
 * closed. The agent's own default, applied when <ssl> is absent, is NONE. */
typedef enum agent_verify_mode_t {
    AGENT_VERIFY_FULL = 0, ///< Verify peer against the CA and check the hostname.
    AGENT_VERIFY_CERT = 1, ///< Verify peer against the CA only.
    AGENT_VERIFY_NONE = 2  ///< No TLS verification (the agent's own configured default).
} agent_verify_mode_t;

/* Agent-side HTTPS transport TLS settings: the <agent><ssl> block (FR10 / #37702 §10). */
typedef struct agent_ssl {
    char * certificate;             ///< <certificate>: optional client (mTLS) certificate.
    char * key;                     ///< <key>: optional client (mTLS) private key.
    char * certificate_authorities; ///< <certificate_authorities>: CA bundle used to verify the manager.
    int verification_mode;          ///< <verification_mode>: agent_verify_mode_t; default FULL.
    char * ciphers;                 ///< <ciphers>: optional cipher list.
} agent_ssl;

/**
 * @brief <agent><batch>: the /stateless send-rate model (#37835).
 *
 * Replaces the leaky bucket's <client_buffer><events_per_second> pacing for
 * stateless traffic. Zero means "unset": the transport module applies its own
 * default (1 MiB, 10 s).
 */
typedef struct agent_batch {
    long long size; ///< <size>: max /stateless request payload, in bytes.
    long interval;  ///< <interval>: longest an event waits before a flush, seconds.
} agent_batch;

/**
 * @brief <agent><stats_report> / <agent><config_report>: the periodic push of
 *        a whole-agent snapshot to /stats and /config (#37843).
 *
 * The two are independent. <stats_report> stays off until <enabled> says
 * otherwise; <config_report> ships on by default (ClientConf() sets it before
 * the config is parsed), so only an explicit <enabled>no</enabled> disables it.
 * ClientConf() also seeds <interval> with its effective default (60 s for
 * stats, 3600 s for config) before parsing, for the same reason: a zero
 * interval is otherwise indistinguishable from "unset" (Read_Agent_Report()
 * rejects an explicit zero outright), and the transport module's own
 * zero-means-unset fallback would otherwise be the only place that default
 * was visible.
 */
typedef struct agent_report {
    unsigned char enabled; ///< <enabled>: whether to push at all.
    long interval;         ///< <interval>: seconds between pushes.
} agent_report;

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
    int package_uninstallation;
    agent_flags_t flags;
    agent_ssl ssl;     ///< HTTPS transport TLS settings (<agent><ssl>).
    agent_batch batch; ///< /stateless batching limits (<agent><batch>).
    agent_report stats_report;  ///< Periodic /stats push (<agent><stats_report>).
    agent_report config_report; ///< Periodic /config push (<agent><config_report>).
    w_enrollment_ctx *enrollment_cfg;
} agent;

/* Anti tampering config */
typedef struct _anti_tampering {
    bool package_uninstallation;
} anti_tampering;

/* Frees the agent struct  */
void Free_Agent(agent * config);

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

/**
 * @brief Read the <agent><batch> limits, for daemons that do not own the block.
 *
 * agentd reads the whole <agent> block; the daemons hosting the sync protocol need
 * the same limits without it, since Read_Agent fills structures agentd allocates
 * beforehand. The local file is read first and the centralized one second, so the
 * manager's value wins - the order ClientConf applies them in.
 *
 * @param cfgfile Local configuration file, or NULL to skip it.
 * @param sharedcfg Centralized configuration file, or NULL to skip it.
 * @param batch Limits to fill; each value is left alone when unconfigured.
 */
void w_read_agent_batch(const char *cfgfile, const char *sharedcfg, agent_batch *batch);

#define DEFAULT_MAX_RETRIES 5
#define DEFAULT_RETRY_INTERVAL 10

/* Port used when <server><port> is unspecified. Must mirror the manager's
 * DEFAULT_HTTPS_PORT (src/remoted/remoted_module/src/http_server/httpServerConfig.cpp)
 * since the agent has no legacy-transport fallback to default to instead. */
#define DEFAULT_HTTPS_CLIENT_PORT 1517

#endif /* CAGENTD_H */
