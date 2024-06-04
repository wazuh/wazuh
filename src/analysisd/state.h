/*
 * Queue (abstract data type)
 * Copyright (C) 2015, Wazuh Inc.
 * June 22, 2018
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef STATE_A_H
#define STATE_A_H

#define ASYS_MAX_NUM_AGENTS_STATS 75

#include <stdint.h>
#include "../wazuh_db/helpers/wdb_global_helpers.h"

/* Status structures */

typedef struct _queue_status_t {
    float syscheck_queue_usage;
    size_t syscheck_queue_size;
    float syscollector_queue_usage;
    size_t syscollector_queue_size;
    float rootcheck_queue_usage;
    size_t rootcheck_queue_size;
    float sca_queue_usage;
    size_t sca_queue_size;
    float hostinfo_queue_usage;
    size_t hostinfo_queue_size;
    float winevt_queue_usage;
    size_t winevt_queue_size;
    float dbsync_queue_usage;
    size_t dbsync_queue_size;
    float upgrade_queue_usage;
    size_t upgrade_queue_size;
    float events_queue_usage;
    size_t events_queue_size;
    float processed_queue_usage;
    size_t processed_queue_size;
    float alerts_queue_usage;
    size_t alerts_queue_size;
    float archives_queue_usage;
    size_t archives_queue_size;
    float firewall_queue_usage;
    size_t firewall_queue_size;
    float fts_queue_usage;
    size_t fts_queue_size;
    float stats_queue_usage;
    size_t stats_queue_size;
} queue_status_t;

typedef struct _integrations_t {
    uint64_t virustotal;
} integrations_t;

typedef struct _logcollector_t {
    uint64_t eventchannel;
    uint64_t eventlog;
    uint64_t macos;
    uint64_t others;
} logcollector_t;

typedef struct _modules_t {
    uint64_t aws;
    uint64_t azure;
    uint64_t ciscat;
    uint64_t command;
    uint64_t docker;
    uint64_t gcp;
    uint64_t github;
    uint64_t office365;
    uint64_t ms_graph;
    uint64_t oscap;
    uint64_t osquery;
    uint64_t rootcheck;
    uint64_t sca;
    uint64_t syscheck;
    uint64_t syscollector;
    uint64_t upgrade;
    uint64_t vulnerability;
    logcollector_t logcollector;
} modules_t;

typedef struct _events_t {
    uint64_t agent;
    uint64_t agentless;
    uint64_t dbsync;
    uint64_t monitor;
    uint64_t remote;
    uint64_t syslog;
    integrations_t integrations;
    modules_t modules;
} events_t;

typedef struct _written_t {
    uint64_t alerts_written;
    uint64_t archives_written;
    uint32_t firewall_written;
    uint32_t fts_written;
    uint32_t stats_written;
} written_t;

typedef struct _eps_state_t {
    uint64_t available_credits_prev;
    uint64_t events_dropped;
    uint64_t events_dropped_not_eps;
    uint64_t seconds_over_limit;
} eps_state_t;

typedef struct _analysisd_state_t {
    uint64_t uptime;
    uint64_t received_bytes;
    uint64_t events_received;
    uint64_t events_processed;
    events_t events_decoded_breakdown;
    events_t events_dropped_breakdown;
    written_t events_written_breakdown;
    eps_state_t eps_state_breakdown;
} analysisd_state_t;

typedef struct _analysisd_agent_state_t {
    uint64_t uptime;
    uint64_t events_processed;
    uint64_t alerts_written;
    uint64_t archives_written;
    uint32_t firewall_written;
    events_t events_decoded_breakdown;
} analysisd_agent_state_t;

/* Status functions */

/**
 * @brief Listen to analysisd socket for new requests
 */
void * asyscom_main(__attribute__((unused)) void * arg) ;

/**
 * @brief Main function of analysisd status writer
 */
void* w_analysisd_state_main();

/**
 * @brief Increment bytes received
 * @param bytes Number of bytes to increment
 */
void w_add_recv(unsigned long bytes);

/**
 * @brief Increment received events counter
 */
void w_inc_received_events();

/**
 * @brief Increment decoded by component events related counter
 */
void w_inc_decoded_by_component_events(const char *component, const char *agent_id);

/**
 * @brief Increment agent decoded events counter
 */
void w_inc_agent_decoded_events(const char *agent_id);

/**
 * @brief Increment agentless decoded events counter
 */
void w_inc_agentless_decoded_events();

/**
 * @brief Increment dbsync decoded events counter
 */
void w_inc_dbsync_decoded_events(const char *agent_id);

/**
 * @brief Increment monitor decoded events counter
 */
void w_inc_monitor_decoded_events(const char *agent_id);

/**
 * @brief Increment remote decoded events counter
 */
void w_inc_remote_decoded_events(const char *agent_id);

/**
 * @brief Increment syslog decoded events counter
 */
void w_inc_syslog_decoded_events();

/**
 * @brief Increment integrations virustotal decoded events counter
 */
void w_inc_integrations_virustotal_decoded_events(const char *agent_id);

/**
 * @brief Increment modules aws decoded events counter
 */
void w_inc_modules_aws_decoded_events(const char *agent_id);

/**
 * @brief Increment modules azure decoded events counter
 */
void w_inc_modules_azure_decoded_events(const char *agent_id);

/**
 * @brief Increment modules ciscat decoded events counter
 */
void w_inc_modules_ciscat_decoded_events(const char *agent_id);

/**
 * @brief Increment modules command decoded events counter
 */
void w_inc_modules_command_decoded_events(const char *agent_id);

/**
 * @brief Increment modules docker decoded events counter
 */
void w_inc_modules_docker_decoded_events(const char *agent_id);

/**
 * @brief Increment modules gcp decoded events counter
 */
void w_inc_modules_gcp_decoded_events(const char *agent_id);

/**
 * @brief Increment modules github decoded events counter
 */
void w_inc_modules_github_decoded_events(const char *agent_id);

/**
 * @brief Increment modules office365 decoded events counter
 */
void w_inc_modules_office365_decoded_events(const char *agent_id);

/**
 * @brief Increment modules ms-graph decoded events counter
 */
void w_inc_modules_ms_graph_decoded_events(const char *agent_id);

/**
 * @brief Increment modules oscap decoded events counter
 */
void w_inc_modules_oscap_decoded_events(const char *agent_id);

/**
 * @brief Increment modules osquery decoded events counter
 */
void w_inc_modules_osquery_decoded_events(const char *agent_id);

/**
 * @brief Increment modules rootcheck decoded events counter
 */
void w_inc_modules_rootcheck_decoded_events(const char *agent_id);

/**
 * @brief Increment modules sca decoded events counter
 */
void w_inc_modules_sca_decoded_events(const char *agent_id);

/**
 * @brief Increment modules syscheck decoded events counter
 */
void w_inc_modules_syscheck_decoded_events(const char *agent_id);

/**
 * @brief Increment modules syscollector decoded events counter
 */
void w_inc_modules_syscollector_decoded_events(const char *agent_id);

/**
 * @brief Increment modules upgrade decoded events counter
 */
void w_inc_modules_upgrade_decoded_events(const char *agent_id);

/**
 * @brief Increment modules vulnerability decoded events counter
 */
void w_inc_modules_vulnerability_decoded_events(const char *agent_id);

/**
 * @brief Increment modules logcollector eventchannel decoded events counter
 */
void w_inc_modules_logcollector_eventchannel_decoded_events(const char *agent_id);

/**
 * @brief Increment modules logcollector eventlog decoded events counter
 */
void w_inc_modules_logcollector_eventlog_decoded_events(const char *agent_id);

/**
 * @brief Increment modules logcollector macos decoded events counter
 */
void w_inc_modules_logcollector_macos_decoded_events(const char *agent_id);

/**
 * @brief Increment modules logcollector others decoded events counter
 */
void w_inc_modules_logcollector_others_decoded_events(const char *agent_id);

/**
 * @brief Increment dropped by component events related counter
 */
void w_inc_dropped_by_component_events(const char *component);

/**
 * @brief Increment agent dropped events counter
 */
void w_inc_agent_dropped_events();

/**
 * @brief Increment agentless dropped events counter
 */
void w_inc_agentless_dropped_events();

/**
 * @brief Increment dbsync dropped events counter
 */
void w_inc_dbsync_dropped_events();

/**
 * @brief Increment monitor dropped events counter
 */
void w_inc_monitor_dropped_events();

/**
 * @brief Increment remote dropped events counter
 */
void w_inc_remote_dropped_events();

/**
 * @brief Increment syslog dropped events counter
 */
void w_inc_syslog_dropped_events();

/**
 * @brief Increment integrations virustotal dropped events counter
 */
void w_inc_integrations_virustotal_dropped_events();

/**
 * @brief Increment modules aws dropped events counter
 */
void w_inc_modules_aws_dropped_events();

/**
 * @brief Increment modules azure dropped events counter
 */
void w_inc_modules_azure_dropped_events();

/**
 * @brief Increment modules ciscat dropped events counter
 */
void w_inc_modules_ciscat_dropped_events();

/**
 * @brief Increment modules command dropped events counter
 */
void w_inc_modules_command_dropped_events();

/**
 * @brief Increment modules docker dropped events counter
 */
void w_inc_modules_docker_dropped_events();

/**
 * @brief Increment modules gcp dropped events counter
 */
void w_inc_modules_gcp_dropped_events();

/**
 * @brief Increment modules github dropped events counter
 */
void w_inc_modules_github_dropped_events();

/**
 * @brief Increment modules office365 dropped events counter
 */
void w_inc_modules_office365_dropped_events();

/**
 * @brief Increment modules ms-graph dropped events counter
 */
void w_inc_modules_ms_graph_dropped_events();

/**
 * @brief Increment modules oscap dropped events counter
 */
void w_inc_modules_oscap_dropped_events();

/**
 * @brief Increment modules osquery dropped events counter
 */
void w_inc_modules_osquery_dropped_events();

/**
 * @brief Increment modules rootcheck dropped events counter
 */
void w_inc_modules_rootcheck_dropped_events();

/**
 * @brief Increment modules sca dropped events counter
 */
void w_inc_modules_sca_dropped_events();

/**
 * @brief Increment modules syscheck dropped events counter
 */
void w_inc_modules_syscheck_dropped_events();

/**
 * @brief Increment modules syscollector dropped events counter
 */
void w_inc_modules_syscollector_dropped_events();

/**
 * @brief Increment modules upgrade dropped events counter
 */
void w_inc_modules_upgrade_dropped_events();

/**
 * @brief Increment modules vulnerability dropped events counter
 */
void w_inc_modules_vulnerability_dropped_events();

/**
 * @brief Increment modules logcollector eventchannel dropped events counter
 */
void w_inc_modules_logcollector_eventchannel_dropped_events();

/**
 * @brief Increment modules logcollector eventlog dropped events counter
 */
void w_inc_modules_logcollector_eventlog_dropped_events();

/**
 * @brief Increment modules logcollector macos dropped events counter
 */
void w_inc_modules_logcollector_macos_dropped_events();

/**
 * @brief Increment modules logcollector others dropped events counter
 */
void w_inc_modules_logcollector_others_dropped_events();

/**
 * @brief Increment processed events counter
 * @param agent_id Id of the agent that corresponds to the event
 */
void w_inc_processed_events(const char *agent_id);

/**
 * @brief Increment alerts written counter
 * @param agent_id Id of the agent that corresponds to the event
 */
void w_inc_alerts_written(const char *agent_id);

/**
 * @brief Increment archives written counter
 * @param agent_id Id of the agent that corresponds to the event
 */
void w_inc_archives_written(const char *agent_id);

/**
 * @brief Increment firewall written counter
 * @param agent_id Id of the agent that corresponds to the event
 */
void w_inc_firewall_written(const char *agent_id);

/**
 * @brief Increment fts written counter
 */
void w_inc_fts_written();

/**
 * @brief Increment stats written counter
 */
void w_inc_stats_written();

/**
 * @brief Increment events dropped by eps
 */
void w_inc_eps_events_dropped();

/**
 * @brief Increment events dropped by causes unrelated to eps
 */
void w_inc_eps_events_dropped_not_eps();

/**
 * @brief Increment seconds over eps limit
 */
void w_inc_eps_seconds_over_limit();

/**
 * @brief Set available credits from previous interval
 * @param credits Credits from previous interval
 */
void w_set_available_credits_prev(unsigned int credits);

/**
 * @brief Create a JSON object with all the analysisd state information
 * @return JSON object
 */
cJSON* asys_create_state_json();

/**
 * @brief Create a JSON object with all the analysisd agents state information
 * @param agents_ids Ids of the requested agents
 * @return JSON object
 */
cJSON* asys_create_agents_state_json(int* agents_ids);

#endif /* STATE_A_H */
