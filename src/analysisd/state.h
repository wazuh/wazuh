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

#include <stdint.h>

OSHash *analysisd_agents_state;

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

typedef struct _events_decoded_t {
    uint64_t syscheck;
    uint64_t syscollector;
    uint64_t rootcheck;
    uint64_t sca;
    uint64_t hostinfo;
    uint64_t winevt;
    uint64_t dbsync;
    uint64_t upgrade;
    uint64_t events;
} events_decoded_t;

typedef struct _events_dropped_t {
    uint64_t syscheck;
    uint64_t syscollector;
    uint64_t rootcheck;
    uint64_t sca;
    uint64_t hostinfo;
    uint64_t winevt;
    uint64_t dbsync;
    uint64_t upgrade;
    uint64_t events;
} events_dropped_t;

typedef struct _events_unknown_t {
    uint64_t syscheck;
    uint64_t syscollector;
    uint64_t rootcheck;
    uint64_t sca;
    uint64_t hostinfo;
    uint64_t winevt;
    uint64_t dbsync;
    uint64_t upgrade;
    uint64_t events;
} events_unknown_t;

typedef struct _events_recv_t {
    events_decoded_t events_decoded_breakdown;
    events_dropped_t events_dropped_breakdown;
    events_unknown_t events_unknown_breakdown;
} events_recv_t;

typedef struct _analysisd_state_t {
    uint64_t received_bytes;
    uint64_t events_received;
    uint64_t events_processed;
    uint64_t alerts_written;
    uint64_t archives_written;
    uint32_t firewall_written;
    uint32_t fts_written;
    uint32_t stats_written;
    events_recv_t events_received_breakdown;
} analysisd_state_t;

typedef struct _analysisd_agent_state_t {
    int id;
    uint64_t events_processed;
    uint64_t alerts_written;
    uint64_t archives_written;
    uint32_t firewall_written;
    events_decoded_t events_decoded_breakdown;
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
 * @brief Increment syscheck decoded events counter
 */
void w_inc_syscheck_decoded_events(char * agent_id);

/**
 * @brief Increment syscollector decoded events counter
 */
void w_inc_syscollector_decoded_events(char * agent_id);

/**
 * @brief Increment rootcheck decoded events counter
 */
void w_inc_rootcheck_decoded_events(char * agent_id);

/**
 * @brief Increment sca decoded events counter
 */
void w_inc_sca_decoded_events(char * agent_id);

/**
 * @brief Increment hostinfo decoded events counter
 */
void w_inc_hostinfo_decoded_events(char * agent_id);

/**
 * @brief Increment winevt decoded events counter
 */
void w_inc_winevt_decoded_events(char * agent_id);

/**
 * @brief Increment dbsync decoded events counter
 */
void w_inc_dbsync_decoded_events(char * agent_id);

/**
 * @brief Increment upgrade decoded events counter
 */
void w_inc_upgrade_decoded_events(char * agent_id);

/**
 * @brief Increment other decoded events counter
 */
void w_inc_events_decoded(char * agent_id);

/**
 * @brief Increment syscheck dropped events counter
 */
void w_inc_syscheck_dropped_events();

/**
 * @brief Increment syscollector dropped events counter
 */
void w_inc_syscollector_dropped_events();

/**
 * @brief Increment rootcheck dropped events counter
 */
void w_inc_rootcheck_dropped_events();

/**
 * @brief Increment sca dropped events counter
 */
void w_inc_sca_dropped_events();

/**
 * @brief Increment hostinfo dropped events counter
 */
void w_inc_hostinfo_dropped_events();

/**
 * @brief Increment winevt dropped events counter
 */
void w_inc_winevt_dropped_events();

/**
 * @brief Increment dbsync dropped events counter
 */
void w_inc_dbsync_dropped_events();

/**
 * @brief Increment upgrade dropped events counter
 */
void w_inc_upgrade_dropped_events();

/**
 * @brief Increment other dropped events counter
 */
void w_inc_events_dropped();

/**
 * @brief Increment syscheck unknown events counter
 */
void w_inc_syscheck_unknown_events();

/**
 * @brief Increment syscollector unknown events counter
 */
void w_inc_syscollector_unknown_events();

/**
 * @brief Increment rootcheck unknown events counter
 */
void w_inc_rootcheck_unknown_events();

/**
 * @brief Increment sca unknown events counter
 */
void w_inc_sca_unknown_events();

/**
 * @brief Increment hostinfo unknown events counter
 */
void w_inc_hostinfo_unknown_events();

/**
 * @brief Increment winevt unknown events counter
 */
void w_inc_winevt_unknown_events();

/**
 * @brief Increment dbsync unknown events counter
 */
void w_inc_dbsync_unknown_events();

/**
 * @brief Increment upgrade unknown events counter
 */
void w_inc_upgrade_unknown_events();

/**
 * @brief Increment other unknown events counter
 */
void w_inc_events_unknown();

/**
 * @brief Increment processed events counter
 */
void w_inc_processed_events(char * agent_id);

/**
 * @brief Increment alerts written counter
 */
void w_inc_alerts_written(char * agent_id);

/**
 * @brief Increment archives written counter
 */
void w_inc_archives_written(char * agent_id);

/**
 * @brief Increment firewall written counter
 */
void w_inc_firewall_written(char * agent_id);

/**
 * @brief Increment fts written counter
 */
void w_inc_fts_written();

/**
 * @brief Increment stats written counter
 */
void w_inc_stats_written();

/**
 * @brief Create a JSON object with all the analysisd state information
 * @return JSON object
 */
cJSON* asys_create_state_json();

#endif /* STATE_A_H */
