/*
 * Copyright (C) 2015, Wazuh Inc.
 * May 03, 2022
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef STATEWDB_H
#define STATEWDB_H

#include <stdint.h>
#include <sys/time.h>
#include "wdb.h"

/* Status structures */

typedef struct _agent_ciscat_t {
    uint64_t ciscat_queries;
    struct timeval ciscat_time;
} agent_ciscat_t;

typedef struct _agent_rootcheck_t {
    uint64_t rootcheck_queries;
    struct timeval rootcheck_time;
} agent_rootcheck_t;

typedef struct _agent_sca_t {
    uint64_t sca_queries;
    struct timeval sca_time;
} agent_sca_t;

typedef struct _agent_sync_t {
    uint64_t dbsync_queries;
    struct timeval dbsync_time;
} agent_sync_t;

typedef struct _agent_syscheck_t {
    uint64_t fim_file_queries;
    uint64_t fim_registry_queries;
    uint64_t fim_registry_key_queries;
    uint64_t fim_registry_value_queries;
    uint64_t syscheck_queries;
    struct timeval fim_file_time;
    struct timeval fim_registry_time;
    struct timeval fim_registry_key_time;
    struct timeval fim_registry_value_time;
    struct timeval syscheck_time;
} agent_syscheck_t;

typedef struct _agent_syscollector_deprecated_t {
    uint64_t hardware_queries;
    uint64_t hotfix_queries;
    uint64_t netaddr_queries;
    uint64_t netinfo_queries;
    uint64_t netproto_queries;
    uint64_t osinfo_queries;
    uint64_t package_queries;
    uint64_t port_queries;
    uint64_t process_queries;
    struct timeval hardware_time;
    struct timeval hotfix_time;
    struct timeval netaddr_time;
    struct timeval netinfo_time;
    struct timeval netproto_time;
    struct timeval osinfo_time;
    struct timeval package_time;
    struct timeval port_time;
    struct timeval process_time;
} agent_syscollector_deprecated_t;

typedef struct _agent_syscollector_t {
    uint64_t syscollector_hotfixes_queries;
    uint64_t syscollector_hwinfo_queries;
    uint64_t syscollector_network_address_queries;
    uint64_t syscollector_network_iface_queries;
    uint64_t syscollector_network_protocol_queries;
    uint64_t syscollector_osinfo_queries;
    uint64_t syscollector_packages_queries;
    uint64_t syscollector_ports_queries;
    uint64_t syscollector_processes_queries;
    uint64_t syscollector_users_queries;
    uint64_t syscollector_groups_queries;
    struct timeval syscollector_hotfixes_time;
    struct timeval syscollector_hwinfo_time;
    struct timeval syscollector_network_address_time;
    struct timeval syscollector_network_iface_time;
    struct timeval syscollector_network_protocol_time;
    struct timeval syscollector_osinfo_time;
    struct timeval syscollector_packages_time;
    struct timeval syscollector_ports_time;
    struct timeval syscollector_processes_time;
    struct timeval syscollector_users_time;
    struct timeval syscollector_groups_time;
    agent_syscollector_deprecated_t deprecated;
} agent_syscollector_t;

typedef struct _agent_breakdown_t {
    uint64_t begin_queries;
    uint64_t close_queries;
    uint64_t commit_queries;
    uint64_t remove_queries;
    uint64_t sql_queries;
    uint64_t vacuum_queries;
    uint64_t get_fragmentation_queries;
    uint64_t sleep_queries;
    struct timeval begin_time;
    struct timeval close_time;
    struct timeval commit_time;
    struct timeval remove_time;
    struct timeval sql_time;
    struct timeval vacuum_time;
    struct timeval get_fragmentation_time;
    struct timeval open_calls_time;
    struct timeval sleep_time;
    agent_ciscat_t ciscat;
    agent_rootcheck_t rootcheck;
    agent_sca_t sca;
    agent_sync_t sync;
    agent_syscheck_t syscheck;
    agent_syscollector_t syscollector;
} agent_breakdown_t;

typedef struct _global_agent_t {
    uint64_t delete_agent_queries;
    uint64_t disconnect_agents_queries;
    uint64_t find_agent_queries;
    uint64_t get_agent_info_queries;
    uint64_t get_agents_by_connection_status_queries;
    uint64_t get_all_agents_queries;
    uint64_t get_distinct_groups_queries;
    uint64_t get_groups_integrity_queries;
    uint64_t recalculate_agent_group_hashes_queries;
    uint64_t insert_agent_queries;
    uint64_t reset_agents_connection_queries;
    uint64_t select_agent_group_queries;
    uint64_t select_agent_name_queries;
    uint64_t set_agent_groups_queries;
    uint64_t sync_agent_groups_get_queries;
    uint64_t sync_agent_info_get_queries;
    uint64_t sync_agent_info_set_queries;
    uint64_t update_agent_data_queries;
    uint64_t update_agent_name_queries;
    uint64_t update_connection_status_queries;
    uint64_t update_status_code_queries;
    uint64_t update_keepalive_queries;
    struct timeval delete_agent_time;
    struct timeval disconnect_agents_time;
    struct timeval find_agent_time;
    struct timeval get_agent_info_time;
    struct timeval get_agents_by_connection_status_time;
    struct timeval get_all_agents_time;
    struct timeval get_distinct_groups_time;
    struct timeval get_groups_integrity_time;
    struct timeval recalculate_agent_group_hashes_time;
    struct timeval insert_agent_time;
    struct timeval reset_agents_connection_time;
    struct timeval select_agent_group_time;
    struct timeval select_agent_name_time;
    struct timeval set_agent_groups_time;
    struct timeval sync_agent_groups_get_time;
    struct timeval sync_agent_info_get_time;
    struct timeval sync_agent_info_set_time;
    struct timeval update_agent_data_time;
    struct timeval update_agent_name_time;
    struct timeval update_connection_status_time;
    struct timeval update_status_code_time;
    struct timeval update_keepalive_time;
} global_agent_t;

typedef struct _global_belongs_t {
    uint64_t get_group_agent_queries;
    uint64_t select_group_belong_queries;
    struct timeval get_group_agent_time;
    struct timeval select_group_belong_time;
} global_belongs_t;

typedef struct _global_group_t {
    uint64_t delete_group_queries;
    uint64_t find_group_queries;
    uint64_t insert_agent_group_queries;
    uint64_t select_groups_queries;
    struct timeval delete_group_time;
    struct timeval find_group_time;
    struct timeval insert_agent_group_time;
    struct timeval select_groups_time;
} global_group_t;

typedef struct _global_labels_t {
    uint64_t get_labels_queries;
    struct timeval get_labels_time;
} global_labels_t;

typedef struct _global_breakdown_t {
    uint64_t backup_queries;
    uint64_t sql_queries;
    uint64_t vacuum_queries;
    uint64_t get_fragmentation_queries;
    uint64_t sleep_queries;
    struct timeval backup_time;
    struct timeval sql_time;
    struct timeval vacuum_time;
    struct timeval get_fragmentation_time;
    struct timeval open_calls_time;
    struct timeval sleep_time;
    global_agent_t agent;
    global_belongs_t belongs;
    global_group_t group;
    global_labels_t labels;
} global_breakdown_t;

typedef struct _mitre_breakdown_t {
    uint64_t sql_queries;
    struct timeval sql_time;
} mitre_breakdown_t;

typedef struct _task_tasks_t {
    uint64_t delete_old_queries;
    uint64_t set_timeout_queries;
    uint64_t upgrade_queries;
    uint64_t upgrade_cancel_tasks_queries;
    uint64_t upgrade_custom_queries;
    uint64_t upgrade_get_status_queries;
    uint64_t upgrade_result_queries;
    uint64_t upgrade_update_status_queries;
    struct timeval delete_old_time;
    struct timeval set_timeout_time;
    struct timeval upgrade_time;
    struct timeval upgrade_cancel_tasks_time;
    struct timeval upgrade_custom_time;
    struct timeval upgrade_get_status_time;
    struct timeval upgrade_result_time;
    struct timeval upgrade_update_status_time;
} task_tasks_t;

typedef struct _task_breakdown_t {
    uint64_t sql_queries;
    struct timeval sql_time;
    task_tasks_t tasks;
} task_breakdown_t;

typedef struct _wazuhdb_breakdown_t {
    uint64_t remove_queries;
    struct timeval remove_time;
} wazuhdb_breakdown_t;

typedef struct _queries_breakdown_t {
    uint64_t agent_queries;
    uint64_t global_queries;
    uint64_t mitre_queries;
    uint64_t task_queries;
    uint64_t wazuhdb_queries;
    agent_breakdown_t agent_breakdown;
    global_breakdown_t global_breakdown;
    mitre_breakdown_t mitre_breakdown;
    task_breakdown_t task_breakdown;
    wazuhdb_breakdown_t wazuhdb_breakdown;
} queries_breakdown_t;

typedef struct _db_stats_t {
    uint64_t uptime;
    uint64_t queries_total;
    queries_breakdown_t queries_breakdown;
} wdb_state_t;

/* Status functions */

/**
 * @brief Increment total queries counter
 *
 */
void w_inc_queries_total();

/**
 * @brief Increment total wazuhdb queries counter
 *
 */
void w_inc_wazuhdb();

/**
 * @brief Increment remove wazuhdb queries counter
 *
 */
void w_inc_wazuhdb_remove();

/**
 * @brief Increment remove wazuhdb time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_wazuhdb_remove_time(struct timeval time);

/**
 * @brief Increment total agent queries counter
 *
 */
void w_inc_agent();

/**
 * @brief Increment open agent DB time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_open_time(struct timeval time);

/**
 * @brief Increment sql agent queries counter
 *
 */
void w_inc_agent_sql();

/**
 * @brief Increment sql agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_sql_time(struct timeval time);

/**
 * @brief Increment remove agent queries counter
 *
 */
void w_inc_agent_remove();

/**
 * @brief Increment remove agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_remove_time(struct timeval time);

/**
 * @brief Increment begin agent queries counter
 *
 */
void w_inc_agent_begin();

/**
 * @brief Increment begin agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_begin_time(struct timeval time);

/**
 * @brief Increment commit agent queries counter
 *
 */
void w_inc_agent_commit();

/**
 * @brief Increment commit agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_commit_time(struct timeval time);

/**
 * @brief Increment close agent queries counter
 *
 */
void w_inc_agent_close();

/**
 * @brief Increment close agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_close_time(struct timeval time);

/**
 * @brief Increment vacuum agent queries counter
 *
 */
void w_inc_agent_vacuum();

/**
 * @brief Increment vacuum agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_vacuum_time(struct timeval time);

/**
 * @brief Increment get_fragmentation agent queries counter
 *
 */
void w_inc_agent_get_fragmentation();

/**
 * @brief Increment get_fragmentation agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_get_fragmentation_time(struct timeval time);

/**
 * @brief Increment rootcheck agent queries counter
 *
 */
void w_inc_agent_rootcheck();

/**
 * @brief Increment rootcheck agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_rootcheck_time(struct timeval time);

/**
 * @brief Increment sca agent queries counter
 *
 */
void w_inc_agent_sca();

/**
 * @brief Increment sca agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_sca_time(struct timeval time);

/**
 * @brief Increment ciscat agent queries counter
 *
 */
void w_inc_agent_ciscat();

/**
 * @brief Increment ciscat agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_ciscat_time(struct timeval time);

/**
 * @brief Increment dbsync agent queries counter
 *
 */
void w_inc_agent_dbsync();

/**
 * @brief Increment dbsync agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_dbsync_time(struct timeval time);

/**
 * @brief Increment syscheck agent queries counter
 *
 */
void w_inc_agent_syscheck();

/**
 * @brief Increment syscheck agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_syscheck_time(struct timeval time);

/**
 * @brief Increment fim file agent queries counter
 *
 */
void w_inc_agent_fim_file();

/**
 * @brief Increment fim file agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_fim_file_time(struct timeval time);

/**
 * @brief Increment fim registry agent queries counter
 *
 */
void w_inc_agent_fim_registry();

/**
 * @brief Increment fim registry agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_fim_registry_time(struct timeval time);

/**
 * @brief Increment fim registry key agent queries counter
 *
 */
void w_inc_agent_fim_registry_key();

/**
 * @brief Increment fim registry key agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_fim_registry_key_time(struct timeval time);

/**
 * @brief Increment fim registry value agent queries counter
 *
 */
void w_inc_agent_fim_registry_value();

/**
 * @brief Increment fim registry value agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_fim_registry_value_time(struct timeval time);

/**
 * @brief Increment syscollector processes agent queries counter
 *
 */
void w_inc_agent_syscollector_processes();

/**
 * @brief Increment syscollector packages agent queries counter
 *
 */
void w_inc_agent_syscollector_packages();

/**
 * @brief Increment syscollector hotfixes agent queries counter
 *
 */
void w_inc_agent_syscollector_hotfixes();

/**
 * @brief Increment syscollector ports agent queries counter
 *
 */
void w_inc_agent_syscollector_ports();

/**
 * @brief Increment syscollector network protocol agent queries counter
 *
 */
void w_inc_agent_syscollector_network_protocol();

/**
 * @brief Increment syscollector network address agent queries counter
 *
 */
void w_inc_agent_syscollector_network_address();

/**
 * @brief Increment syscollector network interface agent queries counter
 *
 */
void w_inc_agent_syscollector_network_iface();

/**
 * @brief Increment syscollector hardware information agent queries counter
 *
 */
void w_inc_agent_syscollector_hwinfo();

/**
 * @brief Increment syscollector OS information agent queries counter
 *
 */
void w_inc_agent_syscollector_osinfo();

/**
 * @brief Increment syscollector users information agent queries counter
 *
 */
void w_inc_agent_syscollector_users();

/**
 * @brief Increment syscollector groups information agent queries counter
 *
 */
void w_inc_agent_syscollector_groups();

/**
 * @brief Increment syscollector agent time counter
 *
 * @param time Value to increment the counter.
 * @param type Syscollector event type.
 */
void w_inc_agent_syscollector_times(struct timeval time, int type);

/**
 * @brief Increment deprecated syscollector processes agent queries counter
 *
 */
void w_inc_agent_syscollector_deprecated_process();

/**
 * @brief Increment deprecated process syscollector agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_syscollector_deprecated_process_time(struct timeval time);

/**
 * @brief Increment deprecated syscollector packages agent queries counter
 *
 */
void w_inc_agent_syscollector_deprecated_packages();

/**
 * @brief Increment deprecated packages syscollector agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_syscollector_deprecated_packages_time(struct timeval time);

/**
 * @brief Increment deprecated syscollector hotfixes agent queries counter
 *
 */
void w_inc_agent_syscollector_deprecated_hotfixes();

/**
 * @brief Increment deprecated hotfixes syscollector agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_syscollector_deprecated_hotfixes_time(struct timeval time);

/**
 * @brief Increment deprecated syscollector ports agent queries counter
 *
 */
void w_inc_agent_syscollector_deprecated_ports();

/**
 * @brief Increment deprecated ports syscollector agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_syscollector_deprecated_ports_time(struct timeval time);

/**
 * @brief Increment deprecated syscollector network protocol agent queries counter
 *
 */
void w_inc_agent_syscollector_deprecated_network_protocol();

/**
 * @brief Increment deprecated network protocol syscollector agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_syscollector_deprecated_network_protocol_time(struct timeval time);

/**
 * @brief Increment deprecated syscollector network address agent queries counter
 *
 */
void w_inc_agent_syscollector_deprecated_network_address();

/**
 * @brief Increment deprecated network address syscollector agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_syscollector_deprecated_network_address_time(struct timeval time);

/**
 * @brief Increment deprecated syscollector network information agent queries counter
 *
 */
void w_inc_agent_syscollector_deprecated_network_info();

/**
 * @brief Increment deprecated network information syscollector agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_syscollector_deprecated_network_info_time(struct timeval time);

/**
 * @brief Increment deprecated syscollector hardware agent queries counter
 *
 */
void w_inc_agent_syscollector_deprecated_hardware();

/**
 * @brief Increment deprecated hardware syscollector agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_syscollector_deprecated_hardware_time(struct timeval time);

/**
 * @brief Increment deprecated syscollector OS information agent queries counter
 *
 */
void w_inc_agent_syscollector_deprecated_osinfo();

/**
 * @brief Increment deprecated OS information syscollector agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_syscollector_deprecated_osinfo_time(struct timeval time);

/**
 * @brief Increment deprecated syscollector OS information agent queries counter
 *
 */
void w_inc_agent_sleep();

/**
 * @brief Increment deprecated OS information syscollector agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_agent_sleep_time(struct timeval time);

/**
 * @brief Increment total global queries counter
 *
 */
void w_inc_global();

/**
 * @brief Increment open global time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_open_time(struct timeval time);

/**
 * @brief Increment sql global queries counter
 *
 */
void w_inc_global_sql();

/**
 * @brief Increment sql global time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_sql_time(struct timeval time);

/**
 * @brief Increment backup global queries counter
 *
 */
void w_inc_global_backup();

/**
 * @brief Increment backup global time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_backup_time(struct timeval time);

/**
 * @brief Increment insert-agent global agent queries counter
 *
 */
void w_inc_global_agent_insert_agent();

/**
 * @brief Increment insert-agent global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_insert_agent_time(struct timeval time);

/**
 * @brief Increment update-agent-data global agent queries counter
 *
 */
void w_inc_global_agent_update_agent_data();

/**
 * @brief Increment update-agent-data global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_update_agent_data_time(struct timeval time);

/**
 * @brief Increment update-agent-name global agent queries counter
 *
 */
void w_inc_global_agent_update_agent_name();

/**
 * @brief Increment update-agent-name global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_update_agent_name_time(struct timeval time);

/**
 * @brief Increment update-keepalive global agent queries counter
 *
 */
void w_inc_global_agent_update_keepalive();

/**
 * @brief Increment update-keepalive global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_update_keepalive_time(struct timeval time);

/**
 * @brief Increment update-connection-status global agent queries counter
 *
 */
void w_inc_global_agent_update_connection_status();

/**
 * @brief Increment update-connection-status global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_update_connection_status_time(struct timeval time);

/**
 * @brief Increment update-status-code global agent queries counter
 *
 */
void w_inc_global_agent_update_status_code();

/**
 * @brief Increment update-status-code global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_update_status_code_time(struct timeval time);

/**
 * @brief Increment reset-agents-connection global agent queries counter
 *
 */
void w_inc_global_agent_reset_agents_connection();

/**
 * @brief Increment reset-agents-connection global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_reset_agents_connection_time(struct timeval time);

/**
 * @brief Increment delete-agent global agent queries counter
 *
 */
void w_inc_global_agent_delete_agent();

/**
 * @brief Increment delete-agent global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_delete_agent_time(struct timeval time);

/**
 * @brief Increment select-agent-name global agent queries counter
 *
 */
void w_inc_global_agent_select_agent_name();

/**
 * @brief Increment select-agent-name global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_select_agent_name_time(struct timeval time);

/**
 * @brief Increment select-agent-group global agent queries counter
 *
 */
void w_inc_global_agent_select_agent_group();

/**
 * @brief Increment select-agent-group global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_select_agent_group_time(struct timeval time);

/**
 * @brief Increment find-agent global agent queries counter
 *
 */
void w_inc_global_agent_find_agent();

/**
 * @brief Increment find-agent global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_find_agent_time(struct timeval time);

/**
 * @brief Increment get-agent-info global agent queries counter
 *
 */
void w_inc_global_agent_get_agent_info();

/**
 * @brief Increment get-agent-info global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_get_agent_info_time(struct timeval time);

/**
 * @brief Increment get-all-agents global agent queries counter
 *
 */
void w_inc_global_agent_get_all_agents();

/**
 * @brief Increment get-all-agents global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_get_all_agents_time(struct timeval time);

/**
 * @brief Increment get-distinct-groups global agent queries counter
 *
 */
void w_inc_global_agent_get_distinct_groups();

/**
 * @brief Increment get-distinct-groups global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_get_distinct_groups_time(struct timeval time);

/**
 * @brief Increment get-agents-by-connection-status global agent queries counter
 *
 */
void w_inc_global_agent_get_agents_by_connection_status();

/**
 * @brief Increment get-agents-by-connection-status global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_get_agents_by_connection_status_time(struct timeval time);

/**
 * @brief Increment disconnect-agents global agent queries counter
 *
 */
void w_inc_global_agent_disconnect_agents();

/**
 * @brief Increment disconnect-agents global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_disconnect_agents_time(struct timeval time);

/**
 * @brief Increment sync-agent-info-get global agent queries counter
 *
 */
void w_inc_global_agent_sync_agent_info_get();

/**
 * @brief Increment sync-agent-info-get global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_sync_agent_info_get_time(struct timeval time);

/**
 * @brief Increment sync-agent-info-set global agent queries counter
 *
 */
void w_inc_global_agent_sync_agent_info_set();

/**
 * @brief Increment sync-agent-info-set global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_sync_agent_info_set_time(struct timeval time);

/**
 * @brief Increment sync-agent-groups-get global agent queries counter
 *
 */
void w_inc_global_agent_sync_agent_groups_get();

/**
 * @brief Increment sync-agent-groups-get global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_sync_agent_groups_get_time(struct timeval time);

/**
 * @brief Increment set-agent-groups global agent queries counter
 *
 */
void w_inc_global_agent_set_agent_groups();

/**
 * @brief Increment set-agent-groups global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_set_agent_groups_time(struct timeval time);

/**
 * @brief Increment get-groups-integrity global agent queries counter
 *
 */
void w_inc_global_agent_get_groups_integrity();

/**
 * @brief Increment get-groups-integrity global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_get_groups_integrity_time(struct timeval time);

/**
 * @brief Increment recalculate-agent-group-hashes global agent queries counter
 *
 */
void w_inc_global_agent_recalculate_agent_group_hashes();

/**
 * @brief Increment recalculate-agent-group-hashes global agent time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_agent_recalculate_agent_group_hashes_time(struct timeval time);

/**
 * @brief Increment insert-agent-group global group queries counter
 *
 */
void w_inc_global_group_insert_agent_group();

/**
 * @brief Increment insert-agent-group global group time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_group_insert_agent_group_time(struct timeval time);

/**
 * @brief Increment delete-group global group queries counter
 *
 */
void w_inc_global_group_delete_group();

/**
 * @brief Increment delete-group global group time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_group_delete_group_time(struct timeval time);

/**
 * @brief Increment select-groups global group queries counter
 *
 */
void w_inc_global_group_select_groups();

/**
 * @brief Increment select-groups global group time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_group_select_groups_time(struct timeval time);

/**
 * @brief Increment find-group global group queries counter
 *
 */
void w_inc_global_group_find_group();

/**
 * @brief Increment find-group global group time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_group_find_group_time(struct timeval time);

/**
 * @brief Increment select-group-belong global belongs queries counter
 *
 */
void w_inc_global_belongs_select_group_belong();

/**
 * @brief Increment select-group-belong global belongs time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_belongs_select_group_belong_time(struct timeval time);

/**
 * @brief Increment get-group-agent global belongs queries counter
 *
 */
void w_inc_global_belongs_get_group_agent();

/**
 * @brief Increment get-group-agent global belongs time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_belongs_get_group_agent_time(struct timeval time);

/**
 * @brief Increment get-labels global labels queries counter
 *
 */
void w_inc_global_labels_get_labels();

/**
 * @brief Increment get-labels global labels time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_labels_get_labels_time(struct timeval time);

/**
 * @brief Increment vacuum global queries counter
 *
 */
void w_inc_global_vacuum();

/**
 * @brief Increment vacuum global time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_vacuum_time(struct timeval time);

/**
 * @brief Increment get_fragmentation global queries counter
 *
 */
void w_inc_global_get_fragmentation();

/**
 * @brief Increment get_fragmentation global time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_get_fragmentation_time(struct timeval time);

/**
 * @brief Increment sleep global queries counter
 *
 */
void w_inc_global_sleep();

/**
 * @brief Increment sleep global time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_global_sleep_time(struct timeval time);

/**
 * @brief Increment task queries counter
 *
 */
void w_inc_task();

/**
 * @brief Increment sql task queries counter
 *
 */
void w_inc_task_sql();

/**
 * @brief Increment sql task time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_task_sql_time(struct timeval time);

/**
 * @brief Increment set-timeout task queries counter
 *
 */
void w_inc_task_set_timeout();

/**
 * @brief Increment set-timeout task time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_task_set_timeout_time(struct timeval time);

/**
 * @brief Increment delete-old task queries counter
 *
 */
void w_inc_task_delete_old();

/**
 * @brief Increment delete-old task time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_task_delete_old_time(struct timeval time);

/**
 * @brief Increment upgrade task queries counter
 *
 */
void w_inc_task_upgrade();

/**
 * @brief Increment upgrade task time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_task_upgrade_time(struct timeval time);

/**
 * @brief Increment custom upgrade task queries counter
 *
 */
void w_inc_task_upgrade_custom();

/**
 * @brief Increment custom upgrade task time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_task_upgrade_custom_time(struct timeval time);

/**
 * @brief Increment get-status upgrade task queries counter
 *
 */
void w_inc_task_upgrade_get_status();

/**
 * @brief Increment get-status upgrade task time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_task_upgrade_get_status_time(struct timeval time);

/**
 * @brief Increment update-status upgrade task queries counter
 *
 */
void w_inc_task_upgrade_update_status();

/**
 * @brief Increment update-status upgrade task time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_task_upgrade_update_status_time(struct timeval time);

/**
 * @brief Increment result upgrade task queries counter
 *
 */
void w_inc_task_upgrade_result();

/**
 * @brief Increment result upgrade task time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_task_upgrade_result_time(struct timeval time);

/**
 * @brief Increment cancel-tasks upgrade task queries counter
 *
 */
void w_inc_task_upgrade_cancel_tasks();

/**
 * @brief Increment cancel-tasks upgrade task time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_task_upgrade_cancel_tasks_time(struct timeval time);

/**
 * @brief Increment mitre queries counter
 *
 */
void w_inc_mitre();

/**
 * @brief Increment sql mitre queries counter
 *
 */
void w_inc_mitre_sql();

/**
 * @brief Increment sql mitre time counter
 *
 * @param time Value to increment the counter.
 */
void w_inc_mitre_sql_time(struct timeval time);

/**
 * @brief Create a JSON object with all the wazuh-db state information
 * @return JSON object
 */
cJSON* wdb_create_state_json();

#endif
