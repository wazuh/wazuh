/*
 * Copyright (C) 2015, Wazuh Inc.
 * May 03, 2022
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <cstdint>

typedef struct _db_stats_t {
    char *version;
    char *deamon_name;
    uint64_t timestamp;
    statistics_t statistics;
} db_stats_t;

typedef struct _statistics_t {
    uint64_t queries_total;
    uint64_t queries_time_total;
    queries_breakdown_t queries_breakdown;
} statistics_t;


typedef struct _queries_breakdown_t {
    uint64_t wazuhdb_queries;
    uint64_t wazuhdb_time;
    uint64_t agent_queries;
    uint64_t agent_time;
    uint64_t global_queries;
    uint64_t global_time;
    uint64_t task_queries;
    uint64_t task_time;
    uint64_t mitre_queries;
    uint64_t mitre_time;
    uint64_t unknown_queries;

    wazuhdb_queries_breakdown_t wazuhdb_queries_breakdown;
    agent_queries_breakdown_t agent_queries_breakdown;
    agent_time_breakdown_t agent_time_breakdown;
    global_queries_breakdown_ global_queries_breakdown;
    global_time_breakdown_t global_time_breakdown;
    task_queries_breakdown_t task_queries_breakdown;
    task_time_breakdown_t task_time_breakdown;
    mitre_queries_breakdown_t mitre_queries_breakdown;
} queries_breakdown_t;

typedef struct _wazuhdb_queries_breakdown_t {
    uint64_t remove_queries;
    uint64_t unknown_queries;
} wazuhdb_queries_breakdown_t;

typedef struct _agent_queries_breakdown_t {
    uint64_t sql_queries;
    uint64_t remove_queries;
    uint64_t begin_queries;
    uint64_t commit_queries;
    uint64_t close_queries;
    uint64_t rootcheck_queries;
    uint64_t sca_queries;
    uint64_t ciscat_queries;
    uint64_t vulnerability_detector_queries;
    uint64_t dbsync_queries;
    uint64_t unknown_queries;

    syscheck_queries_t syscheck_queries;
    syscollector_queries_t syscollector_queries;
} agent_queries_breakdown_t;

typedef struct _syscheck_queries_t {
    uint64_t syscheck_queries;
    uint64_t fim_file_queries;
    uint64_t fim_registry_queries;
} syscheck_queries_t;

typedef struct _syscollector_queries_t {
    uint64_t syscollector_processes_queries;
    uint64_t syscollector_packages_queries;
    uint64_t syscollector_hotfixes_queries;
    uint64_t syscollector_ports_queries;
    uint64_t syscollector_network_protocol_queries;
    uint64_t syscollector_network_address_queries;
    uint64_t syscollector_network_iface_queries;
    uint64_t syscollector_hwinfo_queries;
    uint64_t syscollector_osinfo_queries;
    uint64_t process_queries;
    uint64_t package_queries;
    uint64_t hotfix_queries;
    uint64_t port_queries;
    uint64_t netproto_queries;
    uint64_t netaddr_queries;
    uint64_t netinfo_queries;
    uint64_t hardware_queries;
    uint64_t osinfo_queries;
} syscollector_queries_t;

typedef struct _agent_time_breakdown_t {
    uint64_t sql_time;
    uint64_t remove_time;
    uint64_t begin_time;
    uint64_t commit_time;
    uint64_t close_time;
    uint64_t rootcheck_time;
    uint64_t sca_time;
    uint64_t ciscat_time;
    uint64_t vulnerability_detector_time;
    uint64_t dbsync_time;

    syscheck_time_t syscheck_time;
    syscollector_time_t syscollector_time;
} agent_time_breakdown_t;

typedef struct _syscheck_time_t {
    uint64_t syscheck_time;
    uint64_t fim_file_time;
    uint64_t fim_registry_time;
} syscheck_time_t;

typedef struct _syscollector_time_t {
    uint64_t syscollector_processes_time;
    uint64_t syscollector_packages_time;
    uint64_t syscollector_hotfixes_time;
    uint64_t syscollector_ports_time;
    uint64_t syscollector_network_protocol_time;
    uint64_t syscollector_network_address_time;
    uint64_t syscollector_network_iface_time;
    uint64_t syscollector_hwinfo_time;
    uint64_t syscollector_osinfo_time;
    uint64_t process_time;
    uint64_t package_time;
    uint64_t hotfix_time;
    uint64_t port_time;
    uint64_t netproto_time;
    uint64_t netaddr_time;
    uint64_t netinfo_time;
    uint64_t hardware_time;
    uint64_t osinfo_time;
} syscollector_time_t;

typedef struct _global_queries_breakdown_ {
    uint64_t sql_queries;
    uint64_t unknown_queries;

    agent_queries_t agent_queries;
    group_queries_t group_queries;
    belongs_queries_t belongs_queries;
    labels_queries_t labels_queries;
} global_queries_breakdown_;

typedef struct _agent_queries_t {
    uint64_t insert_agent_queries;
    uint64_t update_agent_data_queries;
    uint64_t update_agent_name_queries;
    uint64_t update_agent_group_queries;
    uint64_t update_keepalive_queries;
    uint64_t update_connection_status_queries;
    uint64_t reset_agents_connection_queries;
    uint64_t sync_agent_info_set_queries;
    uint64_t delete_agent_queries;
    uint64_t select_agent_name_queries;
    uint64_t select_agent_group_queries;
    uint64_t select_keepalive_queries;
    uint64_t find_agent_queries;
    uint64_t get_agent_info_queries;
    uint64_t get_all_agents_queries;
    uint64_t get_agents_by_connection_status_queries;
    uint64_t disconnect_agents_queries;
    uint64_t sync_agent_info_get_queries;
} agent_queries_t;

typedef struct _group_queries_t {
    uint64_t insert_agent_group_queries;
    uint64_t delete_group_queries;
    uint64_t select_groups_queries;
    uint64_t find_group_queries;
} group_queries_t;

typedef struct _belongs_queries_t {
    uint64_t insert_agent_belong_queries;
    uint64_t delete_agent_belong_queries;
    uint64_t delete_group_belong_queries;
} belongs_queries_t;

typedef struct _labels_queries_t {
    uint64_t set_labels_queries;
    uint64_t get_labels_queries;
} labels_queries_t;

typedef struct _global_time_breakdown_t {
    uint64_t sql_time;

    agent_time_t agent_time;
    group_time_t group_time;
    belongs_time_t belongs_time;
    labels_time_t labels_time;
} global_time_breakdown_t;

typedef struct _agent_time_t {
    uint64_t insert_agent_time;
    uint64_t update_agent_data_time;
    uint64_t update_agent_name_time;
    uint64_t update_agent_group_time;
    uint64_t update_keepalive_time;
    uint64_t update_connection_status_time;
    uint64_t reset_agents_connection_time;
    uint64_t sync_agent_info_set_time;
    uint64_t delete_agent_time;
    uint64_t select_agent_name_time;
    uint64_t select_agent_group_time;
    uint64_t select_keepalive_time;
    uint64_t find_agent_time;
    uint64_t get_agent_info_time;
    uint64_t get_all_agents_time;
    uint64_t get_agents_by_connection_status_time;
    uint64_t disconnect_agents_time;
    uint64_t sync_agent_info_get_time;
} agent_time_t;

typedef struct _group_time_t {
    uint64_t insert_agent_group_time;
    uint64_t delete_group_time;
    uint64_t select_groups_time;
    uint64_t find_group_time;
} group_time_t;

typedef struct _belongs_time_t {
    uint64_t insert_agent_belong_time;
    uint64_t delete_agent_belong_time;
    uint64_t delete_group_belong_time;
} belongs_time_t;

typedef struct _labels_time_t {
    uint64_t set_labels_time;
    uint64_t get_labels_time;
} labels_time_t;

typedef struct _task_queries_breakdown_t {
    uint64_t sql_queries;
    uint64_t set_timeout_queries;
    uint64_t delete_old_queries;
    uint64_t unknown_queries;

    upgrade_queries_t upgrade_queries;
} task_queries_breakdown_t;

typedef struct _upgrade_queries_t {
    uint64_t upgrade_queries;
    uint64_t upgrade_custom_queries;
    uint64_t upgrade_get_status_queries;
    uint64_t upgrade_update_status_queries;
    uint64_t upgrade_result_queries;
    uint64_t upgrade_cancel_tasks_queries;
} upgrade_queries_t;

typedef struct _task_time_breakdown_t {
    uint64_t sql_time;
    uint64_t set_timeout_time;
    uint64_t delete_old_time;

    upgrade_time_t upgrade_time;
} task_time_breakdown_t;

typedef struct _upgrade_time_t {
    uint64_t upgrade_time;
    uint64_t upgrade_custom_time;
    uint64_t upgrade_get_status_time;
    uint64_t upgrade_update_status_time;
    uint64_t upgrade_result_time;
    uint64_t upgrade_cancel_tasks_time;
} upgrade_time_t;

typedef struct _mitre_queries_breakdown_t {
    uint64_t sql_queries;
    uint64_t unknown_queries;
} mitre_queries_breakdown_t;