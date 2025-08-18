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

typedef struct _queries_breakdown_t {
    uint64_t global_queries;
    uint64_t task_queries;
    global_breakdown_t global_breakdown;
    task_breakdown_t task_breakdown;
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
 * @brief Create a JSON object with all the wazuh-db state information
 * @return JSON object
 */
cJSON* wdb_create_state_json();

#endif
