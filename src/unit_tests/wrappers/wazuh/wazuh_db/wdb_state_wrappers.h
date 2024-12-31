/*
 * Wazuh Shared Configuration Manager
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 1, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WDB_STATE_WRAPPERS_H
#define WDB_STATE_WRAPPERS_H

#include "../wazuh_db/wdb.h"

cJSON* __wrap_wdb_create_state_json();

// Total counters

void __wrap_w_inc_queries_total();

// Global counters

void __wrap_w_inc_global();

void __wrap_w_inc_global_open_time();

void __wrap_w_inc_global_sql();

void __wrap_w_inc_global_sql_time();

void __wrap_w_inc_global_backup();

void __wrap_w_inc_global_backup_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_vacuum();

void __wrap_w_inc_global_vacuum_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_get_fragmentation();

void __wrap_w_inc_global_get_fragmentation_time(__attribute__((unused))struct timeval diff);

// Global agent counters

void __wrap_w_inc_global_agent_insert_agent();

void __wrap_w_inc_global_agent_insert_agent_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_update_agent_data();

void __wrap_w_inc_global_agent_update_agent_data_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_update_agent_name();

void __wrap_w_inc_global_agent_update_agent_name_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_update_keepalive();

void __wrap_w_inc_global_agent_update_keepalive_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_update_connection_status();

void __wrap_w_inc_global_agent_update_connection_status_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_update_status_code();

void __wrap_w_inc_global_agent_update_status_code_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_reset_agents_connection();

void __wrap_w_inc_global_agent_reset_agents_connection_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_delete_agent();

void __wrap_w_inc_global_agent_delete_agent_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_select_agent_name();

void __wrap_w_inc_global_agent_select_agent_name_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_select_agent_group();

void __wrap_w_inc_global_agent_select_agent_group_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_find_agent();

void __wrap_w_inc_global_agent_find_agent_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_get_agent_info();

void __wrap_w_inc_global_agent_get_agent_info_by_connection_status_and_node();

void __wrap_w_inc_global_agent_get_agent_info_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_get_agent_info_by_connection_status_and_node_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_get_all_agents();

void __wrap_w_inc_global_agent_get_all_agents_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_get_agents_by_connection_status();

void __wrap_w_inc_global_agent_get_agents_by_connection_status_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_disconnect_agents();

void __wrap_w_inc_global_agent_disconnect_agents_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_sync_agent_info_get();

void __wrap_w_inc_global_agent_sync_agent_info_get_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_sync_agent_info_set();

void __wrap_w_inc_global_agent_sync_agent_info_set_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_sync_agent_groups_get();

void __wrap_w_inc_global_agent_sync_agent_groups_get_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_set_agent_groups();

void __wrap_w_inc_global_agent_set_agent_groups_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_get_groups_integrity();

void __wrap_w_inc_global_agent_get_groups_integrity_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_get_distinct_groups();

void __wrap_w_inc_global_agent_get_distinct_groups_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_agent_recalculate_agent_group_hashes();

void __wrap_w_inc_global_agent_recalculate_agent_group_hashes_time(__attribute__((unused))struct timeval diff);

// Global group counters

void __wrap_w_inc_global_group_insert_agent_group();

void __wrap_w_inc_global_group_insert_agent_group_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_group_delete_group();

void __wrap_w_inc_global_group_delete_group_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_group_select_groups();

void __wrap_w_inc_global_group_select_groups_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_group_find_group();

void __wrap_w_inc_global_group_find_group_time(__attribute__((unused))struct timeval diff);

// Global belongs counters

void __wrap_w_inc_global_belongs_select_group_belong();

void __wrap_w_inc_global_belongs_select_group_belong_time(__attribute__((unused))struct timeval diff);

void __wrap_w_inc_global_belongs_get_group_agent();

void __wrap_w_inc_global_belongs_get_group_agent_time(__attribute__((unused))struct timeval diff);

// Global labels counters

void __wrap_w_inc_global_labels_get_labels();

void __wrap_w_inc_global_labels_get_labels_time(__attribute__((unused))struct timeval diff);

#endif /* WDB_STATE_WRAPPERS_H */
