/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WDB_GLOBAL_WRAPPERS_H
#define WDB_GLOBAL_WRAPPERS_H

#include "../wazuh_db/wdb.h"

int __wrap_wdb_global_insert_agent(wdb_t *wdb, int id, char* name, char* ip, char* register_ip, char* internal_key,char* group, int date_add);

int __wrap_wdb_global_update_agent_name(wdb_t *wdb, int id, char* name);

int __wrap_wdb_global_update_agent_version(wdb_t *wdb,
                                           int id,
                                           const char *os_name,
                                           const char *os_version,
                                           const char *os_major,
                                           const char *os_minor,
                                           const char *os_codename,
                                           const char *os_platform,
                                           const char *os_build,
                                           const char *os_uname,
                                           const char *os_arch,
                                           const char *version,
                                           const char *config_sum,
                                           const char *merged_sum,
                                           const char *manager_host,
                                           const char *node_name,
                                           const char *agent_ip,
                                           const char *connection_status,
                                           const char *sync_status,
                                           const char *group_config_status);

cJSON* __wrap_wdb_global_get_agent_labels(wdb_t *wdb, int id);

int __wrap_wdb_global_del_agent_labels(wdb_t *wdb, int id);

int __wrap_wdb_global_set_agent_label(wdb_t *wdb, int id, char* key, char* value);

int __wrap_wdb_global_update_agent_keepalive(wdb_t *wdb, int id, char* connection_status, char* status);

int __wrap_wdb_global_update_agent_connection_status(wdb_t *wdb, int id, char* connection_status, char* sync_status, int status_code);

int __wrap_wdb_global_update_agent_status_code(wdb_t *wdb, int id, int status_code, const char *version, const char *sync_status);

int __wrap_wdb_global_delete_agent(wdb_t *wdb, int id);

cJSON* __wrap_wdb_global_select_agent_name(wdb_t *wdb, int id);

cJSON* __wrap_wdb_global_select_agent_group(wdb_t *wdb, int id);

cJSON* __wrap_wdb_global_get_group_agents(wdb_t *wdb, wdbc_result *status, char *group_name, int last_agent_id);

int __wrap_wdb_global_delete_agent_belong(wdb_t *wdb, int id);

cJSON* __wrap_wdb_global_find_agent(wdb_t *wdb, const char *name, const char *ip);

cJSON* __wrap_wdb_global_find_group(wdb_t *wdb, char* group_name);

int __wrap_wdb_global_insert_agent_group(wdb_t *wdb, char* group_name);

cJSON* __wrap_wdb_global_select_group_belong(wdb_t *wdb, int id_agent);

int __wrap_wdb_global_insert_agent_belong(wdb_t *wdb, int id_group, int id_agent);

int __wrap_wdb_global_delete_group(wdb_t *wdb, char* group_name);

wdbc_result __wrap_wdb_global_set_agent_groups(__attribute__((unused)) wdb_t *wdb, wdb_groups_set_mode_t mode, char *sync_status, cJSON *j_agents_group_info);

cJSON* __wrap_wdb_global_select_groups(wdb_t *wdb);

wdbc_result __wrap_wdb_global_sync_agent_info_get(wdb_t *wdb, int* last_agent_id, char **output);

int __wrap_wdb_global_sync_agent_info_set(wdb_t *wdb,cJSON * json_agent);

cJSON* __wrap_wdb_global_get_all_agents(wdb_t *wdb, int last_agent_id, wdbc_result* status);

int __wrap_wdb_global_get_all_agents_context(wdb_t *wdb);

cJSON* __wrap_wdb_global_get_agent_info(wdb_t *wdb, int id);

int __wrap_wdb_global_reset_agents_connection(wdb_t *wdb, const char *sync_status);

cJSON* __wrap_wdb_global_get_agents_by_connection_status (wdb_t *wdb, int last_agent_id, const char* connection_status, const char* node_name, int limit, wdbc_result* status);

wdbc_result __wrap_wdb_global_sync_agent_groups_get(__attribute__((unused)) wdb_t *wdb, wdb_groups_sync_condition_t condition, int last_agent_id, bool set_synced, bool get_hash, int agent_registration_delta, cJSON **output);

cJSON* __wrap_wdb_global_get_groups_integrity(wdb_t *wdb, os_sha1 hash);

cJSON* __wrap_wdb_global_get_agents_to_disconnect(wdb_t *wdb, int last_agent_id, int keep_alive, const char *sync_status, wdbc_result* status);

int __wrap_wdb_global_agent_exists(wdb_t *wdb, int agent_id);

int __wrap_wdb_global_adjust_v4(wdb_t* wdb);

cJSON* __wrap_wdb_global_get_backups();

time_t __wrap_wdb_global_get_most_recent_backup(char **most_recent_backup_name);

int __wrap_wdb_global_create_backup(wdb_t* wdb, char* output, const char* tag);

int __wrap_wdb_global_restore_backup(wdb_t** wdb, char* snapshot, bool save_pre_restore_state, char* output);

int __wrap_wdb_remove_group_db(const char *name, int *sock);

cJSON* __wrap_wdb_global_get_distinct_agent_groups(   __attribute__((unused)) wdb_t *wdb, char *group_hash, wdbc_result* status);

int __wrap_wdb_global_recalculate_all_agent_groups_hash(__attribute__((unused)) wdb_t *wdb);

cJSON* __wrap_wdb_global_get_group_all_agents(wdb_t* wdb, const char* group_name);

cJSON *__wrap_wdb_global_sync_agent_groups_get_all(wdb_t *wdb, wdb_groups_sync_condition_t condition, bool set_synced, bool get_hash, int agent_registration_delta);

cJSON *__wrap_wdb_global_select_group_belong_agent_id(wdb_t *wdb, int agent_id);

cJSON *__wrap_wdb_global_get_summary(wdb_t *wdb, cJSON *parameters_json);

cJSON *__wrap_wdb_global_sync_agent_info_get_api(wdb_t *wdb);

int __wrap_wdb_global_sync_agent_info_set_np(wdb_t *wdb, cJSON *parameters_json);

#endif
