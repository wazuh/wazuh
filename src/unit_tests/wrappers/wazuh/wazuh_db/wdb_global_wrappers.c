/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "wdb_global_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_wdb_global_insert_agent(__attribute__((unused)) wdb_t *wdb,
                                   int id,
                                   char* name,
                                   char* ip,
                                   char* register_ip,
                                   char* internal_key,
                                   char* group,
                                   int date_add) {
    check_expected(id);
    check_expected(name);
    check_expected(ip);
    check_expected(register_ip);
    check_expected(internal_key);
    check_expected(group);
    check_expected(date_add);

    return mock();
}

int __wrap_wdb_global_update_agent_name(__attribute__((unused)) wdb_t *wdb,
                                        int id,
                                        char* name) {
    check_expected(id);
    check_expected(name);

    return mock();
}

int __wrap_wdb_global_update_agent_version(__attribute__((unused)) wdb_t *wdb,
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
                                           const char *group_config_status) {
    check_expected(id);
    check_expected(os_name);
    check_expected(os_version);
    check_expected(os_major);
    check_expected(os_minor);
    check_expected(os_codename);
    check_expected(os_platform);
    check_expected(os_build);
    check_expected(os_uname);
    check_expected(os_arch);
    check_expected(version);
    check_expected(config_sum);
    check_expected(merged_sum);
    check_expected(manager_host);
    check_expected(node_name);
    check_expected(agent_ip);
    check_expected(connection_status);
    check_expected(sync_status);
    check_expected(group_config_status);

    return mock();
}

cJSON* __wrap_wdb_global_get_agent_labels(__attribute__((unused)) wdb_t *wdb,
                                          int id) {
    check_expected(id);
    return mock_ptr_type(cJSON*);
}

int __wrap_wdb_global_del_agent_labels(__attribute__((unused)) wdb_t *wdb,
                                       int id) {
    check_expected(id);
    return mock();
}

int __wrap_wdb_global_set_agent_label(__attribute__((unused)) wdb_t *wdb,
                                      int id,
                                      char* key,
                                      char* value){
    check_expected(id);
    check_expected(key);
    check_expected(value);
    return mock();
}

int __wrap_wdb_global_update_agent_keepalive(__attribute__((unused)) wdb_t *wdb,
                                            int id,
                                            char* connection_status,
                                            char* status) {
    check_expected(id);
    check_expected(connection_status);
    check_expected(status);
    return mock();
}

int __wrap_wdb_global_update_agent_connection_status(__attribute__((unused)) wdb_t *wdb,
                                                     int id,
                                                     char* connection_status,
                                                     char* sync_status,
                                                     int status_code) {
    check_expected(id);
    check_expected(connection_status);
    check_expected(sync_status);
    check_expected(status_code);
    return mock();
}

int __wrap_wdb_global_update_agent_status_code(__attribute__((unused)) wdb_t *wdb,
                                                   int id,
                                                   int status_code,
                                                   const char *version,
                                                   const char *sync_status) {
    check_expected(id);
    check_expected(status_code);
    check_expected(version);
    check_expected(sync_status);
    return mock();
}

int __wrap_wdb_global_delete_agent(__attribute__((unused)) wdb_t *wdb,
                                   int id) {
    check_expected(id);
    return mock();
}

cJSON* __wrap_wdb_global_select_agent_name(__attribute__((unused)) wdb_t *wdb,
                                           int id) {
    check_expected(id);
    return mock_ptr_type(cJSON*);
}

cJSON* __wrap_wdb_global_select_agent_group(__attribute__((unused)) wdb_t *wdb,
                                            int id) {
    check_expected(id);
    return mock_ptr_type(cJSON*);
}

cJSON* __wrap_wdb_global_get_group_agents(__attribute__((unused)) wdb_t *wdb,
                                          wdbc_result* status,
                                          char* group_name,
                                          int last_agent_id) {

    check_expected(group_name);
    check_expected(last_agent_id);
    *status = mock();
    return mock_ptr_type(cJSON*);
}

int __wrap_wdb_global_delete_agent_belong(__attribute__((unused)) wdb_t *wdb,
                                          int id) {
    check_expected(id);
    return mock();
}

cJSON* __wrap_wdb_global_find_agent(__attribute__((unused)) wdb_t *wdb,
                                    const char *name,
                                    const char *ip) {
    check_expected(name);
    check_expected(ip);
    return mock_ptr_type(cJSON*);
}

cJSON* __wrap_wdb_global_find_group(__attribute__((unused)) wdb_t *wdb,
                                    char *group_name) {
    check_expected(group_name);
    return mock_ptr_type(cJSON*);
}

int __wrap_wdb_global_insert_agent_group(__attribute__((unused)) wdb_t *wdb,
                                         char *group_name) {
    check_expected(group_name);
    return mock();
}

cJSON* __wrap_wdb_global_select_group_belong(__attribute__((unused)) wdb_t *wdb,
                                             int id_agent) {
    check_expected(id_agent);
    return mock_ptr_type(cJSON*);
}

int __wrap_wdb_global_insert_agent_belong(__attribute__((unused)) wdb_t *wdb,
                                          int id_group,
                                          int id_agent) {
    check_expected(id_group);
    check_expected(id_agent);
    return mock();
}

int __wrap_wdb_global_delete_group( __attribute__((unused)) wdb_t *wdb,
                                    char *group_name) {
    check_expected(group_name);
    return mock();
}

wdbc_result __wrap_wdb_global_set_agent_groups(__attribute__((unused)) wdb_t *wdb,
                                               wdb_groups_set_mode_t mode,
                                               char *sync_status,
                                               cJSON *j_agents_group_info) {
    check_expected(mode);
    check_expected(sync_status);
    char *agents_group_info = cJSON_PrintUnformatted(j_agents_group_info);
    check_expected(agents_group_info);
    os_free(agents_group_info);
    return mock();
}

cJSON* __wrap_wdb_global_select_groups(__attribute__((unused)) wdb_t *wdb) {
    return mock_ptr_type(cJSON*);
}

wdbc_result __wrap_wdb_global_sync_agent_info_get(__attribute__((unused)) wdb_t *wdb,
                                                  int* last_agent_id,
                                                  char **output) {
    check_expected(*last_agent_id);
    os_strdup(mock_ptr_type(char*), *output);
    return mock();
}

int __wrap_wdb_global_sync_agent_info_set(__attribute__((unused)) wdb_t *wdb,
                                          cJSON *json_agent) {
    char *str_agent = cJSON_PrintUnformatted(json_agent);
    check_expected(str_agent);
    os_free(str_agent);
    return mock();
}

cJSON* __wrap_wdb_global_get_all_agents(   __attribute__((unused)) wdb_t *wdb,
                                                int last_agent_id,
                                                wdbc_result* status) {
    check_expected(last_agent_id);
    *status = mock();
    return mock_ptr_type(cJSON*);
}

int __wrap_wdb_global_get_all_agents_context(   __attribute__((unused)) wdb_t *wdb) {
    return mock();
}

cJSON* __wrap_wdb_global_get_agent_info(__attribute__((unused)) wdb_t *wdb,
                                        int id){
    check_expected(id);
    return mock_ptr_type(cJSON*);
}

int __wrap_wdb_global_reset_agents_connection(__attribute__((unused)) wdb_t *wdb, const char *sync_status) {
    check_expected(sync_status);
    return mock();
}

cJSON* __wrap_wdb_global_get_agents_by_connection_status (__attribute__((unused)) wdb_t *wdb,
                                                               int last_agent_id,
                                                               const char* connection_status,
                                                               const char* node_name,
                                                               int limit,
                                                               wdbc_result* status) {
    check_expected(last_agent_id);
    check_expected(connection_status);
    *status = mock();
    if (node_name) {
        check_expected(node_name);
        check_expected(limit);
    }
    return mock_ptr_type(cJSON*);
}

wdbc_result __wrap_wdb_global_sync_agent_groups_get(__attribute__((unused)) wdb_t *wdb,
                                                    wdb_groups_sync_condition_t condition,
                                                    int last_agent_id,
                                                    bool set_synced,
                                                    bool get_hash,
                                                    int agent_registration_delta,
                                                    cJSON **output) {
    check_expected(condition);
    check_expected(last_agent_id);
    check_expected(set_synced);
    check_expected(get_hash);
    check_expected(agent_registration_delta);
    *output = mock_ptr_type(cJSON*);
    return mock();
}

cJSON* __wrap_wdb_global_get_groups_integrity(__attribute__((unused)) wdb_t *wdb,
                                              os_sha1 hash) {

    check_expected(hash);
    return mock_ptr_type(cJSON*);
}

cJSON* __wrap_wdb_global_get_agents_to_disconnect(__attribute__((unused)) wdb_t *wdb,
                                                  int last_agent_id,
                                                  int keep_alive,
                                                  const char *sync_status,
                                                  wdbc_result* status) {
    check_expected(last_agent_id);
    check_expected(keep_alive);
    check_expected(sync_status);
    *status = mock();
    return mock_ptr_type(cJSON*);
}

int __wrap_wdb_global_agent_exists(wdb_t *wdb, int agent_id) {
    check_expected_ptr(wdb);
    check_expected(agent_id);
    return mock();
}

int __wrap_wdb_global_adjust_v4(__attribute__((unused)) wdb_t* wdb) {
    return mock();
}

cJSON* __wrap_wdb_global_get_backups() {
    return mock_ptr_type(cJSON*);
}

time_t __wrap_wdb_global_get_most_recent_backup(char **most_recent_backup_name) {
    char *name = NULL;
    if (name = mock_ptr_type(char*), name) {
        os_strdup(name, *most_recent_backup_name);
    }
    return mock();
}

int __wrap_wdb_global_create_backup(__attribute__((unused)) wdb_t* wdb,
                                    char* output,
                                    const char* tag) {
    snprintf(output, OS_MAXSTR + 1, "%s%s", mock_ptr_type(char*), tag ? tag : "");
    return mock();
}

int __wrap_wdb_global_restore_backup(__attribute__((unused)) wdb_t** wdb,
                                     char* snapshot,
                                     bool save_pre_restore_state,
                                     __attribute__((unused)) char* output) {
    if (snapshot) {check_expected(snapshot);}
    check_expected(save_pre_restore_state);
    return mock();
}

int __wrap_wdb_remove_group_db(const char *name,
                               __attribute__((unused)) int *sock) {
    check_expected(name);
    return mock();
}

cJSON* __wrap_wdb_global_get_distinct_agent_groups(   __attribute__((unused)) wdb_t *wdb, char *group_hash,
                                                wdbc_result* status) {
    check_expected(group_hash);
    *status = mock();
    return mock_ptr_type(cJSON*);
}

int __wrap_wdb_global_recalculate_all_agent_groups_hash(__attribute__((unused)) wdb_t *wdb) {
    return mock();
}

cJSON* __wrap_wdb_global_get_group_all_agents(wdb_t* wdb, const char* group_name) {
    check_expected_ptr(wdb);
    check_expected_ptr(group_name);
    return mock_ptr_type(cJSON*);
}

cJSON *__wrap_wdb_global_sync_agent_groups_get_all(wdb_t *wdb, wdb_groups_sync_condition_t condition, bool set_synced, bool get_hash, int agent_registration_delta) {
    check_expected_ptr(wdb);
    check_expected(condition);
    check_expected(set_synced);
    check_expected(get_hash);
    check_expected(agent_registration_delta);
    return mock_ptr_type(cJSON *);
}

cJSON *__wrap_wdb_global_select_group_belong_agent_id(wdb_t *wdb, int agent_id) {
    check_expected_ptr(wdb);
    check_expected(agent_id);
    return mock_ptr_type(cJSON *);
}

cJSON *__wrap_wdb_global_get_summary(wdb_t *wdb, cJSON *parameters_json) {
    check_expected_ptr(wdb);
    check_expected_ptr(parameters_json);
    return mock_ptr_type(cJSON *);
}

cJSON *__wrap_wdb_global_sync_agent_info_get_np(wdb_t *wdb) {
    check_expected_ptr(wdb);
    return mock_ptr_type(cJSON *);
}

int __wrap_wdb_global_sync_agent_info_set_np(wdb_t *wdb, cJSON *parameters_json) {
    check_expected_ptr(wdb);
    check_expected_ptr(parameters_json);
    return mock_type(int);
}