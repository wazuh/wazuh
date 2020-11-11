/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WDB_GLOBAL_WRAPPERS_H
#define WDB_GLOBAL_WRAPPERS_H

#include "wazuh_db/wdb.h"

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
                                    const char *sync_status);

cJSON* __wrap_wdb_global_get_agent_labels(wdb_t *wdb, int id);

int __wrap_wdb_global_del_agent_labels(wdb_t *wdb, int id);

int __wrap_wdb_global_set_agent_label(wdb_t *wdb, int id, char* key, char* value);

int __wrap_wdb_global_update_agent_keepalive(wdb_t *wdb, int id, char* status);

int __wrap_wdb_global_delete_agent(wdb_t *wdb, int id);

cJSON* __wrap_wdb_global_select_agent_name(wdb_t *wdb, int id);

cJSON* __wrap_wdb_global_select_agent_group(wdb_t *wdb, int id);

int __wrap_wdb_global_delete_agent_belong(wdb_t *wdb, int id);

cJSON* __wrap_wdb_global_find_agent(wdb_t *wdb, const char *name, const char *ip);

cJSON* __wrap_wdb_global_select_agent_status(wdb_t *wdb, int id);

int __wrap_wdb_global_update_agent_status(wdb_t *wdb, int id, char *status);

int __wrap_wdb_global_update_agent_group(wdb_t *wdb, int id, char *group);

cJSON* __wrap_wdb_global_find_group(wdb_t *wdb, char* group_name);

int __wrap_wdb_global_insert_agent_group(wdb_t *wdb, char* group_name);

int __wrap_wdb_global_insert_agent_belong(wdb_t *wdb, int id_group, int id_agent);

int __wrap_wdb_global_delete_group_belong(wdb_t *wdb, char* group_name);

int __wrap_wdb_global_delete_group(wdb_t *wdb, char* group_name);

cJSON* __wrap_wdb_global_select_groups(wdb_t *wdb);

cJSON* __wrap_wdb_global_select_agent_keepalive(wdb_t *wdb, char* name, char* ip);

wdbc_result __wrap_wdb_global_sync_agent_info_get(wdb_t *wdb, int* last_agent_id, char **output);

int __wrap_wdb_global_sync_agent_info_set(wdb_t *wdb,cJSON * json_agent);

wdbc_result __wrap_wdb_global_get_agents_by_keepalive(wdb_t *wdb, int* last_agent_id, char comparator, int keep_alive, char **output);

wdbc_result __wrap_wdb_global_get_all_agents(wdb_t *wdb, int* last_agent_id, char **output);

cJSON* __wrap_wdb_global_get_agent_info(wdb_t *wdb, int id);

int __wrap_wdb_global_check_manager_keepalive(wdb_t *wdb);

#endif
