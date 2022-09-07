/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WDB_GLOBAL_HELPERS_WRAPPERS_H
#define WDB_GLOBAL_HELPERS_WRAPPERS_H

#include "wazuh_db/wdb.h"

cJSON *__wrap_wdb_get_agent_labels(int id, int *sock);
int __wrap_wdb_find_agent(const char *name, const char *ip, __attribute__((unused)) int *sock);
int* __wrap_wdb_disconnect_agents(int keepalive, const char *sync_status, __attribute__((unused)) int *sock);
cJSON* __wrap_wdb_get_agent_info(int id, __attribute__((unused)) int *sock);
int* __wrap_wdb_get_agents_by_connection_status(const char* status, __attribute__((unused)) int *sock);
int* __wrap_wdb_get_agents_ids_of_current_node(const char* status, __attribute__((unused)) int *sock, int last_id, int limit);
int* __wrap_wdb_get_all_agents(bool include_manager, int *sock);
int __wrap_wdb_update_agent_keepalive(int id, const char *connection_status, const char *sync_status, __attribute__((unused)) int *sock);
int __wrap_wdb_update_agent_data(agent_info_data *agent_data, __attribute__((unused)) int *sock);
int __wrap_wdb_update_agent_connection_status(int id, const char *connection_status, const char *sync_status, __attribute__((unused)) int *sock);

int __wrap_wdb_set_agent_groups_csv(int id,
                                    __attribute__((unused)) char *groups_csv,
                                    __attribute__((unused)) char *mode,
                                    __attribute__((unused)) char *sync_status,
                                    __attribute__((unused)) int *sock);

int __wrap_wdb_set_agent_groups(int id,
                                __attribute__((unused)) char** groups_array,
                                char* mode,
                                char* sync_status,
                                __attribute__((unused)) int *sock);

char* __wrap_wdb_get_agent_group(int id, int *wdb_sock);

char* __wrap_wdb_get_agent_name(int id, __attribute__((unused)) int *wdb_sock);

int __wrap_wdb_remove_agent_db(int id, const char* name);
#endif
