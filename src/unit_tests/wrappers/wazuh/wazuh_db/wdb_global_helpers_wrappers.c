/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "wdb_global_helpers_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

cJSON* __wrap_wdb_get_agent_labels(int id,__attribute__((unused)) int *sock) {
    check_expected(id);
    return mock_ptr_type(cJSON*);
}

int __wrap_wdb_find_agent(const char *name, const char *ip, __attribute__((unused)) int *sock) {
    check_expected(name);
    check_expected(ip);
    return mock();
}

int* __wrap_wdb_disconnect_agents(int keepalive, const char *sync_status, __attribute__((unused)) int *sock) {
    check_expected(keepalive);
    check_expected(sync_status);
    return mock_ptr_type(int*);
}

cJSON* __wrap_wdb_get_agent_info(int id, __attribute__((unused)) int *sock) {
    check_expected(id);
    return mock_ptr_type(cJSON*);
}

int* __wrap_wdb_get_agents_by_connection_status(const char* status, __attribute__((unused)) int *sock) {
    check_expected(status);

    return mock_ptr_type(int*);
}

int* __wrap_wdb_get_agents_ids_of_current_node(const char* status, __attribute__((unused)) int *sock, int last_id, int limit) {
    check_expected(status);
    check_expected(last_id);
    check_expected(limit);
    return mock_ptr_type(int*);
}

int* __wrap_wdb_get_all_agents(bool include_manager, __attribute__((unused)) int *sock) {
    check_expected(include_manager);
    return mock_ptr_type(int*);
}

rb_tree* __wrap_wdb_get_all_agents_rbtree(bool include_manager, __attribute__((unused)) int *sock) {
    check_expected(include_manager);
    return mock_ptr_type(rb_tree*);
}

int __wrap_wdb_update_agent_keepalive(int id, const char *connection_status, const char *sync_status, __attribute__((unused)) int *sock) {
    check_expected(id);
    check_expected(connection_status);
    check_expected(sync_status);
    return mock();
}

int __wrap_wdb_update_agent_data(agent_info_data *agent_data, __attribute__((unused)) int *sock) {
    check_expected(agent_data);
    return mock();
}

int __wrap_wdb_update_agent_connection_status(int id, const char *connection_status, const char *sync_status, __attribute__((unused)) int *sock) {
    check_expected(id);
    check_expected(connection_status);
    check_expected(sync_status);
    return mock();
}

int __wrap_wdb_update_agent_status_code(int id, agent_status_code_t status_code, const char *version, const char *sync_status, __attribute__((unused)) int *sock) {
    check_expected(id);
    check_expected(status_code);
    check_expected(version);
    check_expected(sync_status);
    return mock();
}

int __wrap_wdb_set_agent_groups_csv(int id,
                                    __attribute__((unused)) char *groups_csv,
                                    __attribute__((unused)) char *mode,
                                    __attribute__((unused)) char *sync_status,
                                    __attribute__((unused)) int *sock) {
    check_expected(id);
    return mock();
}

int __wrap_wdb_set_agent_groups(int id,
                                __attribute__((unused)) char** groups_array,
                                char* mode,
                                char* sync_status,
                                __attribute__((unused)) int *sock) {
    check_expected(id);
    check_expected(mode);
    check_expected(sync_status);
    return mock();
}

char* __wrap_wdb_get_agent_group(int id,
                                 __attribute__((unused)) int *wdb_sock) {
    check_expected(id);
    return mock_type(char *);
}



char* __wrap_wdb_get_agent_name(int id,
                                __attribute__((unused)) int *wdb_sock) {
    check_expected(id);
    return mock_type(char *);
}

int __wrap_wdb_remove_agent_db(int id, const char* name) {
    check_expected(id);
    if (name) {
        check_expected(name);
    }
    return mock();
}

cJSON* __wrap_wdb_get_distinct_agent_groups(__attribute__((unused)) int *sock) {
    return mock_ptr_type(cJSON*);
}

int __wrap_wdb_insert_agent(int id, const char *name, __attribute__((unused)) const char *ip, const char *register_ip,
                            const char *internal_key, const char *group, int keep_date, __attribute__((unused)) int *sock) {
    check_expected(id);
    check_expected(name);
    check_expected(register_ip);
    check_expected(internal_key);
    if (group) {
        check_expected(group);
    }
    check_expected(keep_date);
    return mock();
}

int __wrap_wdb_remove_agent(int id, __attribute__((unused)) int *sock) {
    check_expected(id);
    return mock();
}
