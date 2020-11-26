/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "wdb_agent_wrappers.h"
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
