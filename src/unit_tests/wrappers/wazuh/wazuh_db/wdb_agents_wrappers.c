/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "wdb_agents_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

cJSON* __wrap_wdb_agents_get_sys_osinfo(__attribute__((unused)) wdb_t *wdb) {
    return mock_ptr_type(cJSON*);
}

bool __wrap_wdb_agents_find_package(__attribute__((unused)) wdb_t *wdb, const char* reference){
    check_expected(reference);
    return mock();
}

int __wrap_wdb_agents_send_packages(__attribute__((unused)) wdb_t *wdb) {
    return mock();
}

int __wrap_wdb_agents_get_packages(__attribute__((unused)) wdb_t *wdb, cJSON** response) {
    *response = mock_ptr_type(cJSON*);
    return mock();
}

int __wrap_wdb_agents_get_hotfixes(__attribute__((unused)) wdb_t *wdb, cJSON** response) {
    *response = mock_ptr_type(cJSON*);
    return mock();
}
