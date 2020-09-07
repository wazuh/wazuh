/* Copyright (C) 2015-2020, Wazuh Inc.
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

