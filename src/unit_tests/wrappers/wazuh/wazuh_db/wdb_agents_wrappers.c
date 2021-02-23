/* Copyright (C) 2015-2020, Wazuh Inc.
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

int __wrap_wdb_agents_insert_vuln_cve( __attribute__((unused)) wdb_t *wdb, const char* name, const char* version, const char* architecture, const char* cve) {
    check_expected(name);
    check_expected(version);
    check_expected(architecture);
    check_expected(cve);
    return mock();
}

int __wrap_wdb_agents_clear_vuln_cve( __attribute__((unused)) wdb_t *wdb) {
    return mock();
}
