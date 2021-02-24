/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "wdb_agents_helpers_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>

int __wrap_wdb_agents_vuln_cve_insert(int id,
                                      const char *name,
                                      const char *version,
                                      const char *architecture,
                                      const char *cve,
                                      __attribute__((unused)) int *sock) {
    check_expected(id);
    check_expected(name);
    check_expected(version);
    check_expected(architecture);
    check_expected(cve);
    return mock_type(int);
}

int __wrap_wdb_agents_vuln_cve_clear(int id,
                                     __attribute__((unused)) int *sock) {
    check_expected(id);
    return mock_type(int);
}
