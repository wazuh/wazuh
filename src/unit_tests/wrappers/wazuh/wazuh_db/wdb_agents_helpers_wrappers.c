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

cJSON* __wrap_wdb_agents_vuln_cves_insert(int id,
                                          const char *name,
                                          const char *version,
                                          const char *architecture,
                                          const char *cve,
                                          const char *reference,
                                          const char *type,
                                          const char *status,
                                          bool check_pkg_existence,
                                          __attribute__((unused)) int *sock) {
    check_expected(id);
    check_expected(name);
    check_expected(version);
    check_expected(architecture);
    check_expected(cve);
    check_expected(reference);
    check_expected(type);
    check_expected(status);
    check_expected(check_pkg_existence);
    return mock_ptr_type(cJSON*);
}

int __wrap_wdb_agents_vuln_cves_clear(int id,
                                     __attribute__((unused)) int *sock) {
    check_expected(id);
    return mock_type(int);
}

cJSON* __wrap_wdb_agents_vuln_cves_remove_by_status(int id,
                                                    const char *status,
                                                    __attribute__((unused)) int *sock) {
    check_expected(id);
    check_expected(status);
    return mock_ptr_type(cJSON*);
}

int __wrap_wdb_agents_vuln_cves_update_status(int id,
                                       const char *old_status,
                                       const char *new_status,
                                       __attribute__((unused)) int *sock) {
    check_expected(id);
    check_expected(old_status);
    check_expected(new_status);
    return mock_type(int);
}
