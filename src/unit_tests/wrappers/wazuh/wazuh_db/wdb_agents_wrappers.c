/* Copyright (C) 2015-2021, Wazuh Inc.
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

cJSON* __wrap_wdb_agents_insert_vuln_cves(__attribute__((unused)) wdb_t *wdb,
                                          const char* name,
                                          const char* version,
                                          const char* architecture,
                                          const char* cve,
                                          const char* reference,
                                          const char* type,
                                          const char* status,
                                          bool check_pkg_existance) {
    check_expected(name);
    check_expected(version);
    check_expected(architecture);
    check_expected(cve);
    check_expected(reference);
    check_expected(type);
    check_expected(status);
    check_expected(check_pkg_existance);
    return mock_ptr_type(cJSON*);
}

int __wrap_wdb_agents_update_status_vuln_cves(__attribute__((unused)) wdb_t *wdb, const char* old_status, const char* new_status, const char* type) {
    check_expected(old_status);
    check_expected(new_status);
    check_expected(type);
    return mock();
}

int __wrap_wdb_agents_remove_vuln_cves(__attribute__((unused)) wdb_t *wdb, const char* cve, const char* reference) {
    check_expected(cve);
    check_expected(reference);
    return mock();
}

wdbc_result __wrap_wdb_agents_remove_by_status_vuln_cves(__attribute__((unused)) wdb_t *wdb, const char* status, char **output) {
    check_expected(status);
    os_strdup(mock_ptr_type(char*), *output);
    return mock();
}

int __wrap_wdb_agents_clear_vuln_cves(__attribute__((unused)) wdb_t *wdb) {
    return mock();
}

bool __wrap_wdb_agents_find_package(__attribute__((unused)) wdb_t *wdb, const char* reference){
    check_expected(reference);
    return mock();
}

bool __wrap_wdb_agents_find_cve(__attribute__((unused)) wdb_t *wdb, const char* cve, const char* reference){
    check_expected(cve);
    check_expected(reference);
    return mock();
}
