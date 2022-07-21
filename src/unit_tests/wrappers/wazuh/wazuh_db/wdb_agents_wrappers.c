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

int __wrap_wdb_agents_set_sys_osinfo_triaged(__attribute__((unused)) wdb_t *wdb) {
    return mock();
}

cJSON* __wrap_wdb_agents_insert_vuln_cves(__attribute__((unused)) wdb_t *wdb,
                                          const char* name,
                                          const char* version,
                                          const char* architecture,
                                          const char* cve,
                                          const char* reference,
                                          const char* type,
                                          const char* status,
                                          bool check_pkg_existence,
                                          const char* severity,
                                          double cvss2_score,
                                          double cvss3_score) {
    check_expected(name);
    check_expected(version);
    check_expected(architecture);
    check_expected(cve);
    check_expected(reference);
    check_expected(type);
    check_expected(status);
    check_expected(check_pkg_existence);
    check_expected(severity);
    check_expected(cvss2_score);
    check_expected(cvss3_score);

    return mock_ptr_type(cJSON*);
}

int __wrap_wdb_agents_update_vuln_cves_status(__attribute__((unused)) wdb_t *wdb, const char* old_status, const char* new_status, const char* type) {
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

wdbc_result __wrap_wdb_agents_remove_vuln_cves_by_status(__attribute__((unused)) wdb_t *wdb, const char* status, char **output) {
    check_expected(status);
    os_strdup(mock_ptr_type(char*), *output);
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

int __wrap_wdb_agents_set_packages_triaged(__attribute__((unused)) wdb_t *wdb) {
    return mock();
}

int __wrap_wdb_agents_send_packages(__attribute__((unused)) wdb_t *wdb, bool not_triaged_only) {
    check_expected(not_triaged_only);
    return mock();
}

int __wrap_wdb_agents_get_packages(__attribute__((unused)) wdb_t *wdb, bool not_triaged_only, cJSON** response) {
    check_expected(not_triaged_only);
    *response = mock_ptr_type(cJSON*);
    return mock();
}

int __wrap_wdb_agents_get_hotfixes(__attribute__((unused)) wdb_t *wdb, cJSON** response) {
    *response = mock_ptr_type(cJSON*);
    return mock();
}
