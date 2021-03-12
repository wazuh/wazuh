/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "wm_vuln_detector_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

bool __wrap_c_isdigit(__attribute__((unused)) int c) {
    return mock_type(bool);
}

#ifndef CLIENT

bool __wrap_pkg_version_relate(__attribute__((unused)) const struct pkg_version *a,
                               enum pkg_relation rel,
                               __attribute__((unused)) const struct pkg_version *b,
                               __attribute__((unused)) version_type vertype) {
    check_expected(rel);

    return mock();
}

int __wrap_wm_checks_package_vulnerability(__attribute__((unused)) char *version_a,
                                           __attribute__((unused)) const char *operation,
                                           __attribute__((unused)) const char *version_b,
                                           __attribute__((unused)) version_type vertype) {
    return mock();
}

int __wrap_wm_vuldet_add_cve_node(cve_vuln_pkg *newPkg,
                                  __attribute__((unused)) const char *cve,
                                  __attribute__((unused)) OSHash *cve_table) {
    if (cve_table) {
        wm_vuldet_free_cve_node(newPkg);
    }

    return mock();
}

int __wrap_wm_vuldet_linux_nvd_vulnerabilities(__attribute__((unused)) sqlite3 *db,
                                               __attribute__((unused)) agent_software *agent,
                                               __attribute__((unused)) OSHash *cve_table) {
    return mock();
}

int __wrap_wm_vuldet_prepare() {
    return mock();
}

int __wrap_wm_vuldet_win_nvd_vulnerabilities(__attribute__((unused)) sqlite3 *db,
                                             __attribute__((unused)) agent_software *agent,
                                             __attribute__((unused)) wm_vuldet_flags *flags) {
    return mock();
}

int __wrap_wm_vuldet_json_nvd_parser(__attribute__((unused)) char *json_feed,
                                     __attribute__((unused)) wm_vuldet_db *parsed_vulnerabilities) {
    return mock();
}

int __wrap_wm_vuldet_json_wcpe_parser(__attribute__((unused)) cJSON *json_feed,
                                      __attribute__((unused)) wm_vuldet_db *parsed_vulnerabilities) {
    return mock();
}

int __wrap_wm_vuldet_json_msu_parser(__attribute__((unused)) cJSON *json_feed,
                                     __attribute__((unused)) wm_vuldet_db *parsed_vulnerabilities) {
    return mock();
}

#endif  // CLIENT
