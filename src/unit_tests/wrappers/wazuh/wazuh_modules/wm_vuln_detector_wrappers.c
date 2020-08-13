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

bool __wrap_pkg_version_relate(__attribute__((unused)) const struct pkg_version *a, enum pkg_relation rel,
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

int __wrap_wm_vuldet_add_cve_node(cve_vuln_pkg *newPkg, __attribute__((unused)) const char *cve, OSHash *cve_table) {
    if (cve_table) {
        cve_vuln_pkg *pkg  = (cve_vuln_pkg *) newPkg;
        cve_vuln_pkg *next = NULL;

        do { // Free each package in the linked list.
            next = pkg->next;
            os_free(pkg->bin_name);
            os_free(pkg->src_name);
            os_free(pkg->arch);
            os_free(pkg->version);

            if (pkg->nvd_cond) {
                os_free(pkg->nvd_cond->operator);
                os_free(pkg->nvd_cond->end_version);
                os_free(pkg->nvd_cond->start_version);
                os_free(pkg->nvd_cond);
            }

            if (pkg->vuln_cond) {
                os_free(pkg->vuln_cond->state);
                os_free(pkg->vuln_cond->operation);
                os_free(pkg->vuln_cond->operation_value);
                os_free(pkg->vuln_cond->condition);
                os_free(pkg->vuln_cond);
            }

            os_free(pkg);

            pkg = next;
        } while (pkg);
    }

    return mock();
}

void __wrap_wm_vuldet_free_cve_node(cve_vuln_pkg *newPkg) {
    if (newPkg) {
        cve_vuln_pkg *pkg  = (cve_vuln_pkg *) newPkg;
        cve_vuln_pkg *next = NULL;

        do { // Free each package in the linked list.
            next = pkg->next;
            os_free(pkg->bin_name);
            os_free(pkg->src_name);
            os_free(pkg->arch);
            os_free(pkg->version);

            if (pkg->nvd_cond) {
                os_free(pkg->nvd_cond->operator);
                os_free(pkg->nvd_cond->end_version);
                os_free(pkg->nvd_cond->start_version);
                os_free(pkg->nvd_cond);
            }

            if (pkg->vuln_cond) {
                os_free(pkg->vuln_cond->state);
                os_free(pkg->vuln_cond->operation);
                os_free(pkg->vuln_cond->operation_value);
                os_free(pkg->vuln_cond->condition);
                os_free(pkg->vuln_cond);
            }

            os_free(pkg);

            pkg = next;
        } while (pkg);
    }

    return;
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
