/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WM_VULN_DETECTOR_WRAPPERS_H
#define WM_VULN_DETECTOR_WRAPPERS_H

#include "headers/shared.h"
#include "wazuh_modules/wmodules.h"

bool __wrap_c_isdigit(int c);

#ifndef CLIENT

int __wrap_wm_vuldet_prepare();

bool __wrap_pkg_version_relate(const struct pkg_version *a,
                               enum pkg_relation rel,
                               const struct pkg_version *b,
                               version_type vertype);

int __wrap_wm_checks_package_vulnerability(char *version_a,
                                           const char *operation,
                                           const char *version_b,
                                           version_type vertype);

int __wrap_wm_vuldet_add_cve_node(cve_vuln_pkg *newPkg, const char *cve, OSHash *cve_table);

int __wrap_wm_vuldet_linux_nvd_vulnerabilities(sqlite3 *db, agent_software *agent, OSHash *cve_table);

int __wrap_wm_vuldet_win_nvd_vulnerabilities(sqlite3 *db, agent_software *agent, wm_vuldet_flags *flags);

int __wrap_wm_vuldet_json_nvd_parser(char *json_feed, wm_vuldet_db *parsed_vulnerabilities);

int __wrap_wm_vuldet_json_wcpe_parser(cJSON *json_feed, wm_vuldet_db *parsed_vulnerabilities);

int __wrap_wm_vuldet_json_msu_parser(cJSON *json_feed, wm_vuldet_db *parsed_vulnerabilities);

#endif  // CLIENT

#endif
