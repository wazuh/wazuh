/* Copyright (C) 2015, Wazuh Inc.
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

cJSON* __wrap_wdb_insert_vuln_cves(int id,
                                   const char *name,
                                   const char *version,
                                   const char *architecture,
                                   const char *cve,
                                   const char *severity,
                                   double cvss2_score,
                                   double cvss3_score,
                                   const char *reference,
                                   const char *type,
                                   const char *status,
                                   char **external_references,
                                   const char *condition,
                                   const char *title,
                                   const char *published,
                                   const char *updated,
                                   bool check_pkg_existence,
                                   __attribute__((unused)) int *sock) {
    check_expected(id);
    check_expected(name);
    check_expected(version);
    check_expected(architecture);
    check_expected(cve);
    check_expected(severity);
    check_expected(cvss2_score);
    check_expected(cvss3_score);
    check_expected(reference);
    check_expected(type);
    check_expected(status);

    char* external_references_concatenated = w_strcat_list(external_references, ',');
    check_expected(external_references_concatenated);
    os_free(external_references_concatenated);

    check_expected(condition);
    check_expected(title);
    check_expected(published);
    check_expected(updated);
    check_expected(check_pkg_existence);
    return mock_ptr_type(cJSON*);
}

cJSON* __wrap_wdb_remove_vuln_cves_by_status(int id,
                                             const char *status,
                                             __attribute__((unused)) int *sock) {
    check_expected(id);
    check_expected(status);
    return mock_ptr_type(cJSON*);
}

int __wrap_wdb_update_vuln_cves_status(int id,
                                       const char *old_status,
                                       const char *new_status,
                                       __attribute__((unused)) int *sock) {
    check_expected(id);
    check_expected(old_status);
    check_expected(new_status);
    return mock_type(int);
}
