/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WDB_AGENTS_HELPERS_WRAPPERS_H
#define WDB_AGENTS_HELPERS_WRAPPERS_H

#include "../wazuh_db/wdb.h"

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
                                   __attribute__((unused)) int *sock);

cJSON* __wrap_wdb_remove_vuln_cves_by_status(int id,
                                             const char *status,
                                             __attribute__((unused)) int *sock);

int __wrap_wdb_update_vuln_cves_status(int id,
                                       const char *old_status,
                                       const char *new_status,
                                       __attribute__((unused)) int *sock);
#endif
