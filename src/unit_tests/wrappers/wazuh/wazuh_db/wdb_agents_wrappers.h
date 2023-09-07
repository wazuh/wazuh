/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WDB_AGENTS_WRAPPERS_H
#define WDB_AGENTS_WRAPPERS_H

#include "../wazuh_db/wdb.h"

cJSON* __wrap_wdb_agents_get_sys_osinfo(wdb_t *wdb);
int __wrap_wdb_agents_set_sys_osinfo_triaged(wdb_t *wdb);
cJSON* __wrap_wdb_agents_insert_vuln_cves(wdb_t *wdb,
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
                                          double cvss3_score);
int __wrap_wdb_agents_update_vuln_cves_status(wdb_t *wdb, const char* old_status, const char* new_status, const char* type);
int __wrap_wdb_agents_remove_vuln_cves(wdb_t *wdb, const char* cve, const char* reference);
wdbc_result __wrap_wdb_agents_remove_vuln_cves_by_status(wdb_t *wdb, const char* status, char **output);
bool __wrap_wdb_agents_find_package(wdb_t *wdb, const char* reference);
bool __wrap_wdb_agents_find_cve(wdb_t *wdb, const char* cve, const char* reference);
#endif
