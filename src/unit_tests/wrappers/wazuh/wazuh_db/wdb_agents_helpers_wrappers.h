/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WDB_AGENTS_HELPERS_WRAPPERS_H
#define WDB_AGENTS_HELPERS_WRAPPERS_H

#include "wazuh_db/wdb.h"

int __wrap_wdb_agents_vuln_cves_insert(int id,
                                      const char *name,
                                      const char *version,
                                      const char *architecture,
                                      const char *cve,
                                      const char *reference,
                                      const char *type,
                                      const char *status,
                                      bool check_pkg_existence,
                                      __attribute__((unused)) int *sock);

int __wrap_wdb_agents_vuln_cves_clear(int id,
                                     __attribute__((unused)) int *sock);

cJSON* __wrap_wdb_agents_vuln_cves_remove_by_status(int id,
                                             const char *status,
                                             __attribute__((unused)) int *sock);

#endif
