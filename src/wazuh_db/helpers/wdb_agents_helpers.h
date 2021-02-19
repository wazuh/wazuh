/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2021, Wazuh Inc.
 * February 17, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WDB_AGENTS_HELPERS_H
#define WDB_AGENTS_HELPERS_H

#include "../wdb.h"

typedef enum agents_db_access {
    WDB_AGENTS_VULN_CVE_INSERT,
    WDB_AGENTS_VULN_CVE_CLEAR
} agents_db_access;

/**
 * @brief Insert a CVE to the vuln_cve table in the agents database.
 *
 * @param[in] id The agent ID.
 * @param[in] name The affected package name.
 * @param[in] version The affected package version.
 * @param[in] architecture The affected package architecture.
 * @param[in] cve The vulnerability ID.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_agents_vuln_cve_insert(int id,
                               const char *name,
                               const char *version,
                               const char *architecture,
                               const char *cve,
                               int *sock);

/**
 * @brief Removes all the entries from the vuln_cve table in the agents database.
 *
 * @param[in] id The agent ID.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_agents_vuln_cve_clear(int id,
                              int *sock);

#endif
