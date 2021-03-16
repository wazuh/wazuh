/*
 * Wazuh DB helper module for agents database
 * Copyright (C) 2015-2021, Wazuh Inc.
 * February 10, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WDB_AGENTS_H
#define WDB_AGENTS_H

#include "wdb.h"

/**
 * @brief Function to clear whole data from agent vuln_cve table.
 *
 * @param [in] wdb The 'agents' struct database.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_agents_clear_vuln_cve(wdb_t *wdb);

/**
 * @brief Function to insert a new entry into the agent vuln_cve table.
 *
 * @param [in] wdb The 'agents' struct database.
 * @param [in] name The vulnerable package name.
 * @param [in] version The vulnerable package version.
 * @param [in] architecture The vulnerable package architecture.
 * @param [in] cve The CVE id of the vulnerability.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_agents_insert_vuln_cve(wdb_t *wdb, const char* name, const char* version, const char* architecture, const char* cve);

#endif
