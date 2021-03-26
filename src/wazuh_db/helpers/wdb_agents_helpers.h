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
    WDB_AGENTS_VULN_CVES_INSERT,
    WDB_AGENTS_VULN_CVES_CLEAR,
    WDB_AGENTS_VULN_CVES_REMOVE,
    WDB_AGENTS_VULN_CVES_UPDATE_STATUS
} agents_db_access;

/**
 * @brief Insert or update a vulnerability to the vuln_cves table in the agents database.
 *
 * @param[in] id The agent ID.
 * @param[in] name The affected package name.
 * @param[in] version The affected package version.
 * @param[in] architecture The affected package architecture.
 * @param[in] cve The vulnerability ID.
 * @param[in] reference The package reference.
 * @param[in] type The package type.
 * @param[in] status The vulnerability status.
 * @param[in] check_pkg_existance If TRUE, it enables a package existance verification in sys_programs table.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns cJSON object with 'action': 'INSERT' | 'UPDATE'.
 *                               and 'status': 'SUCCESS' | 'ERROR' | 'PKG_NOT_FOUND'
 *         If the vulnerability already exists in vuln_cve table, 'status' field will contain 'UPDATE' string. Otherwise, it contains 'INSERT'.
 *         If the action was completed successfully, 'status' contains 'SUCCESS' string.
 *         If check_pkg_existance is enabled and the package wasn't found 'status' contains 'PKG_NOT_FOUND'.
 *         On any error, 'status' contains 'ERROR' string.
 *         The cJSON object must be freed by the caller.
 */
cJSON* wdb_agents_vuln_cves_insert(int id,
                               const char *name,
                               const char *version,
                               const char *architecture,
                               const char *cve,
                               const char *reference,
                               const char *type,
                               const char *status,
                               bool check_pkg_existance,
                               int *sock);

/**
 * @brief Removes all the entries from the vuln_cves table in the agents database.
 *
 * @param[in] id The agent ID.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_agents_vuln_cves_clear(int id,
                              int *sock);

/**
 * @brief Removes an entry from the vuln_cves table in the agent's database.
 *
 * @param[in] id The agent ID.
 * @param[in] cve The cve of the vulnerability entry that should be removed.
 * @param[in] reference The reference of the vulnerability entry that should be removed.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_agents_vuln_cves_remove_entry(int id,
                                     const char *cve,
                                     const char *reference,
                                     int *sock);

/**
 * @brief Removes all the entries from the vuln_cves table in the agent's database that have the specified status.
 *
 * @param[in] id The agent ID.
 * @param[in] status The status of the vulnerabilities that should be removed.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns a pointer to a cJSON object that contains the information of all the vulnerabilities removed.
 */
cJSON* wdb_agents_vuln_cves_remove_by_status(int id,
                                            const char *status,
                                            int *sock);

/**
 * @brief Updates all or a specific status from the vuln_cves table in the agents database.
 *
 * @param[in] id The agent ID.
 * @param[in] old_status The status that is going to be updated. The '*' option changes all statuses.
 * @param[in] new_status The new status.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_agents_vuln_cves_update_status(int id,
                                      const char *old_status,
                                      const char *new_status,
                                      int *sock);

#endif
