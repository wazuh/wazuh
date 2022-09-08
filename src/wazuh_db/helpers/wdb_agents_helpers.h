/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
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
    WDB_AGENTS_SYS_OSINFO_GET,
    WDB_AGENTS_SYS_OSINFO_SET_TRIAGGED,
    WDB_AGENTS_VULN_CVES_INSERT,
    WDB_AGENTS_VULN_CVES_REMOVE,
    WDB_AGENTS_VULN_CVES_UPDATE_STATUS
} agents_db_access;

/**
 * @brief Gets the sys_osinfo table data of the specified agent's database.
 *
 * @param[in] id The agent ID.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns cJSON object with the sys_osinfo table information. Null in case of error.
 *                 The cJSON object must be freed by the caller.
 */
cJSON* wdb_get_agent_sys_osinfo(int id,
                                int *sock);

/**
 * @brief Sets the triaged status in the sys_osinfo table of the specified agent's database.
 *
 * @param[in] id The agent ID.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_set_agent_sys_osinfo_triaged(int id,
                                     int *sock);

/**
 * @brief Insert or update a vulnerability to the vuln_cves table in the agents database.
 *
 * @param[in] id The agent ID.
 * @param[in] name The affected package name.
 * @param[in] version The affected package version.
 * @param[in] architecture The affected package architecture.
 * @param[in] cve The vulnerability ID.
 * @param [in] severity A string representing the severity of the vulnerability.
 * @param [in] cvss2_score The vulnerability score according to CVSS v2.
 * @param [in] cvss3_score The vulnerability score according to CVSS v3.
 * @param[in] reference The package reference.
 * @param[in] type The package type.
 * @param[in] status The vulnerability status.
 * @param[in] external_references The vulnerability external references.
 * @param[in] condition The vulnerability condition.
*  @param[in] title The vulnerability title.
*  @param[in] published The vulnerability published date in the feed.
*  @param[in] updated The vulnerability update date, if any.
 * @param[in] check_pkg_existence If TRUE, it enables a package existence verification in sys_programs table.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns cJSON object with 'action': 'INSERT' | 'UPDATE'.
 *                               and 'status': 'SUCCESS' | 'ERROR'.
 *         If the vulnerability already exists in vuln_cve table, 'status' field will contain 'UPDATE' string. Otherwise, it contains 'INSERT'.
 *         If the action was completed successfully, 'status' contains 'SUCCESS' string.
 *         If check_pkg_existence is enabled and the package wasn't found 'status', the package is inserted with the 'OBSOLETE' status.
 *         On any error, 'status' contains 'ERROR' string.
 *         The cJSON object must be freed by the caller.
 */
cJSON* wdb_insert_vuln_cves(int id,
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
                            int *sock);

/**
 * @brief Removes all the entries from the vuln_cves table in the agent's database that have the specified status.
 *
 * @param[in] id The agent ID.
 * @param[in] status The status of the vulnerabilities that should be removed.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns a pointer to a cJSON object that contains the information of all the vulnerabilities removed.
 */
cJSON* wdb_remove_vuln_cves_by_status(int id,
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
int wdb_update_vuln_cves_status(int id,
                                const char *old_status,
                                const char *new_status,
                                int *sock);

/**
 * @brief Updates CVEs' status from the vuln_cves table according their type (OS/PACKAGE).
 *
 * @param[in] id The agent ID.
 * @param[in] type The type of vulnerability to update.
 * @param[in] new_status The new status.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_update_vuln_cves_status_by_type(int id,
                                        const char *type,
                                        const char *new_status,
                                        int *sock);

#endif
