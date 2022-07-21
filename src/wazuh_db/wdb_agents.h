/*
 * Wazuh DB helper module for agents database
 * Copyright (C) 2015, Wazuh Inc.
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
 * @brief Function to get all the OS information from the sys_osinfo table.
 *
 * @param [in] wdb The 'agents' struct database.
 * @return Returns cJSON object with the sys_osinfo database table information.
 *         The cJSON object must be freed by the caller.
 */
cJSON* wdb_agents_get_sys_osinfo(wdb_t *wdb);

/**
 * @brief Function to set the triaged column from the sys_osinfo table.
 *
 * @param [in] wdb The 'agents' struct database.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_agents_set_sys_osinfo_triaged(wdb_t *wdb);

/**
 * @brief Function to check if a certain package exists.
 *
 * @param [in] wdb The 'agents' struct database.
 * @param [in] reference The package reference.
 * @return Returns TRUE if found, FALSE if not or error.
 */
bool wdb_agents_find_package(wdb_t *wdb, const char* reference);

/**
 * @brief Function to check if a certain cve exists.
 *
 * @param [in] wdb The 'agents' struct database.
 * @param [in] cve The CVE id of the vulnerability.
 * @param [in] reference The package reference.
 * @return Returns TRUE if found, FALSE if not or error.
 */
bool wdb_agents_find_cve(wdb_t *wdb, const char* cve, const char* reference);

/**
 * @brief Function to insert a new entry into the agent vuln_cves table.
 *
 * @param [in] wdb The 'agents' struct database.
 * @param [in] name The vulnerable package name.
 * @param [in] version The vulnerable package version.
 * @param [in] architecture The vulnerable package architecture.
 * @param [in] cve The CVE id of the vulnerability.
 * @param [in] reference The package reference.
 * @param [in] type The package type.
 * @param [in] status The vulnerability status.
 * @param [in] check_pkg_existence If TRUE, it enables a package existence verification in sys_programs table.
                                   If the package isn't found, the vulnerability is inserted with status OBSOLETE.
 * @param [in] severity A string representing the severity of the vulnerability.
 * @param [in] cvss2_score The vulnerability score according to CVSS v2.
 * @param [in] cvss3_score The vulnerability score according to CVSS v3.
 * @param [in] external_references The vulnerability external references.
 * @param [in] condition The vulnerability condition.
 * @param [in] title The vulnerability title.
 * @param [in] published The vulnerability published date in the feed.
 * @param [in] updated The vulnerability update date, if any.
 * @return Returns cJSON object with 'action': 'INSERT' | 'UPDATE'.
 *                               and 'status': 'SUCCESS' | 'ERROR'.
 *         The cJSON object must be freed by the caller.
 */
cJSON* wdb_agents_insert_vuln_cves(wdb_t *wdb,
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
                                   double cvss3_score,
                                   const char *external_references,
                                   const char *condition,
                                   const char *title,
                                   const char *published,
                                   const char *updated);

/**
 * @brief Function to update the status field in agent database vuln_cves table.
 *
 * @param [in] wdb The 'agents' struct database.
 * @param [in] old_status The status that is going to be updated. The '*' option changes all statuses.
 * @param [in] new_status The new status.
 * @param [in] type The type of vulnerability to update. Can not be used at the same time than old_status
 * @return Returns 0 on success or -1 on error.
 */
int wdb_agents_update_vuln_cves_status(wdb_t *wdb, const char* old_status, const char* new_status, const char* type);

/**
 * @brief Function to remove vulnerabilities from the vuln_cves table by specifying the PK of the entry.
 *
 * @param [in] wdb The 'agents' struct database.
 * @param [in] cve The cve of the entry that should be removed.
 * @param [in] reference The reference of the entry that should be removed.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_agents_remove_vuln_cves(wdb_t *wdb, const char* cve, const char* reference);

/**
 * @brief Function to remove vulnerabilities from the vuln_cves table filtering by the status.
 *
 * @param [in] wdb The 'agents' struct database.
 * @param [in] status The status that is going to be updated. The '*' option changes all statuses.
 * @param [out] output A buffer where the response is written. Must be de-allocated by the caller.
 * @return wdbc_result to represent if all the vulnerabilities have been removed.
 */
wdbc_result wdb_agents_remove_vuln_cves_by_status(wdb_t *wdb, const char* status, char **output);

/**
 * @brief Function to set all packages from the table as triaged.
 *
 * @param [in] wdb The 'agents' struct database.
 * @return Returns OS_SUCCESS on success or OS_INVALID on error.
 */
int wdb_agents_set_packages_triaged(wdb_t *wdb);

/**
 * @brief Function to send every package from the table row by row using wdb->peer
 *
 * @param [in] wdb The 'agents' struct database.
 * @param [in] not_triaged_only Flag to request packages not marked as triaged only.
 *
 * @return OS_SUCCESS on success.
 *         OS_INVALID on errors executing SQL statement.
 *         OS_SOCKTERR on errors handling the socket.
 *         OS_SIZELIM on error trying to fit the row response into the socket buffer.
 */
int wdb_agents_send_packages(wdb_t *wdb, bool not_triaged_only);

/**
 * @brief Function to send every hotfix from the table row by row using wdb->peer
 *
 * @param [in] wdb The 'agents' struct database.
 * @return OS_SUCCESS on success.
 *         OS_INVALID on errors executing SQL statement.
 *         OS_SOCKTERR on errors handling the socket.
 *         OS_SIZELIM on error trying to fit the row response into the socket buffer.
 */
int wdb_agents_send_hotfixes(wdb_t *wdb);

/**
 * @brief Function to get every package from the table.
 *        It checks if the table is already updated previous obtaining the data.
 *        The packages will be responded in multiple commands with "due" prefix.
 *        All the packages are set as triaged after this.
 *
 * @param [in] wdb The 'agents' struct database.
 * @param [in] not_triaged_only Flag to request packages not marked as triaged only.
 * @param [out] response A JSON structure with the status of the operation:
 *                          {"status":"SUCCESS"} on success
 *                          {"status":"ERROR"} on error
 *                          {"status":"NOT_SYNCED"} if data wasn´t available because the table is being synced
 * @return OS_SUCCESS on success. An error code on error.
 */
int wdb_agents_get_packages(wdb_t *wdb, bool not_triaged_only, cJSON** response);

/**
 * @brief Function to get every hotfix from the table.
 *        It checks if the table is already updated previous obtaining the data.
 *        The hotfixes will be responded in multiple commands with "due" prefix.
 *
 * @param [in] wdb The 'agents' struct database.
 * @param [out] response A JSON structure with the status of the operation:
 *                          {"status":"SUCCESS"} on success
 *                          {"status":"ERROR"} on error
 *                          {"status":"NOT_SYNCED"} if data wasn´t available because the table is being synced
 * @return OS_SUCCESS on success. An error code on error.
 */
int wdb_agents_get_hotfixes(wdb_t *wdb, cJSON** response);

#endif
