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
 * @brief Function to check if a certain package exists.
 *
 * @param [in] wdb The 'agents' struct database.
 * @param [in] reference The package reference.
 * @return Returns TRUE if found, FALSE if not or error.
 */
bool wdb_agents_find_package(wdb_t *wdb, const char* reference);

/**
 * @brief Function to send every package from the table row by row using wdb->peer
 *
 * @param [in] wdb The 'agents' struct database.
 *
 * @return OS_SUCCESS on success.
 *         OS_INVALID on errors executing SQL statement.
 *         OS_SOCKTERR on errors handling the socket.
 *         OS_SIZELIM on error trying to fit the row response into the socket buffer.
 */
int wdb_agents_send_packages(wdb_t *wdb);

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
 *
 * @param [in] wdb The 'agents' struct database.
 * @param [out] response A JSON structure with the status of the operation:
 *                          {"status":"SUCCESS"} on success
 *                          {"status":"ERROR"} on error
 *                          {"status":"NOT_SYNCED"} if data wasn´t available because the table is being synced
 * @return OS_SUCCESS on success. An error code on error.
 */
int wdb_agents_get_packages(wdb_t *wdb, cJSON** response);

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
