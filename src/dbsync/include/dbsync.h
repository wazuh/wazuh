/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/**
 * @file dbsync.h
 * @author Dwordcito
 * @date 16 May 2020
 * @brief File containing the interface to the usage of DBSync.
 *
 */

#pragma once

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include "typedef.h"

#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Turn off the services provided by the shared library.
 */
  EXPORTED void dbsync_teardown(void);

/**
 * @brief Initialize DBSync.
 *
 * @param host_type Define the dynamic library host type.
 * @param db_type Define the type of database.
 * @param path Path of local db.
 * @param sql_statement sql sentence to create tables in a SQL engine
 *
 * @return return a handle to be used in the future (cannot be used by more than 1 thread).
 */
  EXPORTED DBSYNC_HANDLE dbsync_initialize(
    const HostType host_type, 
    const DbEngineType db_type,
    const char* path, 
    const char* sql_statement);

/**
 * @brief Insert bulk data based on json string.
 *
 * @param handle Handle assigned and returned in the initialize method..
 * @param json_raw JSON with snapshot values.
 *
 * @return return 0 if the operations is success, otherwise an error code will vary depending on the operating system.
 */
  EXPORTED int dbsync_insert_data(
    const DBSYNC_HANDLE handle,
    const cJSON* json_insert);

/**
 * @brief Update data table, based on json_raw_snapshot bulk data based on json string.
 *
 * @param handle Handle assigned and returned in the initialize method.
 * @param json_raw_snapshot JSON with snapshot values.
 * @param json_return_modifications JSON with deletes, creations and modifications in rows.
 *
 * @return return 0 if the operations is success, otherwise an error code will vary depending on the operating system.
 */
  EXPORTED int dbsync_update_with_snapshot(
    const DBSYNC_HANDLE handle,
    const cJSON* json_snapshot,
    cJSON** json_return_modifications);

/**
 * @brief Deallocate cJSON result data.
 *
 * @param json_result pointer to pointer of the cJSON result data.
 *
 */
  EXPORTED void dbsync_free_result(
    cJSON** json_result);

/**
 * @brief Update data table, based on json_raw_snapshot bulk data based on json string.
 *
 * @param handle Handle assigned and returned in the initialize method.
 * @param json_raw_snapshot JSON with snapshot values.
 * @param callback function callback to return individually result.
 *
 * @return return 0 if the operations is success, otherwise an error code will vary depending on the operating system.
 */
  EXPORTED int dbsync_update_with_snapshot_cb(
    const DBSYNC_HANDLE handle,
    const cJSON* json_snapshot,
    void* callback);

/**
 * @brief Select data from table.
 *
 * @param handle Handle assigned and returned in the initialize method.
 * @param json_raw_data_input JSON with table name, fields to be return, and filters to apply in the query.
 * @param json_return_rows JSON that containt rows.
 *
 * @return return 0 if the operations is success, otherwise an error code will vary depending on the operating system.
 */
  EXPORTED int dbsync_select_rows(
    const DBSYNC_HANDLE handle,
    const cJSON* json_data_input,
    cJSON** json_return_rows);

/**
 * @brief Set max rows in table, the table works as queue if the limit is exceeded.
 *
 * @param handle Handle assigned and returned in the initialize method.
 * @param table Table name to apply the max rows configuration.
 * @param max_rows Quantity of max rows to apply in table.
 *
 * @return return 0 if the operations is success, otherwise an error code will vary depending on the operating system.
 */
  EXPORTED int dbsync_set_max_rows(
    const DBSYNC_HANDLE handle,
    const char* table,
    const unsigned long long max_rows);


#ifdef __cplusplus
    }
#endif