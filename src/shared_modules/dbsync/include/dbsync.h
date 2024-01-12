/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DBSYNC_H_
#define _DBSYNC_H_

// Define EXPORTED for any platform
#ifndef EXPORTED
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
#endif

#include "commonDefs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initializes the shared library.
 *
 * @param log_function pointer to log function to be used by the dbsync.
 */
EXPORTED void dbsync_initialize(log_fnc_t log_function);

/**
 * @brief Creates a new DBSync instance (wrapper)
 *
 * @param host_type          Dynamic library host type to be used.
 * @param db_type            Database type to be used (currently only supported SQLITE3)
 * @param path               Path where the local database will be created.
 * @param sql_statement      SQL sentence to create tables in a SQL engine.
 *
 * @note db_management will be DbManagement::VOLATILE as default and upgrade_statements will be NULL.
 *
 * @return Handle instance to be used for common sql operations (cannot be used by more than 1 thread).
 */
EXPORTED DBSYNC_HANDLE dbsync_create(const HostType      host_type,
                                     const DbEngineType  db_type,
                                     const char*         path,
                                     const char*         sql_statement);

/**
 * @brief Creates a new DBSync instance (wrapper)
 *
 * @param host_type          Dynamic library host type to be used.
 * @param db_type            Database type to be used (currently only supported SQLITE3)
 * @param path               Path where the local database will be created.
 * @param sql_statement      SQL sentence to create tables in a SQL engine.
 * @param upgrade_statements SQL sentences to upgrade tables in a SQL engine.
 *
 * @note db_management will be DbManagement::PERSISTENT as default.
 *
 * @return Handle instance to be used for common sql operations (cannot be used by more than 1 thread).
 */
EXPORTED DBSYNC_HANDLE dbsync_create_persistent(const HostType      host_type,
                                                const DbEngineType  db_type,
                                                const char*         path,
                                                const char*         sql_statement,
                                                const char**        upgrade_statements);

/**
 * @brief Turns off the services provided by the shared library.
 */
EXPORTED void dbsync_teardown(void);

/**
 * @brief Creates a database transaction based on the supplied information.
 *
 * @param handle         Handle obtained from the \ref dbsync_create method call.
 * @param tables         Tables to be created in the transaction.
 * @param thread_number  Number of worker threads for processing data. If 0 hardware concurrency
 *                       value will be used.
 * @param max_queue_size Max data number to hold/queue to be processed.
 * @param callback_data  This struct contain the result callback will be called for each result
 *                       and user data space returned in each callback call.
 *
 * @return Handle instance to be used in transacted operations.
 */
EXPORTED TXN_HANDLE dbsync_create_txn(const DBSYNC_HANDLE handle,
                                      const cJSON*        tables,
                                      const unsigned int  thread_number,
                                      const unsigned int  max_queue_size,
                                      callback_data_t     callback_data);

/**
 * @brief Closes the \p txn database transaction.
 *
 * @param txn     Database transaction to be closed.
 *
 * @return 0 if succeeded,
 *         specific error code (OS dependent) otherwise.
 */
EXPORTED int dbsync_close_txn(const TXN_HANDLE txn);

/**
 * @brief Synchronizes the \p js_input data using the \p txn current
 *  database transaction.
 *
 * @param txn      Database transaction to be used for \ref js_input data sync.
 * @param js_input JSON information to be synchronized.
 *
 * @return 0 if succeeded,
 *         specific error code (OS dependent) otherwise.
 */
EXPORTED int dbsync_sync_txn_row(const TXN_HANDLE txn,
                                 const cJSON*     js_input);

/**
 * @brief Generates triggers that execute actions to maintain consistency between tables.
 *
 * @param handle        Handle assigned as part of the \ref dbsync_create method.
 * @param js_input      JSON information with tables relationship.
 *
 * @return 0 if succeeded,
 *         specific error code (OS dependent) otherwise.
 */
EXPORTED int dbsync_add_table_relationship(const DBSYNC_HANDLE handle,
                                           const cJSON*        js_input);

/**
 * @brief Insert the \p js_insert data in the database.
 *
 * @param handle    Handle assigned as part of the \ref dbsync_create method().
 * @param js_insert JSON information with values to be inserted.
 *
 * @return 0 if succeeded,
 *         specific error code (OS dependent) otherwise.
 */
EXPORTED int dbsync_insert_data(const DBSYNC_HANDLE handle,
                                const cJSON*        js_insert);

/**
 * @brief Sets the max rows in the \p table table.
 *
 * @param handle   Handle assigned as part of the \ref dbsync_create method().
 * @param table    Table name to apply the max rows configuration.
 * @param max_rows Max rows number to be applied in the table \p table table.
 *
 * @return 0 if succeeded,
 *         specific error code (OS dependent) otherwise.
 */
EXPORTED int dbsync_set_table_max_rows(const DBSYNC_HANDLE handle,
                                       const char*         table,
                                       const long long     max_rows);

/**
 * @brief Inserts (or modifies) a database record.
 *
 * @param handle         Handle instance assigned as part of the \ref dbsync_create method().
 * @param input          JSON information used to add/modified a database record.
 * @param callback_data  This struct contains the result callback that will be called for each result
 *                       and user data space returned in each callback call.
 *
 * @return 0 if succeeded,
 *         specific error code (OS dependent) otherwise.
 */
EXPORTED int dbsync_sync_row(const DBSYNC_HANDLE handle,
                             const cJSON*        js_input,
                             callback_data_t     callback_data);

/**
 * @brief Select data, based in \p json_data_input data, from the database table.
 *
 * @param handle          Handle assigned as part of the \ref dbsync_create method().
 * @param js_data_input   JSON with table name, fields, filters and options to apply in the query.
 * @param callback_data   This struct contain the result callback will be called for each result
 *                        and user data space returned in each callback call.
 *
 * @return 0 if succeeded,
 *         specific error code (OS dependent) otherwise.
 */
EXPORTED int dbsync_select_rows(const DBSYNC_HANDLE handle,
                                const cJSON*        js_data_input,
                                callback_data_t     callback_data);

/**
 * @brief Deletes a database table record and its relationships based on \p js_key_values value.
 *
 * @param handle        Handle instance assigned as part of the \ref dbsync_create method().
 * @param js_key_values JSON information to be applied/deleted in the database.
 *
 * @return 0 if succeeded,
 *         specific error code (OS dependent) otherwise.
 */
EXPORTED int dbsync_delete_rows(const DBSYNC_HANDLE handle,
                                const cJSON*        js_key_values);

/**
 * @brief Gets the deleted rows (diff) from the database.
 *
 * @param txn             Database transaction to be used.
 * @param callback_data   This struct contain the result callback will be called for each result
 *                        and user data space returned in each callback call.
 *
 * @return 0 if succeeded,
 *         specific error code (OS dependent) otherwise.
 */
EXPORTED int dbsync_get_deleted_rows(const TXN_HANDLE  txn,
                                     callback_data_t   callback_data);

/**
 * @brief Updates data table with \p js_snapshot information. \p js_result value will
 *  hold/contain the results of this operation (rows insertion, modification and/or deletion).
 *
 * @param handle      Handle instance assigned as part of the \ref dbsync_create method().
 * @param js_snapshot JSON information with snapshot values.
 * @param js_result   JSON with deletes, creations and modifications (diffs) in rows.
 *
 * @return 0 if succeeded,
 *         specific error code (OS dependent) otherwise.
 *
 * @details The \p js_result resulting data should be freed using the \ref dbsync_free_result function.
 */
EXPORTED int dbsync_update_with_snapshot(const DBSYNC_HANDLE handle,
                                         const cJSON*        js_snapshot,
                                         cJSON**             js_result);

/**
 * @brief Update data table, based on json_raw_snapshot bulk data based on json string.
 *
 * @param handle          Handle assigned as part of the \ref dbsync_create method().
 * @param js_snapshot     JSON with snapshot values.
 * @param callback_data   This struct contain the result callback will be called for each result
 *                        and user data space returned in each callback call.
 *
 * @return 0 if succeeded,
 *         specific error code (OS dependent) otherwise.
 */
EXPORTED int dbsync_update_with_snapshot_cb(const DBSYNC_HANDLE handle,
                                            const cJSON*        js_snapshot,
                                            callback_data_t     callback_data);

/**
 * @brief Deallocate cJSON result data.
 *
 * @param js_data JSON information be be deallocated.
 *
 * @details This function should only be used to free result objects obtained
 *  from the interface.
 */
EXPORTED void dbsync_free_result(cJSON** js_data);

#ifdef __cplusplus
}
#endif

#endif // _DBSYNC_H_
