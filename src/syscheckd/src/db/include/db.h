/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * January 24, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef FIMDB_H
#define FIMDB_H

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
// We avoid the definition __declspec(dllimport) as a workaround for the MinGW bug
// for delayed loaded DLLs in 32bits (https://www.sourceware.org/bugzilla/show_bug.cgi?id=14339)
#define EXPORTED
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include "fimCommonDefs.h"
#include "commonDefs.h"
#include "syscheck.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/evp.h>

#define FIM_DB_MEMORY_PATH  ":memory:"
#define FIM_DB_DISK_PATH    "queue/fim/db/fim.db"

#define EVP_MAX_MD_SIZE 64

/**
 * @brief Initialize the FIM database.
 *
 * It will be dbsync the responsible of managing the DB.
 * @param storage storage 1 Store database in memory, disk otherwise.
 * @param sync_interval Interval when the synchronization will be performed.
 * @param sync_max_interval Maximum interval allowed for the synchronization process.
 * @param sync_response_timeout Minimum interval for the synchronization process.
 * @param sync_callback Callback to send the synchronization messages.
 * @param log_callback Callback to perform logging operations.
 * @param file_limit Maximum number of files to be monitored.
 * @param value_limit Maximum number of registry values to be monitored.
 * @param sync_registry_enable Flag to enable the registry synchronization.
 * @param sync_queue_size Number to define the size of the queue to be synchronized.
 * @param dbsync_log_function Logging function for dbsync module.
 * @param rsync_log_function Logging function for rsync module.
 *
 * @return FIMDB_OK on success, FIMDB_ERROR on error.
 */
EXPORTED FIMDBErrorCode fim_db_init(int storage,
                                    int sync_interval,
                                    uint32_t sync_max_interval,
                                    uint32_t sync_response_timeout,
                                    fim_sync_callback_t sync_callback,
                                    logging_callback_t log_callback,
                                    int file_limit,
                                    int value_limit,
                                    bool sync_registry_enabled,
                                    int sync_thread_pool,
                                    unsigned int sync_queue_size,
                                    log_fnc_t dbsync_log_function,
                                    log_fnc_t rsync_log_function);

/**
 * @brief Get entry data using path.
 *
 * @param file_path File path can be a pattern or a primary key
 * @param data Pointer to the data structure where the callback context will be stored.
 *
 * @retval FIMDB_OK on success.
 * @retval FIMDB_FULL if the table limit was reached.
 * @retval FIMDB_ERR on failure.
 */
EXPORTED FIMDBErrorCode fim_db_get_path(const char* file_path,
                                        callback_context_t data);

/**
 * @brief Find entries based on pattern search.
 *
 * @param pattern Pattern to be searched.
 * @param data Pointer to the data structure where the callback context will be stored.
 *
 * @retval FIMDB_OK on success.
 * @retval FIMDB_FULL if the table limit was reached.
 * @retval FIMDB_ERR on failure.
 */
EXPORTED FIMDBErrorCode fim_db_file_pattern_search(const char* pattern,
                                                   callback_context_t data);

/**
 * @brief Delete entry from the DB using file path.
 *
 * @param path Path of the entry to be removed.
 *
 * @retval FIMDB_OK on success.
 * @retval FIMDB_FULL if the table limit was reached.
 * @retval FIMDB_ERR on failure.
 */
EXPORTED FIMDBErrorCode fim_db_remove_path(const char* path);

/**
 * @brief Get count of all inodes in file_entry table.
 *
 * @return Number of inodes in file_entry table.
 */
EXPORTED int fim_db_get_count_file_inode();

/**
 * @brief Get count of all entries in file_entry table.
 *
 * @return Number of entries in file_entry table.
 */
EXPORTED int fim_db_get_count_file_entry();

/**
 * @brief Makes any necessary queries to get the entry updated in the DB.
 *
 * @param data The information linked to the path to be created or updated.
 * @param callback Callback to send the fim message.
 *
 * @return FIMDB_OK on success.
 */
EXPORTED FIMDBErrorCode fim_db_file_update(fim_entry* data,
                                           callback_context_t callback);

/**
 * @brief Find entries using the inode.
 *
 * @param inode Inode.
 * @param dev Device.
 * @param data Pointer to the data structure where the callback context will be stored.
 *
 * @return FIMDB_OK on success.
 */
EXPORTED FIMDBErrorCode fim_db_file_inode_search(unsigned long long int inode,
                                                 unsigned long int dev,
                                                 callback_context_t data);

/**
 * @brief Push a message to the syscheck queue
 *
 * @param msg The specific message to be pushed
 *
 * @return FIMDB_OK on success.
 */
EXPORTED FIMDBErrorCode fim_sync_push_msg(const char* msg);

/**
 * @brief Thread that performs the syscheck data synchronization
 *
 * @return FIMDB_OK on success.
 */
EXPORTED FIMDBErrorCode fim_run_integrity();

/*
 * @brief Function that starts a new DBSync transaction.
 *
 * @param table Database table that will be used in the DBSync transaction.
 * @param row_callback Callback that is going to be executed for each insertion or modification.
 * param user_data Context that will be used in the callback.
 *
 * @return TXN_HANDLE Transaction handler.
 */
EXPORTED TXN_HANDLE fim_db_transaction_start(const char* table,
                                             result_callback_t row_callback,
                                             void *user_data);

/**
 * @brief Function to perform a sync row operation (ADD OR REPLACE).
 *
 * @param txn_handler Handler to an active transaction.
 * @param entry FIM entry to be added/updated.
 *
 * @retval FIMDB_OK on success.
 * @retval FIMDB_FULL if the table limit was reached.
 * @retval FIMDB_ERR on failure.
 */
EXPORTED FIMDBErrorCode fim_db_transaction_sync_row(TXN_HANDLE txn_handler,
                                                    const fim_entry* entry);

/**
 * @brief Function to perform the deleted rows operation.
 *
 * @param txn_handler Handler to an active transaction.
 * @param callback Function to be executed for each deleted entry.
 *
 * @retval FIMDB_OK on success.
 * @retval FIMDB_FULL if the table limit was reached.
 * @retval FIMDB_ERR on failure.
 */
EXPORTED FIMDBErrorCode fim_db_transaction_deleted_rows(TXN_HANDLE txn_handler,
                                                        result_callback_t callback,
                                                        void* txn_ctx);

/**
 * @brief Turns off the services provided.
 *
 * It will be responsible to close sync and release resources
 */
EXPORTED void fim_db_teardown();

#ifdef WIN32

// Registry functions.

/**
 * @brief Get count of all entries in registry data table.
 *
 * @return Number of entries in registry data table.
 */
EXPORTED int fim_db_get_count_registry_data();

/**
 * @brief Get count of all entries in registry key table.
 *
 * @return Number of entries in registry data table.
 */
EXPORTED int fim_db_get_count_registry_key();

#endif /* WIN32 */


#ifdef __cplusplus
}
#endif // _cplusplus
#endif // FIMDB_H
