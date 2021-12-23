/**
 * @file db.h
 * @brief Definition of FIM database library.
 * @date 2019-08-28
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#ifndef FIMDB_H
#define FIMDB_H
#include "fimCommonDefs.h"
#include "commonDefs.h"


#ifdef __cplusplus
extern "C" {
#include "syscheck.h"
#include <openssl/evp.h>
#endif

#include "syscheck.h"
#include <openssl/evp.h>

#define FIM_DB_MEMORY_PATH  ":memory:"
#define FIM_DB_DISK_PATH    "queue/fim/db/fim.db"

#define EVP_MAX_MD_SIZE 64

#ifndef WIN32
/**
 * @brief Initialize the FIM database.
 *
 * It will be dbsync the responsible of managing the DB.
 * @param storage storage 1 Store database in memory, disk otherwise.
 * @param sync_interval Interval when the synchronization will be performed.
 * @param file_limit Maximum number of files to be monitored
 * @param sync_callback Callback to send the synchronization messages.
 * @param log_callback Callback to perform logging operations.
 */
void fim_db_init(int storage,
                 int sync_interval,
                 int file_limit,
                 fim_sync_callback_t sync_callback,
                 logging_callback_t log_callback);
#else
/**
 * @brief Initialize the FIM database.
 *
 * It will be dbsync the responsible of managing the DB.
 * @param storage storage 1 Store database in memory, disk otherwise.
 * @param sync_interval Interval when the synchronization will be performed.
 * @param file_limit Maximum number of files to be monitored
 * @param sync_callback Callback to send the synchronization messages.
 * @param log_callback Callback to perform logging operations.
 */
void fim_db_init(int storage,
                 int sync_interval,
                 int file_limit,
                 int value_limit,
                 fim_sync_callback_t sync_callback,
                 logging_callback_t log_callback);
#endif

/**
 * @brief Get entry data using path.
 *
 * @param file_path File path can be a pattern or a primary key
 * @param data Pointer to the data structure where the callback context will be stored.
 *
 * @return FIMDB_OK on success, FIMDB_ERROR on failure.
 */
int fim_db_get_path(const char* file_path, callback_context_t data);

/**
 * @brief Find entries based on pattern search.
 *
 * @param pattern Pattern to be searched.
 * @param data Pointer to the data structure where the callback context will be stored.
 *
 * @return FIMDB_OK on success, FIMDB_ERROR on failure.
 */
int fim_db_file_pattern_search(const char* pattern, callback_context_t data);

/**
 * @brief Delete entry from the DB using file path.
 *
 * @param path Path of the entry to be removed.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_remove_path(const char* path);

/**
 * @brief Get count of all inodes in file_entry table.
 *
 * @return Number of inodes in file_entry table.
 */
int fim_db_get_count_file_inode();

/**
 * @brief Get count of all entries in file_entry table.
 *
 * @return Number of entries in file_entry table.
 */
int fim_db_get_count_file_entry();

/**
 * @brief Makes any necessary queries to get the entry updated in the DB.
 *
 * @param path The path to the file being processed.
 * @param data The information linked to the path to be created or updated
 * @param updated The updated is a flag to keep if the operation was updated or not.
 * @return The result of the update operation.
 * @retval Returns any of the values returned by fim_db_set_scanned and fim_db_insert_entry.
 */
int fim_db_file_update(const fim_entry* data, bool* updated);

/**
 * @brief Find entries using the inode.
 *
 * @param inode Inode.
 * @param dev Device.
 * @param data Pointer to the data structure where the callback context will be stored.
 */
void fim_db_file_inode_search(unsigned long int inode, unsigned long int dev, callback_context_t data);

/**
 * @brief Push a message to the syscheck queue
 *
 * @param msg The specific message to be pushed
 */
void fim_sync_push_msg(const char* msg);

/**
 * @brief Thread that performs the syscheck data synchronization
 *
 */
void fim_run_integrity();

/*
 * @brief Function that starts a new DBSync transaction.
 *
 * @param table Database table that will be used in the DBSync transaction.
 * @param row_callback Callback that is going to be executed for each insertion or modification.
 * param user_data Context that will be used in the callback.
 *
 * @return TXN_HANDLE Transaction handler.
 */
TXN_HANDLE fim_db_transaction_start(const char* table, result_callback_t row_callback, void *user_data);

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
FIMDBErrorCodes fim_db_transaction_sync_row(TXN_HANDLE txn_handler, const fim_entry* entry);

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
FIMDBErrorCodes fim_db_transaction_deleted_rows(TXN_HANDLE txn_handler,
                                                result_callback_t callback,
                                                void* txn_ctx);

#ifdef __cplusplus
}
#endif // _cplusplus
#endif // FIMDB_H
