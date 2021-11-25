/**
 * @file db.hpp
 * @brief Definition of FIM database library.
 * @date 2019-08-28
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#ifndef FIMDB_H
#define FIMDB_H
#include "commonDefs.h"

#ifdef __cplusplus
extern "C" {
#endif

// #define fim_db_decode_registry_value_full_row(stmt) _fim_db_decode_registry_value(stmt, 11)


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
enum FIMDBErrorCodes fim_db_init(int storage, int sync_interval, int file_limit, fim_sync_callback_t sync_callback,
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
enum FIMDBErrorCodes fim_db_init(int storage, int sync_interval, int file_limit, int value_limit,
                             fim_sync_callback_t sync_callback, logging_callback_t log_callback);
#endif

#ifdef __cplusplus
}
#endif // _cplusplus
#endif // FIMDB_H
