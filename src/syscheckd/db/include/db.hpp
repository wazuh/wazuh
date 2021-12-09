/**
 * @file db.hpp
 * @brief Definition of FIM database library.
 * @date 2019-08-28
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#ifndef FIMDB_H
#define FIMDB_H
#include "fimCommonDefs.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/evp.h>
#include "syscheck.h"

#define FIM_DB_MEMORY_PATH  ":memory:"
#define FIM_DB_DISK_PATH    "queue/fim/db/fim.db"

#define EVP_MAX_MD_SIZE 64

#define FILE_PRIMARY_KEY "path"

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
 *
 * @return FIM entry struct on success, NULL on error.
 */
fim_entry* fim_db_get_path(const char* file_path);

/**
 * @brief Get all the paths asociated to an inode
 *
 * @param inode Inode.
 * @param dev Device.
 *
 * @return char** An array of the paths asociated to the inode.
 */
char** fim_db_get_paths_from_inode(unsigned long int inode, unsigned long int dev);

/**
 * @brief Delete entry from the DB using file path.
 *
 * @param path Path of the entry to be removed.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_remove_path(const char* path);

/**
 * @brief Removes a range of paths from the database.
 *
 * The paths are alphabetically ordered.
 * The range is given by start and top parameters.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param evt_data Information on how the event was triggered.
 * @param configuration An integer holding the position of the configuration that corresponds to the entries to be deleted.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_range(const char* pattern,
                        pthread_mutex_t* mutex,
                        event_data_t* evt_data,
                        const directory_t* configuration);

/**
 * @brief Remove a range of paths from database if they have a specific monitoring mode.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param evt_data Information on how the event was triggered.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_process_missing_entry(pthread_mutex_t* mutex,
                                 int storage,
                                 event_data_t* evt_data);

/**
 * @brief Remove a wildcard directory that were not expanded from the configuration
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param evt_data Information on how the event was triggered.
 * @param configuration An integer holding the position of the configuration that corresponds to the entries to be deleted.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_remove_wildcard_entry(pthread_mutex_t* mutex,
                                 int storage,
                                 event_data_t* evt_data,
                                 directory_t* configuration);

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

#ifdef __cplusplus
}
#endif // _cplusplus
#endif // FIMDB_H
