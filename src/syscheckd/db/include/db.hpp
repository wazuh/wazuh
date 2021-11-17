/**
 * @file db.hpp
 * @brief Definition of FIM database library.
 * @date 2019-08-28
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#ifndef FIMDB_H
#define FIMDB_H

#ifdef __cplusplus
extern "C" {
#endif


#define fim_db_decode_registry_value_full_row(stmt) _fim_db_decode_registry_value(stmt, 11)

#include "shared.h"
#include <openssl/evp.h>
#include "syscheck.h"
#include "external/sqlite/sqlite3.h"
#include "config/syscheck-config.h"
#ifdef WIN32
#include "registry/registry.h"
#endif
#define FIM_DB_MEMORY_PATH  ":memory:"

#ifndef WAZUH_UNIT_TESTING
#define FIM_DB_DISK_PATH    "queue/fim/db/fim.db"
#define FIM_DB_TMPDIR       "tmp/"
#else
#ifndef WIN32
#define FIM_DB_DISK_PATH    "./fim.db"
#define FIM_DB_TMPDIR       "./"
#else
#define FIM_DB_DISK_PATH    ".\\fim.db"
#define FIM_DB_TMPDIR       ".\\"
#endif
#endif


#define COMMIT_INTERVAL     2

#define FIMDB_OK 0   // Successful result.
#define FIMDB_ERR -1 // Generic error.
#define FIMDB_FULL -2 // DB is full.

#define FIMDB_RM_MAX_LOOP 10 // Max number of loop iterations
#define FIMDB_RM_DEFAULT_TIME 100 //miliseconds

#define FIM_LAST_ROW 0
#define FIM_FIRST_ROW 1

#define EVP_MAX_MD_SIZE 64

#define FIM_DB_PATHS    100

#define FIM_DB_DECODE_TYPE(_func) (void *(*)(sqlite3_stmt *))(_func)
#define FIM_DB_FREE_TYPE(_func) (void (*)(void *))(_func)
#define FIM_DB_CALLBACK_TYPE(_func) (void (*)(fdb_t *, void *, int,  void *))(_func)
#include "commonDefs.h"
extern const char* schema_fim_sql;

/**
 * @brief Executes a simple query in a given database.
 *
 * @param fim_sql The FIM database structure where the database is.
 * @param query The query to be executed.
 *
 * @return int 0 on success, -1 on error.
 */
int fim_db_exec_simple_wquery(fdb_t* fim_sql, const char* query);


/**
 * @brief
 *
 * @param fim_sql FIM database structure.
 * @param type Variable to indicate if the query is for registries or for files. 0 (FIM_TYPE_FILE) for files
 *  1 (FIM_TYPE_REGISTRY) for registries.
 * @param index Statement index.
 * @param callback Callback to be used.
 * @param storage Type of storage (memory or disk).
 * @param arg Storage which contains all the paths
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_process_get_query(fdb_t* fim_sql, int type, int index, void (*callback)(fdb_t*, fim_entry*, int, void*),
                             int storage, void* arg);

/**
 * @brief
 *
 * @param fim_sql FIM database structure.
 * @param index Statement index.
 * @param decode Decode function to be used.
 * @param free_row Free function to be used.
 * @param callback Callback to be used.
 * @param storage Type of storage (memory or disk).
 * @param arg Storage which contains all the paths.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_multiple_row_query(fdb_t* fim_sql, int index, void* (*decode)(sqlite3_stmt*), void (*free_row)(void*),
                              void (*callback)(fdb_t*, void*, int, void*), int storage, void* arg);

/**
 * @brief Create a new database.
 *
 * @param path New database path.
 * @param source SQlite3 schema file.
 * @param storage Type of storage (memory or disk).
 * @param fim_db Database pointer.
 *
 * @return 0 on success, -1 otherwise
 */
int fim_db_create_file(const char* path, const char* source, int storage, sqlite3** fim_db);

/**
 * @brief Create a new temporal storage to save all the files' paths.
 *
 * @param storage Type of storage (memory or disk).
 *
 * @return New file structure.
 */
fim_tmp_file* fim_db_create_temp_file(int storage);


/**
 * @brief Clean and free resources.
 *
 * @param file Storage structure.
 * @param storage Type of storage (memory or disk).
 */
void fim_db_clean_file(fim_tmp_file** file, int storage);

/**
 * @brief Get a fim entry from a path received in a failed synchronization.
 *
 * @param fim_sql FIM database struct.
  * @param type Variable to indicate if the query is for registries or for files. 0 (FIM_TYPE_FILE) for files
 *  1 (FIM_TYPE_REGISTRY) for registries.
 * @param path A string to the path of the object to map in a fim_entry.
 *
 * @return FIM entry struct on success, NULL on error.
 */
fim_entry* fim_db_get_entry_from_sync_msg(fdb_t* fim_sql, fim_type type, const char* path);

/**
 * @brief Read paths and registry paths which are stored in a temporal storage.
 *
 * @param fim_sql FIM database structure.
 * @param type Type of entry that will be used. It can be FIM_TYPE_REGISTRY or FIM_TYPE_FILE.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param callback Function to call within a step.
 * @param mode FIM mode for callback function.
 * @param w_evt Whodata information for callback function.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_process_read_file(fdb_t* fim_sql, fim_tmp_file* file, int type, pthread_mutex_t* mutex,
                             void (*callback)(fdb_t*, fim_entry*, pthread_mutex_t*, void*, void*, void*),
                             int storage, void* alert, void* mode, void* w_evt);

/**
 * @brief Calculate checksum of data entries between @start and @top.
 *
 * Said range will be split into two and the resulting checksums will
 * be returned in their corresponding parameters.
 *
 * @param fim_sql FIM database struct.
  * @param type FIM_TYPE_FILE or FIM_TYPE_REGISTRY.
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param n Number of entries between start and stop.
 * @param ctx_left FIM database's lower side checksum.
 * @param ctx_right FIM database's upper side checksum.
 * @param str_pathlh Holds FIM database's last path of the lower side on a succesful exit.
 * @param str_pathuh Holds FIM database's first path of the higher side on a succesful exit.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_checksum_range(fdb_t* fim_sql,
                              fim_type type,
                              const char* start,
                              const char* top,
                              int n,
                              EVP_MD_CTX* ctx_left,
                              EVP_MD_CTX* ctx_right,
                              char** str_pathlh,
                              char** str_pathuh);

/**
 * @brief Get path list between @start and @top. (stored in @file).
 *
 * @param fim_sql FIM database struct.
 * @param type FIM_TYPE_FILE or FIM_TYPE_REGISTRY.
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param file  Structure of the storage which contains all the paths.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_path_range(fdb_t* fim_sql, fim_type type, const char* start, const char* top, fim_tmp_file** file, int storage);

/**
 * @brief Initialize the FIM database.
 *
 * It will be dbsync the responsible of managing the DB.
 * @param storage storage 1 Store database in memory, disk otherwise.
 * @param sync_interval Interval when the synchronization will be performed.
 * @param file_limit Maximum number of files to be monitored
 * @param sync_callback Callback to send the synchronization messages.
 * @param log_callback Callback to perform logging operations.
 * @return int
 */
int fim_db_init(int storage, int sync_interval, int file_limit, fim_sync_callback_t sync_callback, logging_callback_t log_callback);

/**
 * @brief Finalize stmt and close DB.
 *
 * @param fim_sql FIM database struct.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
void fim_db_close(fdb_t* fim_sql);

/**
 * @brief Clean the FIM databases.
 *
 */
void fim_db_clean(void);

/**
 * @brief Compile all statement associated with FIM queries.
 *
 * @param fim_sql FIM database struct.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_cache(fdb_t* fim_sql);

/**
 * @brief Finalize all statements.
 *
 * @param fim_sql FIM database struct.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_finalize_stmt(fdb_t* fim_sql);

/**
 * @brief End transaction and commit.
 *
 * @param fim_sql FIM database struct.
 */
void fim_db_check_transaction(fdb_t* fim_sql);

/**
 * @brief Force the commit in the database.
 *
 * @param fim_sql FIM database struct.
 */
void fim_db_force_commit(fdb_t* fim_sql);

/**
 * @brief Reset statement and clean bindings parameters.
 *
 * @param fim_sql FIM database struct.
 * @param index Statement index.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_clean_stmt(fdb_t* fim_sql, int index);

/**
 * @brief Get count of all entries in the database. This function must not be called from outside fim_db,
 * use `fim_db_get_count` instead.
 *
 * The database to count is chosen with the index variable.
 *
 * @param fim_sql FIM database struct.
 * @param index Index to SQL statement.
 *
 * @return Number of entries in selected database.
*/
int _fim_db_get_count(fdb_t* fim_sql, int index);

/**
 * @brief Get count of all entries in the database.
 *
 * The database to count is chosen with the index variable.
 *
 * @param fim_sql FIM database struct.
 * @param index Index to SQL statement.
 *
 * @return Number of entries in selected database.
*/
int fim_db_get_count(fdb_t* fim_sql, int index);

/**
 * @brief Count the number of entries between range @start and @top.
 *
 * @param fim_sql FIM database struct.
 * @param type FIM_TYPE_FILE or FIM_TYPE_REGISTRY.
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param counter Pointer which will hold the final count.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_count_range(fdb_t* fim_sql, fim_type type, const char* start, const char* top, int* counter);


// Callbacks

/**
 * @brief Write an entry path into the storage pointed by @arg.
 *
 * @param fim_sql FIM database struct.
 * @param entry FIM entry to save.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param args Storage which contains all the paths.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
void fim_db_callback_save_path(fdb_t* fim_sql, fim_entry* entry, int storage, void* arg);

/**
 * @brief Write a string into the storage pointed by @arg.
 *
 * @param fim_sql FIM database struct.
 * @param str String to be saved into storage.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param arg Storage which contains all the strings.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
void fim_db_callback_save_string(fdb_t* fim_sql, const char* str, int storage, void* arg);

/**
 * @brief Callback function: Entry checksum calculation.
 *
 * @param fim_sql FIM database struct.
 * @param checksum Checksum to be added to the ongoing digest.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param arg
 */
void fim_db_callback_calculate_checksum(fdb_t* fim_sql, char* checksum, int storage, void* arg);

/**
 * @brief Binds data into a range data statement.
 *
 * @param fim_sql FIM database structure.
 * @param index Index of the particular statement.
 * @param start First entry of the range.
 * @param top Last entry of the range.
 */
void fim_db_bind_range(fdb_t* fim_sql, int index, const char* start, const char* top);

/**
 * @brief Decode a single string from the executed sqlite3 statement.
 *
 * @param stmt A sqlite3_stmt that has just been stepped.
 * @return A string with the query result, the caller is responsible of deallocating it using free. NULL on error.
 */
char* fim_db_decode_string(sqlite3_stmt* stmt);

/**
 * @brief Get the last/first row from file_entry.
 *
 * @param fim_sql FIM database struct.
 * @param type FIM_TYPE_FILE or FIM_TYPE_REGISTRY.
 * @param path pointer of pointer where the path will be stored.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_last_path(fdb_t* fim_sql, int type, char** path);

/**
 * @brief Get the last/first row from file_entry.
 *
 * @param fim_sql FIM database struct.
 * @param type FIM_TYPE_FILE or FIM_TYPE_REGISTRY.
 * @param path pointer of pointer where the path will be stored.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_first_path(fdb_t* fim_sql, int type, char** path);

/**
 * @brief Get checksum of all file_entry.
 *
 * @param fim_sql FIM database struct.
 * @param type FIM_TYPE_FILE or FIM_TYPE_REGISTRY.
 * @param arg CTX object.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_data_checksum(fdb_t* fim_sql, fim_type type, void* arg);

/**
 * @brief Read a single line from a fim_tmp_file.
 *
 * @param file A fim_tmp_file pointer from which to read the line.
 * @param storage Type of storage (memory or disk).
 * @param it The current line number to be read.
 * @param buffer Buffer where the line will be saved.
 *
 * @retval 0
 * Line readed successfuly
 * @retval 1
 * End of file
 * @retval -1
 * Fail at fseek
 */
int fim_db_read_line_from_file(fim_tmp_file* file, int storage, int it, char** buffer);

/**
 * @brief Get count of all entries in the FIM DB.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of entries in the FIM DB.
 */
int fim_db_get_count_entries(fdb_t* fim_sql);

/**
 * @brief Check if the FIM DB is full.
 *
 * @param fim_sql FIM database struct.
 * @retval 0 if the DB is not full.
 * @retval 1 if the DB is full.
 */
int fim_db_is_full(fdb_t* fim_sql);

/**
 * @brief Check if database if full
 *
 * @param fim_sql FIM database structure.
 */
int fim_db_check_limit(fdb_t* fim_sql);


/**
 * @brief Get list of all paths by storing them in a temporal file.
 *
 * @param fim_sql FIM database struct.
 * @param index Type of query.
 * @param fd File where all paths will be stored.
 *
 * @return FIM entry struct on success, NULL on error.
 */
int fim_db_get_multiple_path(fdb_t* fim_sql, int index, FILE* fd);

/**
 * @brief Get entry data using path.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 *
 * @return FIM entry struct on success, NULL on error.
 */
fim_entry* fim_db_get_path(fdb_t* fim_sql, const char* file_path);

/**
 * @brief Get all the paths asociated to an inode
 *
 * @param fim_sql FIM databse struct.
 * @param inode Inode.
 * @param dev Device.
 *
 * @return char** An array of the paths asociated to the inode.
 */
char** fim_db_get_paths_from_inode(fdb_t* fim_sql, unsigned long int inode, unsigned long int dev);

/**
 * @brief Delete entry from the DB using file path.
 *
 * @param fim_sql FIM database struct.
 * @param path Path of the entry to be removed.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_remove_path(fdb_t* fim_sql, const char* path);

/**
 * @brief Set all entries from database to unscanned.
 *
 * @param fim_sql FIM database struct.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_all_unscanned(fdb_t* fim_sql);

/**
 * @brief Get all the unscanned files by saving them in a temporal storage.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_not_scanned(fdb_t* fim_sql, fim_tmp_file** file, int storage);

/**
 * @brief Delete not scanned entries from database.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_not_scanned(fdb_t* fim_sql, fim_tmp_file* file, pthread_mutex_t* mutex, int storage);

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
int fim_db_delete_range(fdb_t* fim_sql,
                        fim_tmp_file* file,
                        pthread_mutex_t* mutex,
                        int storage,
                        event_data_t* evt_data,
                        directory_t* configuration);

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
int fim_db_process_missing_entry(fdb_t* fim_sql,
                                 fim_tmp_file* file,
                                 pthread_mutex_t* mutex,
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
int fim_db_remove_wildcard_entry(fdb_t* fim_sql,
                                 fim_tmp_file* file,
                                 pthread_mutex_t* mutex,
                                 int storage,
                                 event_data_t* evt_data,
                                 directory_t* configuration);

/**
 * @brief Decodes a row from the database to be saved in a fim_entry structure.
 *
 * @param stmt The statement to be decoded.
 *
 * @return fim_entry* The filled structure.
 */
fim_entry* fim_db_decode_full_row(sqlite3_stmt* stmt);

/**
 * @brief Get count of all inodes in file_entry table.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of inodes in file_entry table.
 */
int fim_db_get_count_file_inode(fdb_t* fim_sql);

/**
 * @brief Get count of all entries in file_entry table.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of entries in file_entry table.
 */
int fim_db_get_count_file_entry(fdb_t* fim_sql);

/**
 * @brief Get path list using the sqlite LIKE operator using @pattern. (stored in @file).
 * @param fim_sql FIM database struct.
 * @param pattern Pattern that will be used for the LIKE operation.
 * @param file Structure of the storage which contains all the paths.
 * @param storage 1 Store database in memory, disk otherwise.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_path_from_pattern(fdb_t* fim_sql, const char* pattern, fim_tmp_file** file, int storage);

/**
 * @brief Makes any necessary queries to get the entry updated in the DB.
 *
 * @param fim_sql FIM database struct.
 * @param path The path to the file being processed.
 * @param data The information linked to the path to be updated
 * @param saved If the file had information stored in the DB, that data is returned in this parameter.
 * @return The result of the update operation.
 * @retval Returns any of the values returned by fim_db_set_scanned and fim_db_insert_entry.
 */
int fim_db_file_update(fdb_t* fim_sql, const char* path, const fim_file_data* data, fim_entry** saved);

#ifdef WIN32

/**
 * @brief Read registry data that are stored in a temporal storage.
 *
 * @param fim_sql FIM database structure.
 * @param file Structure of the file which contains all the key ids and value names.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param callback Function to call within a step.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param alert False don't send alert, True send delete alert.
 * @param mode FIM mode for callback function.
 * @param w_evt Whodata information for callback function.
 *
 */
int fim_db_process_read_registry_data_file(fdb_t* fim_sql, fim_tmp_file* file, pthread_mutex_t* mutex,
                                           void (*callback)(fdb_t*, fim_entry*, pthread_mutex_t*, void*, void*, void*),
                                           int storage, void* alert, void* mode, void* w_evt);

// Registry callbacks

/**
 * @brief Write an entry path into the storage pointed by @args.
 *
 * @param fim_sql FIM database struct.
 * @param entry Registry value data to be saved.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param arg Storage which contains all the paths.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
void fim_db_callback_save_reg_data_name(fdb_t* fim_sql, fim_entry* entry, int storage, void* arg);

// Registry functions.

/**
 * @brief Get checksum of all registry key.
 *
 * @param fim_sql FIM database struct.
 * @param arg CTX object.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_key_checksum(fdb_t* fim_sql, void* arg);

/**
 * @brief Get checksum of all registry data.
 *
 * @param fim_sql FIM database struct.
 * @param arg CTX object.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_data_checksum(fdb_t* fim_sql, void* arg);

/**
 * @brief Get the rowid of a key path.
 * @param fim_sql FIM database struct
 * @param path Path of the key to look for
 * @param rowid Variable where the rowid will be stored
 * @param arch Architecture of the registry
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_key_rowid(fdb_t* fim_sql, const char* path, unsigned int arch, unsigned int* rowid);

/**
 * @brief Get registry data using its key_id and name. This function must not be called from outside fim_db,
 * use `fim_db_get_registry_data` instead.
 *
 * @param fim_sql FIM database struct.
 * @param key_id ID of the registry.
 * @param name Name of the registry value.
 *
 * @return FIM registry data struct on success, NULL on error.
 */
fim_registry_value_data* _fim_db_get_registry_data(fdb_t* fim_sql, unsigned int key_id, const char* name);

/**
 * @brief Get registry data using its key_id and name.
 *
 * @param fim_sql FIM database struct.
 * @param key_id ID of the registry.
 * @param name Name of the registry value.
 *
 * @return FIM registry data struct on success, NULL on error.
 */
fim_registry_value_data* fim_db_get_registry_data(fdb_t* fim_sql, unsigned int key_id, const char* name);

/**
 * @brief Get a registry key using its path. This function must not be called from outside fim_db,
 * use `fim_db_get_registry_key` instead.
 *
 * @param fim_sql FIM database struct.
 * @param arch An integer specifying the bit count of the register element, must be ARCH_32BIT or ARCH_64BIT.
 * @param path Path to registry key.
 * @param arch Architecture of the registry
 *
 * @return FIM registry key struct on success, NULL on error.
*/
fim_registry_key* _fim_db_get_registry_key(fdb_t* fim_sql, const char* path, unsigned int arch);

/**
 * @brief Get a registry key using its path.
 *
 * @param fim_sql FIM database struct.
 * @param arch An integer specifying the bit count of the register element, must be ARCH_32BIT or ARCH_64BIT.
 * @param path Path to registry key.
 * @param arch Architecture of the registry
 *
 * @return FIM registry key struct on success, NULL on error.
*/
fim_registry_key* fim_db_get_registry_key(fdb_t* fim_sql, const char* path, unsigned int arch);


/**
 * @brief Get all the key paths
 *
 * @param fim_sql FIM databse struct.
 * @param key_id key_id of the registry data table.
 *
 * @return char** An array of the paths asociated to the key_id.
 */
char** fim_db_get_all_registry_key(fdb_t* fim_sql, unsigned long int key_id);

/**
 * @brief Insert or update registry data.
 *
 * @param fim_sql FIM database struct.
 * @param data Registry data to be inserted.
 * @param key_id Registry key ID.
 * @param replace_entry 0 if a new registry_data entry is being inserted.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_registry_data(fdb_t* fim_sql,
                                fim_registry_value_data* data,
                                unsigned int key_id,
                                unsigned int replace_entry);

/**
 * @brief Insert or update registry key.
 *
 * @param fim_sql FIM database struct.
 * @param entry Registry key to be inserted.
 * @param rowid Row id of the registry.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_registry_key(fdb_t* fim_sql, fim_registry_key* entry, unsigned int rowid);

/**
 * @brief Calculate checksum of registry keys between @start and @top.
 *
 * Said range will be split into two and the resulting checksums will
 * be sent as sync messages.
 *
 * @param fim_sql FIM database struct
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param id Sync session counter (timetamp).
 * @param n Number of entries between start and stop.
 * @param mutex FIM database's mutex for thread synchronization.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_registry_key_checksum_range(fdb_t* fim_sql, const char* start, const char* top,
                                       long id, int n, pthread_mutex_t* mutex);

/**
 * @brief Count the number of entries between range @start and @top.
 *
 * @param fim_sql FIM database struct
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param counter Pointer which will hold the final count.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_key_count_range(fdb_t* fim_sql, char* start, char* top, int* counter);

/**
 * @brief Count the number of registry data entries between range @start and @top.
 *
 * @param fim_sql FIM database struct
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param counter Pointer which will hold the final count.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */

int fim_db_get_registry_data_count_range(fdb_t* fim_sql, const char* start, const char* top, int* counter);

/**
 * @brief Get the last/first row from registry_key table.
 *
 * @param fim_sql FIM database struct
 * @param mode FIM_FIRST_ROW or FIM_LAST_ROW.
 * @param path pointer of pointer where the path will be stored.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_row_registry_key(fdb_t* fim_sql, int mode, char** path);

/**
 * @brief Get the last/first row from registry_data table.
 *
 * @param fim_sql FIM database struct
 * @param mode FIM_FIRST_ROW or FIM_LAST_ROW.
 * @param path pointer of pointer where the path will be stored.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_row_registry_data(fdb_t* fim_sql, int mode, char** path);

/**
 * @brief Set all entries from registry_key table to unscanned.
 *
 * @param fim_sql FIM database struct.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_all_registry_key_unscanned(fdb_t* fim_sql);

/**
 * @brief Set all entries from registry_data table to unscanned.
 *
 * @param fim_sql FIM database struct.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_all_registry_data_unscanned(fdb_t* fim_sql);

/**
 * @brief Set a registry key as scanned.
 *
 * @param fim_sql FIM database struct.
 * @param path Registry key path.
 * @param arch Architecture of the registry
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_registry_key_scanned(fdb_t* fim_sql, const char* path, unsigned int arch);

/**
 * @brief Set a registry data as scanned.
 *
 * @param fim_sql FIM database struct.
 * @param name Value name.
 * @param key_id key_id of the registry data table.
 * @param file_path File path.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_registry_data_scanned(fdb_t* fim_sql, const char* name, unsigned int key_id);

/**
 * @brief Get all the unscanned registries keys by saving them in a temporal storage.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_keys_not_scanned(fdb_t* fim_sql, fim_tmp_file** file, int storage);

/**
 * @brief Get all the unscanned registries values by saving them in a temporal storage.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_data_not_scanned(fdb_t* fim_sql, fim_tmp_file** file, int storage);

/**
 * @brief Get count of all entries in registry data table.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of entries in registry data table.
 */
int fim_db_get_count_registry_data(fdb_t* fim_sql);

/**
 * @brief Get count of all entries in registry key table.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of entries in registry data table.
 */
int fim_db_get_count_registry_key(fdb_t* fim_sql);

/**
 * @brief Get registry keys between @start and @top. (stored in @file).
 *
 * @param fim_sql FIM database struct.
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param file  Structure of the storage which contains all the paths.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 *
 */
int fim_db_get_registry_value_range(fdb_t* fim_sql, const char* start, const char* top, fim_tmp_file** file,
                                    int storage);

/**
 * @brief Removes a range of registry keys from the database.
 * The key paths are alphabetically ordered.
 * The range is given by start and top parameters.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_registry_key_range(fdb_t* fim_sql, fim_tmp_file* file, pthread_mutex_t* mutex, int storage);

/**
 * @brief Removes a range of registry data from the database.
 * The key paths are alphabetically ordered.
 * The range is given by start and top parameters.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_registry_value_range(fdb_t* fim_sql, fim_tmp_file* file, pthread_mutex_t* mutex, int storage);
/**
 * @brief Remove a range of registry keys from database if they have a
 * specific monitoring mode.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param mode FIM mode (scheduled, realtime or whodata)
 * @param w_evt Whodata information
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_process_missing_registry_key_entry(fdb_t* fim_sql, fim_tmp_file* file, pthread_mutex_t* mutex, int storage,
                                              fim_event_mode mode, whodata_evt* w_evt);

/**
 * @brief Remove a range of registry data from database if they have a
 * specific monitoring mode.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param mode FIM mode (scheduled, realtime or whodata)
 * @param w_evt Whodata information
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_process_missing_registry_data_entry(fdb_t* fim_sql, fim_tmp_file* file, pthread_mutex_t* mutex, int storage,
                                               fim_event_mode mode, whodata_evt* w_evt);


/**
 * @brief Get count of all entries in registry key and registry data table.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of entries in registry key table.
 */
int fim_db_get_count_registry_key_data(fdb_t* fim_sql);

/**
 * @brief Delete registry using registry entry.
 *
 * @param fim_sql FIM database struct.
 * @param entry Registry entry.
 */
int fim_db_remove_registry_key(fdb_t* fim_sql, fim_entry* entry);

/**
 * @brief Delete registry data using fim_registry_value_data entry.
 *
 * @param fim_sql FIM database struct.
 * @param entry fim_registry_value_data entry.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_remove_registry_value_data(fdb_t* fim_sql, fim_registry_value_data* entry);

/**
 * @brief Get a registry using it's id.
 *
 * @param fim_sql FIM database struct.
 * @param id Id of the registry key
 *
 * @return fim_registry_key structure.
 */
fim_registry_key* fim_db_get_registry_key_using_id(fdb_t* fim_sql, unsigned int id);

/**
 * @brief Get all registry values from given id.
 *
 * Given an id, save in a fim_tmp_file all its values.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param storage Type of storage (memory or disk).
 * @param key_id Key id of the values.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_values_from_registry_key(fdb_t* fim_sql, fim_tmp_file** file, int storage, unsigned long int key_id);

/**
 * @brief Decodes a row from the database to be saved in a fim_registry_key structure.
 *
 * @param stmt The statement to be decoded.
 *
 * @return fim_registry_key* The filled structure.
 */
fim_registry_key* fim_db_decode_registry_key(sqlite3_stmt* stmt);

/**
 * @brief Decodes a row from the database to be saved in a fim_registry_value_data structure.
 *
 * @param stmt The statement to be decoded.
 *
 * @return fim_registry_value_data* The filled structure.
 */
fim_registry_value_data* fim_db_decode_registry_value(sqlite3_stmt* stmt);

/**
 * @brief Decodes a row from the registry database to be saved in a registry key structure.
 *
 * @param stmt The statement to be decoded.
 * @param index Index of the statement.
 *
 * @return fim_entry* The filled structure.
 */
fim_entry* fim_db_decode_registry(int index, sqlite3_stmt* stmt);

#endif /* WIN32 */
#ifdef __cplusplus
}
#endif // _cplusplus
#endif // FIMDB_H
