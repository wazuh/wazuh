/**
 * @file fim_sync.c
 * @author
 * @brief Definition of FIM data synchronization library
 * @version 0.1
 * @date 2019-08-28
 *
 * @copyright Copyright (c) 2019 Wazuh, Inc.
 */

#include <openssl/evp.h>
#include "shared.h"
#include "syscheck.h"
#include "external/sqlite/sqlite3.h"
#include "config/syscheck-config.h"

#define FIM_DB_MEMORY_PATH  ":memory:"

#ifndef WIN32
#define FIM_DB_DISK_PATH    DEFAULTDIR "/queue/db/fim.db"
#else
#define FIM_DB_DISK_PATH    "queue/fim/db/fim.db"
#endif
#define COMMIT_INTERVAL     2

#define FIMDB_OK 0   // Successful result.
#define FIMDB_ERR -1 // Generic error.

#define FIM_LAST_ROW 0
#define FIM_FIRST_ROW 1

#define EVP_MAX_MD_SIZE 64

extern const char *schema_fim_sql;

/**
 * @brief Initialize FIM databases.
 * Checks if the databases exists.
 * If it exists deletes the previous version and creates a new one.
 *
 * @param fim_sql FIM database struct.
 * @param memory 1 Store database in memory, disk otherwise.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
fdb_t *fim_db_init(int memory);

/**
 * @brief Finalize stmt and close DB
 *
 * @param fim_sql FIM database struct.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
void fim_db_close(fdb_t *fim_sql);

/**
 * @brief Clean the FIM databases.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_clean(void);

/**
 * @brief Compile all statement associated with FIM queries.
 *
 * @param fim_sql FIM database struct.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_cache(fdb_t *fim_sql);

/**
 * @brief Finalize all statements
 *
 * @param fim_sql FIM database struct.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_finalize_stmt(fdb_t *fim_sql);

/**
 * @brief End transaction and commit.
 *
 * @param fim_sql FIM database struct.
 */
void fim_db_check_transaction(fdb_t *fim_sql);

/**
 * @brief Force the commit in the database.
 *
 * @param fim_sql FIM database struct.
 */
void fim_db_force_commit(fdb_t *fim_sql);

/**
 * @brief Reset statement and clean bindings parameters
 *
 * @param fim_sql FIM database struct.
 * @param index Statement index.
 */
int fim_db_clean_stmt(fdb_t *fim_sql, int index);

/**
 * @brief Get checksum of all entry_data.
 * @param fim_sql FIM database struct.
 * @param arg CTX object.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_data_checksum(fdb_t *fim_sql, void * arg);

/**
 * @brief Send sync messages for all entries between @start and @top.
 *
 * @param start First entry of the range.
 * @param top Last entry of the range.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_sync_path_range(fdb_t *fim_sql, char *start, char *top);

/**
 * @brief Get entry data using path.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 * @return FIM entry struct on success, NULL on error.
 */
fim_entry *fim_db_get_path(fdb_t *fim_sql, const char *file_path);

/**
 * @brief Check if a specific inode exists in the database
 *
 * @param fim_sql FIM database struct.
 * @param inode Inode.
 * @param dev Device.
 * @return int 1 if exists, 0 if not.
 */
int fim_db_get_inode(fdb_t *fim_sql, const unsigned long int inode, const unsigned long int dev);

/**
 * @brief Get all the paths asociated to an inode
 *
 * @param fim_sql FIM databse struct.
 * @param inode Inode.
 * @param dev Device.
 * @return char** An array of the paths asociated to the inode.
 */
char **fim_db_get_paths_from_inode(fdb_t *fim_sql, const unsigned long int inode, const unsigned long int dev);

/**
 * @brief Insert or update entry data.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 * @param entry Entry data to be inserted.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_data(fdb_t *fim_sql, const char *file_path, fim_entry_data *entry);

/**
 * @brief Insert or update entry path.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 * @param entry Entry data to be inserted.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_path(fdb_t *fim_sql, const char *file_path, fim_entry_data *entry);

/**
 * @brief Callback function: Send sync message for a sole entry.
 *
 */
 void fim_db_callback_sync_path_range(__attribute__((unused)) fdb_t *fim_sql,
                                      fim_entry *entry, void *arg);

/**
 * @brief Callback function: Entry checksum calculation.
 *
 */
void fim_db_callback_calculate_checksum(__attribute__((unused)) fdb_t *fim_sql,
                                        fim_entry *entry, void *arg);

/**
 * @brief Calculate checksum of data entries between @start and @top.
 * Said range will be splitted into two and the resulting checksums will
 * be sent as sync messages.
 *
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param id Sync session counter (timetamp).
 * @param n Number of entries between start and stop.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_data_checksum_range(fdb_t *fim_sql, const char *start, const char *top,
                                const long id, const int n);

/**
 * @brief Count the number of entries between range @start and @top.
 *
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param counter Pointer which will hold the final count.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_count_range(fdb_t *fim_sql, char *start, char *top, int *counter);

/**
 * @brief Delete entry using file path.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 * @param arg 0 No send alert, 1 send delete alert.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
void fim_db_remove_path(fdb_t *fim_sql, fim_entry *entry, void *arg);

/**
 * @brief Delete not scanned entries from database.
 *
 * @param fim_sql FIM database struct.
 * @return int
 */
int fim_db_delete_not_scanned(fdb_t * fim_sql);

/**
 * @brief Removes a range of paths from the database.
 * The paths are alphabetically ordered.
 * The range is given by start and top parameters.
 *
 * @param fim_sql FIM database struct.
 * @param start Path that sets the beggining of the range.
 * @param top Path that sets the ending of the range.
 * @return int
 */
int fim_db_delete_range(fdb_t * fim_sql, char *start, char *top);

/**
 * @brief Get the last/first row from entry_path.
 *
 * @param mode FIM_FIRST_ROW or FIM_LAST_ROW.
 * @param path pointer of pointer where the path will be stored.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_row_path(fdb_t *fim_sql, int mode, char **path);

/**
 * @brief Set all entries from database to unscanned.
 *
 * @param fim_sql FIM database struct.
 * @return int
 */
int fim_db_set_all_unscanned(fdb_t *fim_sql);

/**
 * @brief
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 */
int fim_db_set_scanned(fdb_t *fim_sql, char *path);
