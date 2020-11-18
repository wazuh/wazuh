/**
 * @file fim_sync.c
 * @brief Definition of FIM data synchronization library
 * @date 2019-08-28
 *
 * @copyright Copyright (c) 2019 Wazuh, Inc.
 */


#include "shared.h"
#include <openssl/evp.h>
#include "syscheck.h"
#include "external/sqlite/sqlite3.h"
#include "config/syscheck-config.h"

#define FIM_DB_MEMORY_PATH  ":memory:"

#ifndef WIN32
#define FIM_DB_DISK_PATH    DEFAULTDIR "/queue/fim/db/fim.db"
#define FIM_DB_TMPDIR       DEFAULTDIR "/tmp/"
#else
#define FIM_DB_DISK_PATH    "queue/fim/db/fim.db"
#define FIM_DB_TMPDIR       "tmp/"
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

extern const char *schema_fim_sql;

/**
 * @brief Initialize FIM databases.
 * Checks if the databases exists.
 * If it exists deletes the previous version and creates a new one.
 *
 * @param fim_sql FIM database struct.
 * @param storage 1 Store database in memory, disk otherwise.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
fdb_t *fim_db_init(int storage);

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
 */
void fim_db_clean(void);

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
 * @brief Get entry data using path.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 * @return FIM entry struct on success, NULL on error.
 */
fim_entry *fim_db_get_path(fdb_t *fim_sql, const char *file_path);

/**
 * @brief Get list of all paths by storing them in a temporal file.
 *
 * @param fim_sql FIM database struct.
 * @param index Type of query.
 * @param fd    File where all paths will be stored.
 * @return FIM entry struct on success, NULL on error.
 */
int fim_db_get_multiple_path(fdb_t *fim_sql, int index, FILE *fd);

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
 * @param entry Entry data to be inserted.
 * @param row_id
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_data(fdb_t *fim_sql, fim_entry_data *entry, int *row_id);

/**
 * @brief Insert or update entry path.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 * @param entry Entry data to be inserted.
 * @param inode_id
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_path(fdb_t *fim_sql, const char *file_path, fim_entry_data *entry, int inode_id);

/**
 * @brief Insert an entry in the needed tables.
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
 * @param new Entry data to be inserted.
 * @param saved Entry with existing data.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert(fdb_t *fim_sql, const char *file_path, fim_entry_data *new, fim_entry_data *saved);

/**
 * @brief Send sync message for all entries.
 * @param fim_sql FIM database struct.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param fd    Structure of temporal storage which contains all the paths.
 */
int fim_db_sync_path_range(fdb_t *fim_sql, pthread_mutex_t *mutex,
                            fim_tmp_file *file, int storage);

/**
 * @brief Callback function: Entry checksum calculation.
 *
 */
void fim_db_callback_calculate_checksum( fdb_t *fim_sql, fim_entry *entry, int storage,
                                         void *arg);

/**
 * @brief Calculate checksum of data entries between @start and @top.
 * Said range will be splitted into two and the resulting checksums will
 * be sent as sync messages.
 *
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param id Sync session counter (timetamp).
 * @param n Number of entries between start and stop.
 * @param mutex FIM database's mutex for thread synchronization.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_data_checksum_range(fdb_t *fim_sql, const char *start, const char *top,
                                const long id, const int n, pthread_mutex_t *mutex);

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
 * @param mutex
 * @param alert False don't send alert, True send delete alert.
 * @param fim_ev_mode FIM Mode (scheduled/realtime/whodata)
 * @param w_evt Whodata information
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
void fim_db_remove_path(fdb_t *fim_sql, fim_entry *entry, pthread_mutex_t *mutex,
                        __attribute__((unused))void *alert,
                        __attribute__((unused))void *fim_ev_mode,
                        __attribute__((unused))void *w_evt);

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
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_all_unscanned(fdb_t *fim_sql);

/**
 * @brief
 *
 * @param fim_sql FIM database struct.
 * @param file_path File path.
* @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_scanned(fdb_t *fim_sql, char *path);

/**
 * @brief Get all the unscanned files by saving them in a temporal storage.
 *
 * @param fim_sql FIM database struct.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param File    Structure of the file which contains all the paths.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_not_scanned(fdb_t * fim_sql,fim_tmp_file **file, int storage);

/**
 * @brief Write an entry path into the storage pointed by @args.
 *
 * @param fim_sql FIM database struct.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param args    Storage which contains all the paths.
 * @param pos     If memory is 1, pos indicates the position in the array.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
void fim_db_callback_save_path(fdb_t *fim_sql, fim_entry *entry, int storage, void *arg);

/**
 * @brief Callback function to send a sync message for a sole entry.
 * @param fim_sql FIM database struct.
 * @param entry Entry data to be inserted.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param mode  Unused argument.
 * @param w_event Unused argument.
 */
void fim_db_callback_sync_path_range(__attribute__((unused))fdb_t *fim_sql, fim_entry *entry,
    __attribute__((unused))pthread_mutex_t *mutex, __attribute__((unused))void *alert,
    __attribute__((unused))void *mode, __attribute__((unused))void *w_event);

/**
 * @brief Delete not scanned entries from database.
 *
 * @param fim_sql FIM database struct.
 * @param file    Structure of the file which contains all the paths.
 * @param mutex
 * @param storage 1 Store database in memory, disk otherwise.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_not_scanned(fdb_t *fim_sql, fim_tmp_file *file,
                                pthread_mutex_t *mutex, int storage);

/**
 * @brief Get path list between @start and @top. (stored in @file).
 *
 * @param fim_sql FIM database struct.
 * @param file  Structure of the storage which contains all the paths.
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param storage 1 Store database in memory, disk otherwise.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 *
 */
int fim_db_get_path_range(fdb_t *fim_sql, char *start, char *top,
                         fim_tmp_file **file, int storage) ;

/**
 * @brief Removes a range of paths from the database.
 * The paths are alphabetically ordered.
 * The range is given by start and top parameters.
 *
 * @param fim_sql FIM database struct.
 * @param file  Structure of the file which contains all the paths.
 * @param mutex
 * @param storage 1 Store database in memory, disk otherwise.
 * @param mode FIM mode (scheduled, realtime or whodata)
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_range(fdb_t * fim_sql, fim_tmp_file *file,
                        pthread_mutex_t *mutex, int storage, fim_event_mode mode);

/**
 * @brief Remove a range of paths from database if they have a
 * specific monitoring mode.
 *
 * @param fim_sql FIM database struct.
 * @param file  Structure of the file which contains all the paths.
 * @param mutex
 * @param storage 1 Store database in memory, disk otherwise.
 * @param mode FIM mode (scheduled, realtime or whodata)
 * @param w_evt Whodata information
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_process_missing_entry(fdb_t *fim_sql, fim_tmp_file *file,
                                 pthread_mutex_t *mutex, int storage,
                                 fim_event_mode mode,
                                 whodata_evt * w_evt);

/**
 * @brief Get count of all entries in entry_data table.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of entries in entry_data table.
 */
int fim_db_get_count_entry_data(fdb_t * fim_sql);

/**
 * @brief Get count of all entries in entry_path table.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of entries in entry_path table.
 */
int fim_db_get_count_entry_path(fdb_t * fim_sql);
