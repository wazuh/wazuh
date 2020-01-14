/**
 * @file fim_db.h
 * @author Alberto Marin
 * @author Cristobal Lopez
 * @brief FIM database library.
 * @date 2020-1-10
 *
 * @copyright Copyright (c) 2019 Wazuh, Inc.
 */

/*
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "../headers/shared.h"
#include "../wazuh_db/wdb.h"
#include "../headers/os_utils.h"
#include "../config/syscheck-config.h"
#include <openssl/evp.h>

#define FIM_DB_MEM ":memory:"
#define FIM_DB_PATH DEFAULTDIR "/queue/db/fim/fim.db"
#define COMMIT_INTERVAL 1

#define FIMDB_OK   0 // Successful result.
#define FIMDB_ERR -1 // Generic error.

#define FIM_LAST_ROW -1
#define FIM_FIRST_ROW 1

extern const char *schema_fim_sql;

typedef enum fdb_stmt {
    FIMDB_STMT_INSERT_DATA,
    FIMDB_STMT_INSERT_PATH,
    FIMDB_STMT_GET_PATH,
    FIMDB_STMT_GET_INODE,
    FIMDB_STMT_GET_LAST_ROW,
    FIMDB_STMT_GET_FIRST_ROW,
    FIMDB_STMT_GET_ALL_ENTRIES,
    FIMDB_STMT_GET_NOT_SCANNED,
    FIMDB_STMT_SET_ALL_UNSCANNED,
    FIMDB_STMT_DELETE_UNSCANNED,
    FIMDB_STMT_UPDATE_ENTRY_DATA,
    FIMDB_STMT_UPDATE_ENTRY_PATH,
    FIMDB_STMT_GET_PATH_COUNT,
    FIMDB_STMT_DELETE_PATH,
    FIMDB_STMT_GET_DATA_ROW,
    FIMDB_STMT_DELETE_DATA_ROW,
    FIMDB_STMT_GET_HARDLINK_COUNT,
    FIMDB_STMT_DELETE_PATH_INODE,
    FIMDB_STMT_DISABLE_SCANNED,
    FIMDB_STMT_GET_UNIQUE_FILE,
    FIMDB_STMT_SIZE
} fdb_stmt;

typedef struct transaction_t {
    time_t last_commit;
    time_t interval;
} transaction_t;

typedef struct fdb_t {
    sqlite3 * db;
    sqlite3_stmt *stmt[FIMDB_STMT_SIZE];
    transaction_t transaction;
} fdb_t;


/**
 * @brief Initialize FIM databases.
 * Checks if the databases exists.
 * If it exists deletes the previous version and creates a new one.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_init(void);


/**
 * @brief Clean the FIM databases.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_clean(void);


/**
 * @brief Insert a new entry.
 *
 * @param file_path File path.
 * @param entry Entry data to be inserted.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert(const char* file_path, fim_entry_data *entry);


/**
 * @brief Update/Replace entry.
 *
 * @param inode File inode.
 * @param device Device ID.
 * @param entry New entry data.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_update(const unsigned long int inode, const unsigned long int dev, fim_entry_data *entry);


/**
 * @brief Delete entry using file path.
 *
 * @param file_path File path.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete(const char * file_path);


/**
 * @brief Get entry data using inode.
 *
 * @param inode Inode
 * @param dev Device
 * @return List of fim_entry_data.
 */
fim_entry * fim_db_get_inode(const unsigned long int inode, const unsigned long int dev);

/**
 * @brief Get the last/first row from entry_path.
 *
 * @param mode FIM_FIRST_ROW or FIM_LAST_ROW.
 * @return path located at the specified row.
 */
char * fim_db_get_row_path(int mode);

/**
 * @brief Get entry data using path.
 *
 * @param file_path File path.
 * @return FIM entry struct.
 */
fim_entry * fim_db_get_path(const char * file_path);


/**
 * @brief Get a unique file entry using its path, inode, and device.
 *
 * @param file_path File path.
 * @param inode File inode.
 * @param dev Device ID.
 * @return FIM entry struct.
 */
fim_entry * fim_db_get_unique_file(const char * file_path, const unsigned long int inode, const unsigned long int dev);


/**
 * @brief Get all the paths within a range.
 *
 * @param start Starting path.
 * @param end Last included path.
 * @param callback Callback function.
 * @param arg Callback argument.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_range(const char * start, const char * end, void (*callback)(fim_entry *, void *), void * arg);


/**
 * @brief Get all the paths in the DB.
 * This function will return a list with the paths in ascending order.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_all(void *arg);


/**
 * @brief Set all files to 'not scanned'.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_all_unscanned(void);


/**
 * @brief Delete all unscanned entries.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 *
 */
int fim_db_delete_all(void);


/**
 *
 * @brief Calculate checksum for all data entries.
 *
 * @param ctx Structure that contains the global checksum.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise
 *
 */
int fim_db_get_data_checksum(void * ctx);


/**
 * @brief Get all files not scanned.
 *
 * @param callback Callback function (fim_report_deleted).
 * @param arg Callback argument.
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_not_scanned();


/**
 * @brief Perform the transaction if required.
 * It must not be called from a critical section.
 *
 */
void fim_check_transaction(void);


/**
 * @brief Returm the statement associated with the query.
 *
 * @param index Query index.
 * @return An statement on success, NULL otherwise.
 */
sqlite3_stmt *fim_db_cache(fdb_stmt index);


/**
 * @brief Force the commit in the database.
 *
 */
void fim_force_commit(void);


/**
 * @brief Callback function: Entry checksum calculation.
 *
 */
void fim_db_callback_calculate_checksum(fim_entry *entry, void *arg);
