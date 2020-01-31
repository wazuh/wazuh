/**
 * @file fim_sync.c
 * @author
 * @brief Definition of FIM data synchronization library
 * @version 0.1
 * @date 2019-08-28
 *
 * @copyright Copyright (c) 2019 Wazuh, Inc.
 */

#include "fim_db.h"


static const char *SQL_STMT[] = {
    [FIMDB_STMT_INSERT_DATA] = "INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [FIMDB_STMT_INSERT_PATH] = "INSERT INTO entry_path (path, inode_id, mode, last_event, entry_type, scanned, options, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
    [FIMDB_STMT_GET_PATH] = "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_path INNER JOIN entry_data ON path = ? AND entry_data.rowid = entry_path.inode_id;",
    [FIMDB_STMT_GET_INODE] = "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_path INNER JOIN entry_data ON inode = ? AND dev = ? AND entry_data.rowid = entry_path.inode_id;",
    [FIMDB_STMT_UPDATE_DATA] = "UPDATE entry_data SET size = ?, perm = ?, attributes = ?, uid = ?, gid = ?, user_name = ?, group_name = ?, hash_md5 = ?, hash_sha1 = ?, hash_sha256 = ?, mtime = ? WHERE dev = ? AND inode = ?;",
    [FIMDB_STMT_UPDATE_PATH] = "UPDATE entry_path SET mode = ?, last_event = ?, entry_type = ?, scanned = ?, options = ?, checksum = ? WHERE inode_id = (SELECT rowid FROM entry_data WHERE dev = ? AND inode = ?);",
    [FIMDB_STMT_GET_LAST_PATH] = "SELECT path FROM entry_path ORDER BY path DESC LIMIT 1;",
    [FIMDB_STMT_GET_FIRST_PATH] = "SELECT path FROM entry_path ORDER BY path ASC LIMIT 1;",
    [FIMDB_STMT_GET_ALL_ENTRIES] = "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_data INNER JOIN entry_path ON inode_id = entry_data.rowid ORDER BY PATH ASC;",
    [FIMDB_STMT_GET_NOT_SCANNED] = "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_data INNER JOIN entry_path ON inode_id = entry_data.rowid WHERE scanned = 0 ORDER BY PATH ASC;",
    [FIMDB_STMT_SET_ALL_UNSCANNED] = "UPDATE entry_path SET scanned = 0;",
    [FIMDB_STMT_GET_PATH_COUNT] = "SELECT count(inode_id), inode_id FROM entry_path WHERE inode_id = (select inode_id from entry_path where path = ?);",
    [FIMDB_STMT_GET_DATA_ROW] = "SELECT rowid FROM entry_data WHERE inode = ? AND dev = ?;",
    [FIMDB_STMT_GET_COUNT_RANGE] = "SELECT count(*) FROM entry_path INNER JOIN entry_data ON entry_data.rowid = entry_path.inode_id WHERE path BETWEEN ? and ? ORDER BY path;",
    [FIMDB_STMT_GET_PATH_RANGE] = "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_path INNER JOIN entry_data ON entry_data.rowid = entry_path.inode_id WHERE path BETWEEN ? and ? ORDER BY path;",
    [FIMDB_STMT_DELETE_PATH] = "DELETE FROM entry_path WHERE path = ?;",
    [FIMDB_STMT_DELETE_DATA] = "DELETE FROM entry_data WHERE rowid = ?;",
    [FIMDB_STMT_GET_PATHS_INODE] = "SELECT path FROM entry_path INNER JOIN entry_data ON entry_data.rowid=entry_path.inode_id WHERE entry_data.inode=? AND entry_data.dev=?;",
    [FIMDB_STMT_GET_PATHS_INODE_COUNT] = "SELECT count(*) FROM entry_path INNER JOIN entry_data ON entry_data.rowid=entry_path.inode_id WHERE entry_data.inode=? AND entry_data.dev=?;",
    [FIMDB_STMT_SET_SCANNED] = "UPDATE entry_path SET scanned = 1 WHERE path = ?;",
};

/**
 * @brief Decodes a row from the database to be saved in a fim_entry structure.
 *
 * @param stmt The statement to be decoded.
 * @return fim_entry* The filled structure.
 */
static fim_entry *fim_db_decode_full_row(sqlite3_stmt *stmt);

/**
 * @brief Executes a simple query in a given database.
 *
 * @param fim_sql The FIM database structure where the database is.
 * @param query The query to be executed.
 * @return int 0 on success, -1 on error.
 */
static int fim_db_exec_simple_wquery(fdb_t *fim_sql, const char *query);

/**
 * @brief
 *
 * @param fim_sql FIM database structure.
 * @param index
 * @param callback
 * @param arg
 * @return int
 */
static int fim_db_process_get_query(fdb_t *fim_sql, int index,
                                    void (*callback)(fdb_t *, fim_entry *, void *),
                                    void * arg);

/**
 * @brief Binds data into a insert data statement.
 *
 * @param fim_sql FIM database structure.
 * @param entry FIM entry data structure.
 */
static void fim_db_bind_insert_data(fdb_t *fim_sql, fim_entry_data *entry);

/**
 * @brief Binds data into a insert data statement.
 *
 * @param fim_sql FIM database structure.
 * @param start First entry of the range.
 * @param top Last entry of the range.
 */
void fim_db_bind_range(fdb_t *fim_sql, int index, const char *start, const char *top);

/**
 * @brief Binds a range of paths.
 *
 * @param fim_sql FIM database structure.
 * @param file_path File name of the file to insert.
 * @param row_id Row id to be bound.
 * @param entry FIM entry data structure.
 */
static void fim_db_bind_insert_path(fdb_t *fim_sql, const char *file_path,
                                    int row_id, fim_entry_data *entry);

/**
 * @brief Binds a path into a statement.
 *
 * @param fim_sql FIM database structure.
 * @param index Index of the particular statement.
 * @param file_path File name of the file to insert.
 */
static void fim_db_bind_path(fdb_t *fim_sql, int index,
                             const char * file_path);

/**
 * @brief Binds data into a get inode statement.
 *
 * @param fim_sql FIM database structure.
 * @param index Index of the particular statement.
 * @param inode Inode of the file.
 * @param dev dev of the file.
 */
static void fim_db_bind_get_inode(fdb_t *fim_sql, int index,
                                  const unsigned long int inode,
                                  const unsigned long int dev);

/**
 * @brief Binds data into an update entry data statement.
 *
 * @param fim_sql FIM database structure.
 * @param entry FIM entry data structure.
 */
static void fim_db_bind_update_data(fdb_t *fim_sql,
                                          fim_entry_data *entry);

/**
 * @brief Binds data into an update entry path statement.
 *
 * @param fim_sql FIM database structure.
 * @param entry FIM entry data structure.
 */
static void fim_db_bind_update_path(fdb_t *fim_sql,
                                          fim_entry_data *entry);

/**
 * @brief Binds data into a delete data id statement.
 *
 * @param fim_sql FIM database structure.
 * @param row The especific row.
 */
static void fim_db_bind_delete_data_id(fdb_t *fim_sql, int row);


/**
 * @brief Create a new database.
 * @param path New database path.
 * @param source SQlite3 schema file.
 * @param memory Boolean value to choose between db stored in disk or in memory.
 * @param fim_db Database pointer.
 *
 */
static int fim_db_create_file(const char *path, const char *source, const int memory, sqlite3 **fim_db);

/**
 * @brief
 *
 * @param fim_sql FIM database structure.
 * @param file_path File name of the file to insert.
 */
void fim_db_bind_set_scanned(fdb_t *fim_sql, const char *file_path);


fdb_t *fim_db_init(int memory) {
    fdb_t *fim;
    char *path = (memory == 1) ? FIM_DB_MEMORY_PATH : FIM_DB_DISK_PATH;

    os_calloc(1, sizeof(fdb_t), fim);
    fim->transaction.interval = COMMIT_INTERVAL;

    if (fim_db_clean() < 0) {
        goto free_fim;
    }

    if (fim_db_create_file(path, schema_fim_sql, memory, &fim->db) < 0) {
        goto free_fim;
    }

    if (!memory &&
        sqlite3_open_v2(path, &fim->db, SQLITE_OPEN_READWRITE, NULL)) {
        goto free_fim;
    }

    if (fim_db_cache(fim)) {
        goto free_fim;
    }

    char *error;
    sqlite3_exec(fim->db, "PRAGMA synchronous = OFF", NULL, NULL, &error);

    if (error) {
        merror("SQL ERROR: %s", error);
        sqlite3_free(error);
        goto free_fim;
    }

    if (fim_db_exec_simple_wquery(fim, "BEGIN;") == FIMDB_ERR) {
        goto free_fim;
    }

    return fim;

free_fim:
    if (fim->db){ 
        sqlite3_close(fim->db);
    }
    os_free(fim);
    return NULL;
}

void fim_db_close(fdb_t *fim_sql) {
    fim_db_force_commit(fim_sql);
    fim_db_finalize_stmt(fim_sql);
    sqlite3_close_v2(fim_sql->db);
}

int fim_db_clean(void) {
    if (w_is_file(FIM_DB_DISK_PATH)) {
        return remove(FIM_DB_DISK_PATH);
    }
    return FIMDB_OK;
}

int fim_db_cache(fdb_t *fim_sql) {
    int index;
    int retval = FIMDB_ERR;

    for (index = 0; index < FIMDB_STMT_SIZE; index++) {
        if (sqlite3_prepare_v2(fim_sql->db, SQL_STMT[index], -1,
            &fim_sql->stmt[index], NULL) != SQLITE_OK) {
            merror("Error in fim_db_cache(): statement(%d)'%s' %s", index, SQL_STMT[index], sqlite3_errmsg(fim_sql->db));
            goto end;
        }
    }

    retval = FIMDB_OK;
end:
    return retval;
}

int fim_db_create_file(const char *path, const char *source, const int memory, sqlite3 **fim_db) {
    const char *sql;
    const char *tail;

    sqlite3 *db;
    sqlite3_stmt *stmt;
    int result;

    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
        printf("Couldn't create SQLite database '%s': %s", path, sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        return -1;
    }

    for (sql = source; sql && *sql; sql = tail) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, &tail) != SQLITE_OK) {
            printf("Preparing statement: %s", sqlite3_errmsg(db));
            sqlite3_close_v2(db);
            return -1;
        }

        result = sqlite3_step(stmt);

        switch (result) {
        case SQLITE_MISUSE:
        case SQLITE_ROW:
        case SQLITE_DONE:
            break;
        default:
            printf("Stepping statement: %s", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            sqlite3_close_v2(db);
            return -1;
        }

        sqlite3_finalize(stmt);
    }

    if (memory == 1) {
        *fim_db = db;
        return 0;
    }

    sqlite3_close_v2(db);

    if (chmod(path, 0660) < 0) {
        printf("CHMOD_ERROR");
        return -1;
    }

    return 0;
}

int fim_db_finalize_stmt(fdb_t *fim_sql) {
    int index;
    int retval = FIMDB_ERR;

    for (index = 0; index < FIMDB_STMT_SIZE; index++) {
        fim_db_clean_stmt(fim_sql, index);
        if (sqlite3_finalize(fim_sql->stmt[index]) != SQLITE_OK) {
            merror("Error in fim_db_finalize_stmt(): statement(%d)'%s' %s", index, SQL_STMT[index], sqlite3_errmsg(fim_sql->db));
            goto end;
        }
    }

    retval = FIMDB_OK;
end:
    return retval;
}

void fim_db_check_transaction(fdb_t *fim_sql) {
    time_t now = time(NULL);

    if (fim_sql->transaction.last_commit + fim_sql->transaction.interval <= now) {
        if (!fim_sql->transaction.last_commit) {
            fim_sql->transaction.last_commit = now;
            return;
        }

        // If the completion of the transaction fails, we do not update the timestamp
        if (fim_db_exec_simple_wquery(fim_sql, "END;") != FIMDB_ERR) {
            mdebug1("Database transaction completed.");
            fim_sql->transaction.last_commit = now;
            while (fim_db_exec_simple_wquery(fim_sql, "BEGIN;") == FIMDB_ERR);
        }
    }
}

void fim_db_force_commit(fdb_t *fim_sql) {
    fim_sql->transaction.last_commit = 1;
    fim_db_check_transaction(fim_sql);
}

int fim_db_clean_stmt(fdb_t *fim_sql, int index) {
    if (sqlite3_reset(fim_sql->stmt[index]) != SQLITE_OK || sqlite3_clear_bindings(fim_sql->stmt[index]) != SQLITE_OK) {
        sqlite3_finalize(fim_sql->stmt[index]);

        if (sqlite3_prepare_v2(fim_sql->db, SQL_STMT[index], -1, &fim_sql->stmt[index], NULL) != SQLITE_OK) {
            merror("Error in fim_db_cache(): %s", sqlite3_errmsg(fim_sql->db));
            return FIMDB_ERR;
        }
    }

    return FIMDB_OK;
}

/** Wrapper functions **/

int fim_db_get_data_checksum(fdb_t *fim_sql, void * arg) {
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_ALL_ENTRIES);
    return fim_db_process_get_query(fim_sql, FIMDB_STMT_GET_ALL_ENTRIES, fim_db_callback_calculate_checksum, arg);
}

int fim_db_sync_path_range(fdb_t *fim_sql, char *start, char *top) {
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH_RANGE);
    fim_db_bind_range(fim_sql, FIMDB_STMT_GET_PATH_RANGE, start, top);
    return fim_db_process_get_query(fim_sql, FIMDB_STMT_GET_PATH_RANGE, fim_db_callback_sync_path_range, NULL);
}

int fim_db_delete_not_scanned(fdb_t * fim_sql) {
    return fim_db_process_get_query(fim_sql, FIMDB_STMT_GET_NOT_SCANNED,
                                    fim_db_remove_path, (void *) (int) 1);
}

int fim_db_delete_range(fdb_t * fim_sql, char *start, char *top) {
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH_RANGE);
    fim_db_bind_range(fim_sql, FIMDB_STMT_GET_PATH_RANGE, start, top);
    return fim_db_process_get_query(fim_sql, FIMDB_STMT_GET_PATH_RANGE,
                                    fim_db_remove_path, NULL);
}

int fim_db_process_get_query(fdb_t *fim_sql, int index, void (*callback)(fdb_t *, fim_entry *, void *), void * arg) {
    int result;

    while (result = sqlite3_step(fim_sql->stmt[index]), result == SQLITE_ROW) {
        fim_entry *entry = fim_db_decode_full_row(fim_sql->stmt[index]);
        callback(fim_sql, (void *) entry, arg);

        free_entry(entry);
    }

    fim_db_check_transaction(fim_sql);

    return result != SQLITE_DONE ? FIMDB_ERR : FIMDB_OK;
}

int fim_db_exec_simple_wquery(fdb_t *fim_sql, const char *query) {
    char *error = NULL;

    sqlite3_exec(fim_sql->db, query, NULL, NULL, &error);

    if (error) {
        merror("SQL ERROR: %s", error);
        sqlite3_free(error);
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

fim_entry *fim_db_decode_full_row(sqlite3_stmt *stmt) {
    fim_entry *entry = NULL;

    os_calloc(1, sizeof(fim_entry), entry);
    w_strdup((char *)sqlite3_column_text(stmt, 0), entry->path);

    os_calloc(1, sizeof(fim_entry_data), entry->data);
    entry->data->mode = (unsigned int)sqlite3_column_int(stmt, 2);
    entry->data->last_event = (time_t)sqlite3_column_int(stmt, 3);
    entry->data->entry_type = sqlite3_column_int(stmt, 4);
    entry->data->scanned = (time_t)sqlite3_column_int(stmt, 5);
    entry->data->options = (time_t)sqlite3_column_int(stmt, 6);
    strncpy(entry->data->checksum, (char *)sqlite3_column_text(stmt, 7), sizeof(os_sha1) - 1);
    entry->data->dev = (unsigned long int)sqlite3_column_int(stmt, 8);
    entry->data->inode = (unsigned long int)sqlite3_column_int(stmt, 9);
    entry->data->size = (unsigned int)sqlite3_column_int(stmt, 10);
    w_strdup((char *)sqlite3_column_text(stmt, 11), entry->data->perm);
    w_strdup((char *)sqlite3_column_text(stmt, 12), entry->data->attributes);
    w_strdup((char *)sqlite3_column_text(stmt, 13), entry->data->uid);
    w_strdup((char *)sqlite3_column_text(stmt, 14), entry->data->gid);
    w_strdup((char *)sqlite3_column_text(stmt, 15), entry->data->user_name);
    w_strdup((char *)sqlite3_column_text(stmt, 16), entry->data->group_name);
    strncpy(entry->data->hash_md5, (char *)sqlite3_column_text(stmt, 17), sizeof(os_md5) - 1);
    strncpy(entry->data->hash_sha1, (char *)sqlite3_column_text(stmt, 18), sizeof(os_sha1) - 1);
    strncpy(entry->data->hash_sha256, (char *)sqlite3_column_text(stmt, 19), sizeof(os_sha256) - 1);
    entry->data->mtime = (unsigned int)sqlite3_column_int(stmt, 20);

    return entry;
}

/* No needed bind FIMDB_STMT_GET_LAST_ROWID, FIMDB_STMT_GET_ALL_ENTRIES, FIMDB_STMT_GET_NOT_SCANNED,
   FIMDB_STMT_SET_ALL_UNSCANNED, FIMDB_STMT_DELETE_UNSCANNED */

/* FIMDB_STMT_INSERT_DATA */
void fim_db_bind_insert_data(fdb_t *fim_sql, fim_entry_data *entry) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 1, entry->dev);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 2, entry->inode);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 3, entry->size);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 4, entry->perm, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 5, entry->attributes, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 6, entry->uid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 7, entry->gid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 8, entry->user_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 9, entry->group_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 10, entry->hash_md5, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 11, entry->hash_sha1, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 12, entry->hash_sha256, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 13, entry->mtime);
}

/* FIMDB_STMT_INSERT_PATH */
void fim_db_bind_insert_path(fdb_t *fim_sql, const char *file_path, int row_id, fim_entry_data *entry) {
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_PATH], 1, file_path, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_PATH], 2, row_id);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_PATH], 3, entry->mode);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_PATH], 4, entry->last_event);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_PATH], 5, entry->entry_type);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_PATH], 6, entry->scanned);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_PATH], 7, entry->options);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_PATH], 8, entry->checksum, -1, NULL);
}

/* FIMDB_STMT_GET_PATH, FIMDB_STMT_GET_PATH_COUNT, FIMDB_STMT_DELETE_PATH */
void fim_db_bind_path(fdb_t *fim_sql, int index, const char *file_path) {
    if (index == FIMDB_STMT_GET_PATH || index == FIMDB_STMT_GET_PATH_COUNT || index == FIMDB_STMT_DELETE_PATH) {
        sqlite3_bind_text(fim_sql->stmt[index], 1, file_path, -1, NULL);
    }
}

/* FIMDB_STMT_GET_INODE, FIMDB_STMT_GET_DATA_ROW, FIMDB_STMT_GET_PATHS_INODE, FIMDB_STMT_GET_PATHS_INODE_COUNT */
void fim_db_bind_get_inode(fdb_t *fim_sql, int index, const unsigned long int inode, const unsigned long int dev) {
    if (index == FIMDB_STMT_GET_INODE || index == FIMDB_STMT_GET_DATA_ROW ||
        index == FIMDB_STMT_GET_PATHS_INODE || index == FIMDB_STMT_GET_PATHS_INODE_COUNT) {
        sqlite3_bind_int(fim_sql->stmt[index], 1, inode);
        sqlite3_bind_int(fim_sql->stmt[index], 2, dev);
    }
}

/* FIMDB_STMT_UPDATE_ENTRY_DATA */
void fim_db_bind_update_data(fdb_t *fim_sql, fim_entry_data *entry) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 1, entry->size);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 2, entry->perm, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 3, entry->attributes, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 4, entry->uid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 5, entry->gid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 6, entry->user_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 7, entry->group_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 8, entry->hash_md5, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 9, entry->hash_sha1, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 10, entry->hash_sha256, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 11, entry->mtime);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 12, entry->dev);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 13, entry->inode);
}

/* FIMDB_STMT_UPDATE_ENTRY_PATH */
void fim_db_bind_update_path(fdb_t *fim_sql, fim_entry_data *entry) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_PATH], 1, entry->mode);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_PATH], 2, entry->last_event);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_PATH], 3, entry->entry_type);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_PATH], 4, entry->scanned);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_PATH], 5, entry->options);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_PATH], 6, entry->checksum, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_PATH], 7, entry->dev);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_PATH], 8, entry->inode);
}

/* FIMDB_STMT_DELETE_DATA */
void fim_db_bind_delete_data_id(fdb_t *fim_sql, int row) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_DELETE_DATA], 1, row);
}

/* FIMDB_STMT_SET_SCANNED */
void fim_db_bind_set_scanned(fdb_t *fim_sql, const char *file_path) {
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_SET_SCANNED], 1, file_path, -1, NULL);
}

void fim_db_bind_range(fdb_t *fim_sql, int index, const char *start, const char *top) {
    if (index == FIMDB_STMT_GET_PATH_RANGE ||
        index == FIMDB_STMT_GET_COUNT_RANGE ) {
        sqlite3_bind_text(fim_sql->stmt[index], 1, start, -1, NULL);
        sqlite3_bind_text(fim_sql->stmt[index], 2, top, -1, NULL);
    }
}

fim_entry *fim_db_get_path(fdb_t *fim_sql, const char *file_path) {
    fim_entry *entry = NULL;

    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH);
    fim_db_bind_path(fim_sql, FIMDB_STMT_GET_PATH, file_path);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATH]) == SQLITE_ROW) {
        entry = fim_db_decode_full_row(fim_sql->stmt[FIMDB_STMT_GET_PATH]);
    }

    return entry;
}

int fim_db_get_inode(fdb_t *fim_sql, const unsigned long int inode, const unsigned long int dev) {
    int ret = FIMDB_OK;

    // Clean statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_INODE);

    fim_db_bind_get_inode(fim_sql, FIMDB_STMT_GET_INODE, inode, dev);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_INODE]) == SQLITE_ROW) {
        ret = FIMDB_ERR;
    }

    fim_db_check_transaction(fim_sql);
    return ret;
}

char **fim_db_get_paths_from_inode(fdb_t *fim_sql, const unsigned long int inode, const unsigned long int dev) {
    char **paths = NULL;

    // Clean statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATHS_INODE);
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATHS_INODE_COUNT);

    fim_db_bind_get_inode(fim_sql, FIMDB_STMT_GET_PATHS_INODE_COUNT, inode, dev);

    if(sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATHS_INODE_COUNT]) == SQLITE_ROW) {
        int result = 0;
        int i = 0;
        int rows = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_PATHS_INODE_COUNT], 0);

        os_calloc(rows + 1, sizeof(char *), paths);
        fim_db_bind_get_inode(fim_sql, FIMDB_STMT_GET_PATHS_INODE, inode, dev);

        while (result = sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATHS_INODE]), result == SQLITE_ROW) {
            if (i >= rows) {
                printf("ERROR: The count returned is smaller than the actual elements. This shouldn't happen.\n");
                break;
            }
            os_strdup((char *)sqlite3_column_text(fim_sql->stmt[FIMDB_STMT_GET_PATHS_INODE], 0), paths[i]);
            i++;
        }
    }

    fim_db_check_transaction(fim_sql);
    return paths;
}

int fim_db_get_count_range(fdb_t *fim_sql, char *start, char *top, int *count) {
    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_COUNT_RANGE);
    fim_db_bind_range(fim_sql, FIMDB_STMT_GET_COUNT_RANGE, start, top);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_COUNT_RANGE]) != SQLITE_ROW) {
        merror("SQL ERROR: %s", sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    *count = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_COUNT_RANGE], 0);

    return FIMDB_OK;
}

int fim_db_insert_data(fdb_t *fim_sql, const char *file_path, fim_entry_data *entry) {
    int res;
    int retval;

    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_INSERT_DATA);
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_UPDATE_DATA);
    fim_db_bind_insert_data(fim_sql, entry);

    res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_INSERT_DATA]);

    switch (res) {
    case SQLITE_DONE:
        break; //Insert succesfull

    case SQLITE_CONSTRAINT:
        // Update entry_data
        fim_db_bind_update_data(fim_sql, entry);

        if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA]), res != SQLITE_DONE) {
            merror("SQL ERROR: (%d)%s", res, sqlite3_errmsg(fim_sql->db));
            return FIMDB_ERR;
        }
        break;

    default:
        merror("SQL ERROR: (%d)%s", res, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;

    }

    retval = fim_db_insert_path(fim_sql, file_path, entry);
    fim_db_check_transaction(fim_sql);
    return retval;
}

int fim_db_insert_path(fdb_t *fim_sql, const char *file_path, fim_entry_data *entry) {
    long long inode_id;
    int res;

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_DATA_ROW);
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_INSERT_PATH);
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_UPDATE_PATH);

    fim_db_bind_get_inode(fim_sql, FIMDB_STMT_GET_DATA_ROW, entry->inode, entry->dev);

    if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_DATA_ROW]), res != SQLITE_ROW) {
        merror("SQL ERROR: (%d)%s", res, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }
    inode_id = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_DATA_ROW], 0);

    // Insert in inode_path
    fim_db_bind_insert_path(fim_sql, file_path, inode_id, entry);

    res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_INSERT_PATH]);

    switch (res) {
    case SQLITE_DONE:
        break;

    case SQLITE_CONSTRAINT: // If path exist need update
        fim_db_bind_update_path(fim_sql, entry);

        if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_UPDATE_PATH]), res != SQLITE_DONE) {
            merror("SQL ERROR: (%d)%s", res, sqlite3_errmsg(fim_sql->db));
            return FIMDB_ERR;
        }
        break;

    default:
        merror("SQL ERROR: (%d)%s", res, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

void fim_db_callback_sync_path_range(__attribute__((unused)) fdb_t *fim_sql,
                                     fim_entry *entry, __attribute__((unused))void *arg) {
        cJSON * entry_data = fim_entry_json(entry->path, entry->data);
        char * plain = dbsync_state_msg("syscheck", entry_data);
        mdebug1("Sync Message for %s sent: %s", entry->path, plain);
        fim_send_sync_msg(plain);
        free(plain);
}

void fim_db_callback_calculate_checksum(__attribute__((unused)) fdb_t *fim_sql, fim_entry *entry, void *arg) {
    EVP_MD_CTX *ctx = (EVP_MD_CTX *)arg;
    EVP_DigestUpdate(ctx, entry->data->checksum, strlen(entry->data->checksum));
}

int fim_db_data_checksum_range(fdb_t *fim_sql, const char *start, const char *top,
                                const long id, const int n) {
    fim_entry *entry = NULL;
    int m = n / 2;
    int i;
    int retval = FIMDB_ERR;
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digest_size = 0;
    os_sha1 hexdigest;
    char *str_pathlh = NULL;
    char *str_pathuh = NULL;
    char *plain      = NULL;

    // Clean statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH_RANGE);

    EVP_MD_CTX *ctx_left = EVP_MD_CTX_create();
    EVP_MD_CTX *ctx_right = EVP_MD_CTX_create();

    EVP_DigestInit(ctx_left, EVP_sha1());
    EVP_DigestInit(ctx_right, EVP_sha1());

    fim_db_bind_range(fim_sql, FIMDB_STMT_GET_PATH_RANGE, start, top);

    // Calculate checksum of the first half
    for (i = 0; i < m; i++) {
        if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATH_RANGE]) != SQLITE_ROW) {
            merror("SQL ERROR: %s", sqlite3_errmsg(fim_sql->db));
            goto end;
        }
        entry = fim_db_decode_full_row(fim_sql->stmt[FIMDB_STMT_GET_PATH_RANGE]);
        if (i == (m - 1) && entry->path) {
            os_strdup(entry->path, str_pathlh);
        }
        fim_db_callback_calculate_checksum(fim_sql, entry, (void *)ctx_left);
        free_entry(entry);
    }

    //Calculate checksum of the second half
    for (i = m; i < n; i++) {
        if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATH_RANGE]) != SQLITE_ROW) {
            merror("SQL ERROR: %s", sqlite3_errmsg(fim_sql->db));
            goto end1;
        }
        entry = fim_db_decode_full_row(fim_sql->stmt[FIMDB_STMT_GET_PATH_RANGE]);
        if (i == m && entry->path) {
            os_strdup(entry->path, str_pathuh);
        }
        fim_db_callback_calculate_checksum(fim_sql, entry, (void *)ctx_right);
        free_entry(entry);
    }

    if (!str_pathlh || !str_pathuh) {
        merror("Failed to obtain required paths in order to form message");
        goto end1;
    }

    // Send message with checksum of first half
    EVP_DigestFinal_ex(ctx_left, digest, &digest_size);
    OS_SHA1_Hexdigest(digest, hexdigest);
    plain = dbsync_check_msg("syscheck", INTEGRITY_CHECK_LEFT, id, start, str_pathlh, str_pathuh, hexdigest);
    fim_send_sync_msg(plain);
    os_free(plain);

    // Send message with checksum of second half
    EVP_DigestFinal_ex(ctx_right, digest, &digest_size);
    OS_SHA1_Hexdigest(digest, hexdigest);
    plain = dbsync_check_msg("syscheck", INTEGRITY_CHECK_RIGHT, id, str_pathuh, top, "", hexdigest);
    fim_send_sync_msg(plain);
    os_free(plain);

    retval = FIMDB_OK;

    end1:
        EVP_MD_CTX_destroy(ctx_right);
        os_free(str_pathlh);
        os_free(str_pathuh);

    end:
        EVP_MD_CTX_destroy(ctx_left);
        return retval;
}

void fim_db_remove_path(fdb_t *fim_sql, fim_entry *entry, __attribute__((unused))void *arg) {

    int *alert = (int *) arg;

    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH_COUNT);
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_DATA);
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_PATH);
    fim_db_bind_path(fim_sql, FIMDB_STMT_GET_PATH_COUNT, entry->path);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATH_COUNT]) == SQLITE_ROW) {
        int rows = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_PATH_COUNT], 0);
        int rowid = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_PATH_COUNT], 1);

        switch (rows) {
        case 0:
            // No entries with this path.
            break;
        case 1:
            // The inode has only one entry, delete the entry data.
            fim_db_bind_delete_data_id(fim_sql, rowid);
            if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_DELETE_DATA]) != SQLITE_DONE) {
                goto end;
            }

            if (alert) {
                cJSON * json_event      = NULL;
                char * json_formated    = NULL;
                int pos = 0;

                const char *FIM_ENTRY_TYPE[] = { "file", "registry"};

                if (pos = fim_configuration_directory(entry->path,
                    FIM_ENTRY_TYPE[entry->data->entry_type]), pos < 0) {
                    goto end;
                }

                json_event = fim_json_event(entry->path, NULL, entry->data, pos,
                                                FIM_DELETE, FIM_SCHEDULED, NULL);

                if (!strcmp(FIM_ENTRY_TYPE[entry->data->entry_type], "file") &&
                    syscheck.opts[pos] & CHECK_SEECHANGES) {
                    delete_target_file(entry->path);
                }

                if (json_event) {
                    mdebug2(FIM_FILE_MSG_DELETE, entry->path);
                    json_formated = cJSON_PrintUnformatted(json_event);
                    send_syscheck_msg(json_formated);

                    os_free(json_formated);
                    cJSON_Delete(json_event);
                }
            }
            // Fallthrough
        default:
            // The inode has more entries, delete only this path.
            fim_db_bind_path(fim_sql, FIMDB_STMT_DELETE_PATH, entry->path);
            if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_DELETE_PATH]) != SQLITE_DONE) {
                goto end;
            }

            break;
        }
    }

   end:
        fim_db_check_transaction(fim_sql);
}

int fim_db_get_row_path(fdb_t * fim_sql, int mode, char **path) {
    int index = (mode)? FIMDB_STMT_GET_FIRST_PATH : FIMDB_STMT_GET_LAST_PATH;
    int result;

    fim_db_clean_stmt(fim_sql, index);

    if (result = sqlite3_step(fim_sql->stmt[index]), result != SQLITE_ROW && result != SQLITE_DONE) {
        merror("SQL ERROR: %s", sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    if (result == SQLITE_ROW) {
        w_strdup((char *)sqlite3_column_text(fim_sql->stmt[index], 0), *path);
    }

    return FIMDB_OK;
}

int fim_db_set_all_unscanned(fdb_t *fim_sql) {
    int retval = fim_db_exec_simple_wquery(fim_sql, SQL_STMT[FIMDB_STMT_SET_ALL_UNSCANNED]);
    fim_db_check_transaction(fim_sql);
    return retval;
}


int fim_db_set_scanned(fdb_t *fim_sql, char *path) {
    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_SET_SCANNED);
    fim_db_bind_set_scanned(fim_sql, path);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_SET_SCANNED]) != SQLITE_DONE) {
        merror("SQL ERROR: %s", sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}
