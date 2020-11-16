/**
 * @file fim_sync.c
 * @brief Definition of FIM data synchronization library
 * @date 2019-08-28
 *
 * @copyright Copyright (c) 2019 Wazuh, Inc.
 */

#include "fim_db.h"

#ifdef WAZUH_UNIT_TESTING
#ifdef WIN32
#include "unit_tests/wrappers/windows/synchapi_wrappers.h"
#include "unit_tests/wrappers/windows/libc/stdio_wrappers.h"
#endif
#define static
#endif

static const char *SQL_STMT[] = {
#ifdef WIN32
    [FIMDB_STMT_INSERT_DATA] = "INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
#else
    [FIMDB_STMT_INSERT_DATA] = "INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
#endif
    [FIMDB_STMT_REPLACE_PATH] = "INSERT OR REPLACE INTO entry_path (path, inode_id, mode, last_event, entry_type, scanned, options, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
    [FIMDB_STMT_GET_PATH] = "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_path INNER JOIN entry_data ON path = ? AND entry_data.rowid = entry_path.inode_id;",
    [FIMDB_STMT_UPDATE_DATA] = "UPDATE entry_data SET size = ?, perm = ?, attributes = ?, uid = ?, gid = ?, user_name = ?, group_name = ?, hash_md5 = ?, hash_sha1 = ?, hash_sha256 = ?, mtime = ? WHERE rowid = ?;",
    [FIMDB_STMT_UPDATE_PATH] = "UPDATE entry_path SET inode_id = ?, mode = ?, last_event = ?, entry_type = ?, scanned = ?, options = ?, checksum = ? WHERE path = ?;",
    [FIMDB_STMT_GET_LAST_PATH] = "SELECT path FROM entry_path ORDER BY path DESC LIMIT 1;",
    [FIMDB_STMT_GET_FIRST_PATH] = "SELECT path FROM entry_path ORDER BY path ASC LIMIT 1;",
    [FIMDB_STMT_GET_ALL_ENTRIES] = "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_data INNER JOIN entry_path ON inode_id = entry_data.rowid ORDER BY PATH ASC;",
    [FIMDB_STMT_GET_NOT_SCANNED] = "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_data INNER JOIN entry_path ON inode_id = entry_data.rowid WHERE scanned = 0 ORDER BY PATH ASC;",
    [FIMDB_STMT_SET_ALL_UNSCANNED] = "UPDATE entry_path SET scanned = 0;",
    [FIMDB_STMT_GET_PATH_COUNT] = "SELECT count(inode_id), inode_id FROM entry_path WHERE inode_id = (select inode_id from entry_path where path = ?);",
#ifndef WIN32
    [FIMDB_STMT_GET_DATA_ROW] = "SELECT rowid FROM entry_data WHERE inode = ? AND dev = ?;",
#else
    [FIMDB_STMT_GET_DATA_ROW] = "SELECT inode_id FROM entry_path WHERE path = ?",
#endif
    [FIMDB_STMT_GET_COUNT_RANGE] = "SELECT count(*) FROM entry_path INNER JOIN entry_data ON entry_data.rowid = entry_path.inode_id WHERE path BETWEEN ? and ? ORDER BY path;",
    [FIMDB_STMT_GET_PATH_RANGE] = "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_path INNER JOIN entry_data ON entry_data.rowid = entry_path.inode_id WHERE path BETWEEN ? and ? ORDER BY path;",
    [FIMDB_STMT_DELETE_PATH] = "DELETE FROM entry_path WHERE path = ?;",
    [FIMDB_STMT_DELETE_DATA] = "DELETE FROM entry_data WHERE rowid = ?;",
    [FIMDB_STMT_GET_PATHS_INODE] = "SELECT path FROM entry_path INNER JOIN entry_data ON entry_data.rowid=entry_path.inode_id WHERE entry_data.inode=? AND entry_data.dev=?;",
    [FIMDB_STMT_GET_PATHS_INODE_COUNT] = "SELECT count(*) FROM entry_path INNER JOIN entry_data ON entry_data.rowid=entry_path.inode_id WHERE entry_data.inode=? AND entry_data.dev=?;",
    [FIMDB_STMT_SET_SCANNED] = "UPDATE entry_path SET scanned = 1 WHERE path = ?;",
    [FIMDB_STMT_GET_INODE_ID] = "SELECT inode_id FROM entry_path WHERE path = ?",
    [FIMDB_STMT_GET_COUNT_PATH] = "SELECT count(*) FROM entry_path",
    [FIMDB_STMT_GET_COUNT_DATA] = "SELECT count(*) FROM entry_data",
    [FIMDB_STMT_GET_INODE] = "SELECT inode FROM entry_data where rowid=(SELECT inode_id FROM entry_path WHERE path = ?)",
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
 * @param pos
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
static int fim_db_process_get_query(fdb_t *fim_sql, int index,
                                    void (*callback)(fdb_t *, fim_entry *, int, void *),
                                    int memory, void * arg);


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
static void fim_db_bind_replace_path(fdb_t *fim_sql, const char *file_path,
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
 * @param row_id Row id in entry_data table.
 */
static void fim_db_bind_update_data(fdb_t *fim_sql,
                                    fim_entry_data *entry,
                                    int *row_id);

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
 * @param storage 1 Store database in memory, disk otherwise.
 * @param fim_db Database pointer.
 *
 */
static int fim_db_create_file(const char *path, const char *source, const int storage, sqlite3 **fim_db);


/**
 * @brief Read paths which are stored in a temporal storage.
 *
 * @param fim_sql FIM database structure.
 * @param mutex
 * @param storage 1 Store database in memory, disk otherwise.
 * @param callback Function to call within a step.
 * @param mode FIM mode for callback function.
 * @param w_evt Whodata information for callback function.
 *
 */
 static int fim_db_process_read_file(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex,
        void (*callback)(fdb_t *, fim_entry *, pthread_mutex_t *, void *, void *, void *), int storage, void * alert, void * mode, void * w_evt);


/**
 * @brief Create a new temporal storage to save all the files' paths.
 * @param size Number of paths(Only if memory is 1)
 * @return New file structure.
 */
static fim_tmp_file *fim_db_create_temp_file(int storage);


/**
 * @brief Clean and free resources
 * @param file Storage structure
 * @param storage Type of storage (memory or disk)
 */
static void fim_db_clean_file(fim_tmp_file **file, int storage);


/**
 * @brief
 *
 * @param fim_sql FIM database structure.
 * @param file_path File name of the file to insert.
 */
void fim_db_bind_set_scanned(fdb_t *fim_sql, const char *file_path);

/**
 * @brief Binds data into a select inode_id statement
 *
 * @param fim_sql FIM database structure.
 * @param file_path File name of the file to select.
 */
void fim_db_bind_get_inode_id(fdb_t *fim_sql, const char *file_path);

/**
 * @brief Binds data into a select inode statement
 *
 * @param fim_sql FIM database structure.
 * @param file_path File name of the file to select.
 */
void fim_db_bind_get_path_inode(fdb_t *fim_sql, const char *file_path);


fdb_t *fim_db_init(int storage) {
    fdb_t *fim;
    char *path = (storage == FIM_DB_MEMORY) ? FIM_DB_MEMORY_PATH : FIM_DB_DISK_PATH;

    os_calloc(1, sizeof(fdb_t), fim);
    fim->transaction.interval = COMMIT_INTERVAL;

    if (storage == FIM_DB_DISK) {
        fim_db_clean();
    }

    if (fim_db_create_file(path, schema_fim_sql, storage, &fim->db) < 0) {
        goto free_fim;
    }

    if (!storage &&
        sqlite3_open_v2(path, &fim->db, SQLITE_OPEN_READWRITE, NULL)) {
        goto free_fim;
    }

    if (fim_db_cache(fim)) {
        goto free_fim;
    }

    char *error;
    sqlite3_exec(fim->db, "PRAGMA synchronous = OFF", NULL, NULL, &error);

    if (error) {
        merror("SQL error turning off synchronous mode: %s", error);
        fim_db_finalize_stmt(fim);
        sqlite3_free(error);
        goto free_fim;
    }

    if (fim_db_exec_simple_wquery(fim, "BEGIN;") == FIMDB_ERR) {
        fim_db_finalize_stmt(fim);
        goto free_fim;
    }

    return fim;

free_fim:
    if (fim->db){
        sqlite3_close_v2(fim->db);
    }
    os_free(fim);
    return NULL;
}

void fim_db_close(fdb_t *fim_sql) {
    fim_db_force_commit(fim_sql);
    fim_db_finalize_stmt(fim_sql);
    sqlite3_close_v2(fim_sql->db);
}


void fim_db_clean(void) {

    if (w_is_file(FIM_DB_DISK_PATH)) {
        // If the file is being used by other processes, wait until
        // it's unlocked in order to remove it. Wait at most 5 seconds.
        int i, rm;
        for (i = 1; i <= FIMDB_RM_MAX_LOOP && (rm = remove(FIM_DB_DISK_PATH)); i++) {
            mdebug2(FIM_DELETE_DB_TRY, FIM_DB_DISK_PATH, i);
#ifdef WIN32
            Sleep(FIMDB_RM_DEFAULT_TIME * i); //milliseconds
#else
            usleep(FIMDB_RM_DEFAULT_TIME * i); //milliseconds
#endif
        }

        //Loop endlessly until the file can be removed. (60s)
        if (rm == FIMDB_ERR) {
            while (remove(FIM_DB_DISK_PATH)) {
                // LCOV_EXCL_START
                mdebug2(FIM_DELETE_DB, FIM_DB_DISK_PATH);
#ifdef WIN32
                Sleep(60000); //milliseconds
#else
                sleep(60); //seconds
#endif
                // LCOV_EXCL_STOP
            }
        }
    }

}


int fim_db_cache(fdb_t *fim_sql) {
    int index;
    int retval = FIMDB_ERR;

    for (index = 0; index < FIMDB_STMT_SIZE; index++) {
        if (sqlite3_prepare_v2(fim_sql->db, SQL_STMT[index], -1,
            &fim_sql->stmt[index], NULL) != SQLITE_OK) {
            merror("Error preparing statement '%s': %s", SQL_STMT[index], sqlite3_errmsg(fim_sql->db));
            goto end;
        }
    }

    retval = FIMDB_OK;
end:
    return retval;
}

int fim_db_create_file(const char *path, const char *source, const int storage, sqlite3 **fim_db) {
    const char *sql;
    const char *tail;

    sqlite3 *db;
    sqlite3_stmt *stmt;
    int result;

    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
        merror("Couldn't create SQLite database '%s': %s", path, sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        return -1;
    }

    for (sql = source; sql && *sql; sql = tail) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, &tail) != SQLITE_OK) {
            merror("Error preparing statement '%s': %s", sql, sqlite3_errmsg(db));
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
            merror("Error stepping statement '%s': %s", sql, sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            sqlite3_close_v2(db);
            return -1;
        }

        sqlite3_finalize(stmt);
    }

    if (storage == FIM_DB_MEMORY) {
        *fim_db = db;
        return 0;
    }

    sqlite3_close_v2(db);

    if (chmod(path, 0660) < 0) {
        merror(CHMOD_ERROR, path, errno, strerror(errno));
        return -1;
    }

    return 0;
}

fim_tmp_file *fim_db_create_temp_file(int storage) {
    fim_tmp_file *file;
    os_calloc(1, sizeof(fim_tmp_file), file);

    if (storage == FIM_DB_DISK) {
        os_calloc(PATH_MAX, sizeof(char), file->path);
        //Create random name unique to this thread
        sprintf(file->path, "%stmp_%lu%d%u", FIM_DB_TMPDIR,
                    (unsigned long)time(NULL),
                    getpid(),
                    os_random());

        file->fd = fopen(file->path, "w+");
        if (file->fd == NULL) {
            merror("Failed to create temporal storage '%s': %s (%d)", file->path, strerror(errno), errno);
            os_free(file->path);
            os_free(file);
            return NULL;
        }
    } else {
        file->list = W_Vector_init(100);
    }

    return file;
}

void fim_db_clean_file(fim_tmp_file **file, int storage) {
    if (storage == FIM_DB_DISK) {
        fclose((*file)->fd);
        if (remove((*file)->path) < 0) {
            merror("Failed to remove '%s': %s (%d)", (*file)->path, strerror(errno), errno);
        }
        os_free((*file)->path);
    } else {
        W_Vector_free((*file)->list);
    }

    os_free((*file));
}

int fim_db_finalize_stmt(fdb_t *fim_sql) {
    int index;
    int retval = FIMDB_ERR;

    for (index = 0; index < FIMDB_STMT_SIZE; index++) {
        fim_db_clean_stmt(fim_sql, index);
        if (sqlite3_finalize(fim_sql->stmt[index]) != SQLITE_OK) {
            merror("Error finalizing statement '%s': %s", SQL_STMT[index], sqlite3_errmsg(fim_sql->db));
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
            merror("Error preparing statement '%s': %s", SQL_STMT[index], sqlite3_errmsg(fim_sql->db));
            return FIMDB_ERR;
        }
    }

    return FIMDB_OK;
}


//wrappers

int fim_db_get_path_range(fdb_t *fim_sql, char *start, char *top, fim_tmp_file **file, int storage) {
    if ((*file = fim_db_create_temp_file(storage)) == NULL) {
        return FIMDB_ERR;
    }

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH_RANGE);
    fim_db_bind_range(fim_sql, FIMDB_STMT_GET_PATH_RANGE, start, top);

    int ret = fim_db_process_get_query(fim_sql, FIMDB_STMT_GET_PATH_RANGE, fim_db_callback_save_path, storage, (void*) *file);

    if (*file && (*file)->elements == 0) {
        fim_db_clean_file(file, storage);
    }

    return ret;
}

int fim_db_get_not_scanned(fdb_t * fim_sql, fim_tmp_file **file, int storage) {
    if ((*file = fim_db_create_temp_file(storage)) == NULL) {
        return FIMDB_ERR;
    }

    int ret = fim_db_process_get_query(fim_sql, FIMDB_STMT_GET_NOT_SCANNED, fim_db_callback_save_path, storage, (void*) *file);

    if (*file && (*file)->elements == 0) {
        fim_db_clean_file(file, storage);
    }

    return ret;

}

int fim_db_get_data_checksum(fdb_t *fim_sql, void * arg) {
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_ALL_ENTRIES);
    return fim_db_process_get_query(fim_sql, FIMDB_STMT_GET_ALL_ENTRIES, fim_db_callback_calculate_checksum, 0, arg);
}

int fim_db_process_get_query(fdb_t *fim_sql, int index, void (*callback)(fdb_t *, fim_entry *, int , void *), int storage, void * arg) {
    int result;
    int i;
    for (i = 0; result = sqlite3_step(fim_sql->stmt[index]), result == SQLITE_ROW; i++) {
        fim_entry *entry = fim_db_decode_full_row(fim_sql->stmt[index]);
        callback(fim_sql, entry, storage, arg);
        free_entry(entry);
    }

    fim_db_check_transaction(fim_sql);

    return result != SQLITE_DONE ? FIMDB_ERR : FIMDB_OK;
}

int fim_db_exec_simple_wquery(fdb_t *fim_sql, const char *query) {
    char *error = NULL;

    sqlite3_exec(fim_sql->db, query, NULL, NULL, &error);

    if (error) {
        merror("Error executing simple query '%s': %s", query, error);
        sqlite3_free(error);
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

int fim_db_sync_path_range(fdb_t * fim_sql, pthread_mutex_t *mutex, fim_tmp_file *file, int storage) {
    return fim_db_process_read_file(fim_sql, file, mutex, fim_db_callback_sync_path_range, storage,
                                    NULL, NULL, NULL);
}

int fim_db_delete_not_scanned(fdb_t * fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage) {
    return fim_db_process_read_file(fim_sql, file, mutex, fim_db_remove_path, storage,
                                    (void *) true, (void *) FIM_SCHEDULED, NULL);
}

int fim_db_delete_range(fdb_t * fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage) {
    return fim_db_process_read_file(fim_sql, file, mutex, fim_db_remove_path, storage,
                                    (void *) false, (void *) FIM_SCHEDULED, NULL);
}

int fim_db_process_missing_entry(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage, fim_event_mode mode, whodata_evt * w_evt) {
    return fim_db_process_read_file(fim_sql, file, mutex, fim_db_remove_path, storage,
                                    (void *) true, (void *) (fim_event_mode) mode, (void *) w_evt);
}

int fim_db_process_read_file(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex,
    void (*callback)(fdb_t *, fim_entry *, pthread_mutex_t *, void *, void *, void *),
    int storage, void * alert, void * mode, void * w_evt) {

    char line[PATH_MAX + 1];
    char *path = NULL;
    int i = 0;

    if (storage == FIM_DB_DISK) {
        fseek(file->fd, SEEK_SET, 0);
    }

    do {

        if (storage == FIM_DB_DISK) {
            /* fgets() adds \n(newline) to the end of the string,
             So it must be removed. */
            if (fgets(line, sizeof(line), file->fd)) {
                size_t len = strlen(line);

                if (len > 2 && line[len - 1] == '\n') {
                    line[len - 1] = '\0';
                } else {
                    merror("Temporary path file '%s' is corrupt: missing line end.", file->path);
                    continue;
                }

                path = wstr_unescape_json(line);
            }
        } else {
            path = wstr_unescape_json((char *) W_Vector_get(file->list, i));
        }

        if (path) {
            w_mutex_lock(mutex);
            fim_entry *entry = fim_db_get_path(fim_sql, path);
            w_mutex_unlock(mutex);
            if (entry != NULL) {
                callback(fim_sql, entry, mutex, alert, mode, w_evt);
                free_entry(entry);
            }
            os_free(path);
        }

        i++;
    } while (i < file->elements);

    fim_db_clean_file(&file, storage);

    return FIMDB_OK;
}

fim_entry *fim_db_decode_full_row(sqlite3_stmt *stmt) {
    fim_entry *entry = NULL;

    os_calloc(1, sizeof(fim_entry), entry);
    os_strdup((char *)sqlite3_column_text(stmt, 0), entry->path);

    os_calloc(1, sizeof(fim_entry_data), entry->data);
    entry->data->mode = (unsigned int)sqlite3_column_int(stmt, 2);
    entry->data->last_event = (time_t)sqlite3_column_int(stmt, 3);
    entry->data->entry_type = sqlite3_column_int(stmt, 4);
    entry->data->scanned = (time_t)sqlite3_column_int(stmt, 5);
    entry->data->options = (time_t)sqlite3_column_int(stmt, 6);
    strncpy(entry->data->checksum, (char *)sqlite3_column_text(stmt, 7), sizeof(os_sha1) - 1);
    entry->data->dev = (unsigned long int)sqlite3_column_int(stmt, 8);
    entry->data->inode = (unsigned long int)sqlite3_column_int64(stmt, 9);
    entry->data->size = (unsigned int)sqlite3_column_int(stmt, 10);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 11), entry->data->perm);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 12), entry->data->attributes);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 13), entry->data->uid);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 14), entry->data->gid);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 15), entry->data->user_name);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 16), entry->data->group_name);
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
#ifndef WIN32
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 1, entry->dev);
    sqlite3_bind_int64(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 2, entry->inode);
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
#else
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 1, entry->size);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 2, entry->perm, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 3, entry->attributes, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 4, entry->uid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 5, entry->gid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 6, entry->user_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 7, entry->group_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 8, entry->hash_md5, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 9, entry->hash_sha1, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 10, entry->hash_sha256, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_INSERT_DATA], 11, entry->mtime);
#endif
}

/* FIMDB_STMT_REPLACE_PATH */
void fim_db_bind_replace_path(fdb_t *fim_sql, const char *file_path, int row_id, fim_entry_data *entry) {
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 1, file_path, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 2, row_id);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 3, entry->mode);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 4, entry->last_event);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 5, entry->entry_type);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 6, entry->scanned);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 7, entry->options);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 8, entry->checksum, -1, NULL);
}

/* FIMDB_STMT_GET_PATH, FIMDB_STMT_GET_PATH_COUNT, FIMDB_STMT_DELETE_PATH, FIMDB_STMT_GET_DATA_ROW */
void fim_db_bind_path(fdb_t *fim_sql, int index, const char *file_path) {
    if (index == FIMDB_STMT_GET_PATH || index == FIMDB_STMT_GET_PATH_COUNT
       || index == FIMDB_STMT_DELETE_PATH || index == FIMDB_STMT_GET_DATA_ROW) {
        sqlite3_bind_text(fim_sql->stmt[index], 1, file_path, -1, NULL);
    }
}

/* FIMDB_STMT_GET_PATHS_INODE, FIMDB_STMT_GET_PATHS_INODE_COUNT, FIMDB_STMT_GET_DATA_ROW */
void fim_db_bind_get_inode(fdb_t *fim_sql, int index, const unsigned long int inode, const unsigned long int dev) {
    if (index == FIMDB_STMT_GET_PATHS_INODE || index == FIMDB_STMT_GET_PATHS_INODE_COUNT
        || index == FIMDB_STMT_GET_DATA_ROW) {
        sqlite3_bind_int64(fim_sql->stmt[index], 1, inode);
        sqlite3_bind_int(fim_sql->stmt[index], 2, dev);
    }
}

/* FIMDB_STMT_UPDATE_ENTRY_DATA */
void fim_db_bind_update_data(fdb_t *fim_sql, fim_entry_data *entry, int *row_id) {
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
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA], 12, *row_id);
}

/* FIMDB_STMT_DELETE_DATA */
void fim_db_bind_delete_data_id(fdb_t *fim_sql, int row) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_DELETE_DATA], 1, row);
}

/* FIMDB_STMT_SET_SCANNED */
void fim_db_bind_set_scanned(fdb_t *fim_sql, const char *file_path) {
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_SET_SCANNED], 1, file_path, -1, NULL);
}

/* FIMDB_STMT_GET_INODE_ID */
void fim_db_bind_get_inode_id(fdb_t *fim_sql, const char *file_path) {
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_GET_INODE_ID], 1, file_path, -1, NULL);
}

/* FIMDB_STMT_GET_INODE */
void fim_db_bind_get_path_inode(fdb_t *fim_sql, const char *file_path) {
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_GET_INODE], 1, file_path, -1, NULL);
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
                minfo("The count returned is smaller than the actual elements. This shouldn't happen.");
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
        merror("Step error getting count range 'start %s' 'top %s': %s", start, top,  sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    *count = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_COUNT_RANGE], 0);

    return FIMDB_OK;
}

int fim_db_insert_data(fdb_t *fim_sql, fim_entry_data *entry, int *row_id) {
    int res;

    if(*row_id == 0) {
        fim_db_clean_stmt(fim_sql, FIMDB_STMT_INSERT_DATA);

        fim_db_bind_insert_data(fim_sql, entry);

        if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_INSERT_DATA]), res != SQLITE_DONE) {
            merror("Step error inserting data row_id '%d': %s", *row_id, sqlite3_errmsg(fim_sql->db));
            return FIMDB_ERR;
        }

        *row_id = sqlite3_last_insert_rowid(fim_sql->db);
    } else {
        // Update entry_data
        fim_db_clean_stmt(fim_sql, FIMDB_STMT_UPDATE_DATA);
        fim_db_bind_update_data(fim_sql, entry, row_id);

        if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA]), res != SQLITE_DONE) {
            merror("Step error updating data row_id '%d': %s", *row_id, sqlite3_errmsg(fim_sql->db));
            return FIMDB_ERR;
        }
    }

    return FIMDB_OK;
}

int fim_db_insert_path(fdb_t *fim_sql, const char *file_path, fim_entry_data *entry, int inode_id) {
    int res;

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_REPLACE_PATH);
    fim_db_bind_replace_path(fim_sql, file_path, inode_id, entry);

    if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH]), res != SQLITE_DONE) {
            merror("Step error replacing path '%s': %s", file_path, sqlite3_errmsg(fim_sql->db));
            return FIMDB_ERR;
    }

    return FIMDB_OK;
}

int fim_db_insert(fdb_t *fim_sql, const char *file_path, fim_entry_data *new, fim_entry_data *saved) {
    int inode_id;
    int res, res_data, res_path;
    unsigned int nodes_count;

    // Add event
    if (!saved) {
        if (syscheck.file_limit_enabled) {
            nodes_count = fim_db_get_count_entry_path(fim_sql);
            if (nodes_count >= syscheck.file_limit) {
                fim_sql->full = true;
                mdebug1("Couldn't insert '%s' entry into DB. The DB is full, please check your configuration.", file_path);
                return FIMDB_FULL;
            }
        }
    }
    // Modified event
#ifndef WIN32
    else if (new->inode != saved->inode) {
        fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH_COUNT);
        fim_db_bind_path(fim_sql, FIMDB_STMT_GET_PATH_COUNT, file_path);

        sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATH_COUNT]);

        res = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_PATH_COUNT], 0);
        inode_id = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_PATH_COUNT], 1);
        if (res == 1) {
            // The inode has only one entry, delete the entry data.
            fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_DATA);
            fim_db_bind_delete_data_id(fim_sql, inode_id);

            if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_DELETE_DATA]) != SQLITE_DONE) {
                merror("Step error deleting data: %s", sqlite3_errmsg(fim_sql->db));
                return FIMDB_ERR;
            }
            fim_db_force_commit(fim_sql);
        }
    }

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_DATA_ROW);
    fim_db_bind_get_inode(fim_sql, FIMDB_STMT_GET_DATA_ROW, new->inode, new->dev);
#else
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_DATA_ROW);
    fim_db_bind_path(fim_sql, FIMDB_STMT_GET_DATA_ROW, file_path);
#endif

    res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_DATA_ROW]);

    switch(res) {
    case SQLITE_ROW:
        inode_id = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_DATA_ROW], 0);
    break;

    case SQLITE_DONE:
        inode_id = 0;
    break;

    default:
        merror("Step error getting data row: %s", sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    res_data = fim_db_insert_data(fim_sql, new, &inode_id);
    res_path = fim_db_insert_path(fim_sql, file_path, new, inode_id);

    fim_db_check_transaction(fim_sql);

    return res_data || res_path;
}

void fim_db_callback_calculate_checksum(__attribute__((unused)) fdb_t *fim_sql, fim_entry *entry,
    __attribute__((unused))int storage, void *arg) {

    EVP_MD_CTX *ctx = (EVP_MD_CTX *)arg;
    EVP_DigestUpdate(ctx, entry->data->checksum, strlen(entry->data->checksum));
}

int fim_db_data_checksum_range(fdb_t *fim_sql, const char *start, const char *top,
                                const long id, const int n, pthread_mutex_t *mutex) {
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

    EVP_MD_CTX *ctx_left = EVP_MD_CTX_create();
    EVP_MD_CTX *ctx_right = EVP_MD_CTX_create();

    EVP_DigestInit(ctx_left, EVP_sha1());
    EVP_DigestInit(ctx_right, EVP_sha1());

    w_mutex_lock(mutex);

    // Clean statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH_RANGE);

    fim_db_bind_range(fim_sql, FIMDB_STMT_GET_PATH_RANGE, start, top);

    // Calculate checksum of the first half
    for (i = 0; i < m; i++) {
        if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATH_RANGE]) != SQLITE_ROW) {
            merror("Step error getting path range, first half 'start %s' 'top %s' (i:%d): %s", start, top, i, sqlite3_errmsg(fim_sql->db));
            w_mutex_unlock(mutex);
            goto end;
        }
        entry = fim_db_decode_full_row(fim_sql->stmt[FIMDB_STMT_GET_PATH_RANGE]);
        if (i == (m - 1) && entry->path) {
            os_strdup(entry->path, str_pathlh);
        }
        //Type of storage not required
        fim_db_callback_calculate_checksum(fim_sql, entry, FIM_DB_DISK, (void *)ctx_left);
        free_entry(entry);
    }

    //Calculate checksum of the second half
    for (i = m; i < n; i++) {
        if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATH_RANGE]) != SQLITE_ROW) {
            merror("Step error getting path range, second half 'start %s' 'top %s' (i:%d): %s", start, top, i, sqlite3_errmsg(fim_sql->db));
            w_mutex_unlock(mutex);
            goto end;
        }
        entry = fim_db_decode_full_row(fim_sql->stmt[FIMDB_STMT_GET_PATH_RANGE]);
        if (i == m && entry->path) {
            os_free(str_pathuh);
            os_strdup(entry->path, str_pathuh);
        }
        //Type of storage not required
        fim_db_callback_calculate_checksum(fim_sql, entry, FIM_DB_DISK, (void *)ctx_right);
        free_entry(entry);
    }

    w_mutex_unlock(mutex);

    if (!str_pathlh || !str_pathuh) {
        merror("Failed to obtain required paths in order to form message");
        goto end;
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
    os_free(str_pathuh);

    retval = FIMDB_OK;

end:
    EVP_MD_CTX_destroy(ctx_left);
    EVP_MD_CTX_destroy(ctx_right);
    os_free(str_pathlh);
    os_free(str_pathuh);
    return retval;
}

void fim_db_remove_path(fdb_t *fim_sql, fim_entry *entry, pthread_mutex_t *mutex,
     __attribute__((unused))void *alert,
     __attribute__((unused))void *fim_ev_mode,
     __attribute__((unused))void *w_evt) {

    int *send_alert = (int *) alert;
    fim_event_mode mode = (fim_event_mode) fim_ev_mode;
    int rows = 0;
    int conf;

    if(entry->data->entry_type == FIM_TYPE_FILE) {

        conf = fim_configuration_directory(entry->path, "file");

        if(conf > -1) {
            switch (mode) {
            /* Don't send alert if received mode and mode in configuration aren't the same */
            case FIM_REALTIME:
                if (!(syscheck.opts[conf] & REALTIME_ACTIVE)) {
                    return;     // LCOV_EXCL_LINE
                }
                break;

            case FIM_WHODATA:
                if (!(syscheck.opts[conf] & WHODATA_ACTIVE)) {
                    return;     // LCOV_EXCL_LINE
                }
                break;

            case FIM_SCHEDULED:
                if (!(syscheck.opts[conf] & SCHEDULED_ACTIVE)) {
                    return;     // LCOV_EXCL_LINE
                }
                break;

            }
        } else {
            mdebug2(FIM_DELETE_EVENT_PATH_NOCONF, entry->path);
            return;
        }
    }

    w_mutex_lock(mutex);

    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH_COUNT);
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_DATA);
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_PATH);
    fim_db_bind_path(fim_sql, FIMDB_STMT_GET_PATH_COUNT, entry->path);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATH_COUNT]) == SQLITE_ROW) {
        rows = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_PATH_COUNT], 0);
        int rowid = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_PATH_COUNT], 1);

        switch (rows) {
        case 0:
            // No entries with this path.
            break;
        case 1:
            // The inode has only one entry, delete the entry data.
            fim_db_bind_delete_data_id(fim_sql, rowid);
            if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_DELETE_DATA]) != SQLITE_DONE) {
                w_mutex_unlock(mutex);
                goto end;
            }
            //Fallthrough
        default:
            // The inode has more entries, delete only this path.
            fim_db_bind_path(fim_sql, FIMDB_STMT_DELETE_PATH, entry->path);
            if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_DELETE_PATH]) != SQLITE_DONE) {
                w_mutex_unlock(mutex);
                goto end;
            }

            fim_sql->full = false;
            break;
        }
    }

    w_mutex_unlock(mutex);


    if (send_alert && rows >= 1) {
        whodata_evt *whodata_event = (whodata_evt *) w_evt;
        cJSON * json_event      = NULL;
        char * json_formatted    = NULL;
        int pos = 0;
        const char *FIM_ENTRY_TYPE[] = {"file", "registry"};

        // Obtaining the position of the directory, in @syscheck.dir, where @entry belongs
        if (pos = fim_configuration_directory(entry->path,
            FIM_ENTRY_TYPE[entry->data->entry_type]), pos < 0) {
            goto end;
        }

        json_event = fim_json_event(entry->path, NULL, entry->data, pos, FIM_DELETE, mode, whodata_event, NULL);

        if (!strcmp(FIM_ENTRY_TYPE[entry->data->entry_type], "file") && syscheck.opts[pos] & CHECK_SEECHANGES) {
            if (syscheck.disk_quota_enabled) {
                char *full_path;
                full_path = seechanges_get_diff_path(entry->path);

                if (full_path != NULL && IsDir(full_path) == 0) {
                    syscheck.diff_folder_size -= (DirSize(full_path) / 1024);   // Update diff_folder_size

                    if (!syscheck.disk_quota_full_msg) {
                        syscheck.disk_quota_full_msg = true;
                    }
                }

                os_free(full_path);
            }

            delete_target_file(entry->path);
        }

        if (json_event) {
            mdebug2(FIM_FILE_MSG_DELETE, entry->path);
            json_formatted = cJSON_PrintUnformatted(json_event);
            send_syscheck_msg(json_formatted);

            os_free(json_formatted);
            cJSON_Delete(json_event);
        }
    }

end:
    w_mutex_lock(mutex);
    fim_db_check_transaction(fim_sql);
    w_mutex_unlock(mutex);
}

int fim_db_get_row_path(fdb_t * fim_sql, int mode, char **path) {
    int index = (mode)? FIMDB_STMT_GET_FIRST_PATH : FIMDB_STMT_GET_LAST_PATH;
    int result;

    fim_db_clean_stmt(fim_sql, index);

    if (result = sqlite3_step(fim_sql->stmt[index]), result != SQLITE_ROW && result != SQLITE_DONE) {
        merror("Step error getting row path '%s': %s", *path, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    if (result == SQLITE_ROW) {
        os_strdup((char *)sqlite3_column_text(fim_sql->stmt[index], 0), *path);
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
        merror("Step error setting scanned path '%s': %s", path, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    fim_db_check_transaction(fim_sql);

    return FIMDB_OK;
}

void fim_db_callback_save_path(__attribute__((unused))fdb_t * fim_sql, fim_entry *entry, int storage, void *arg) {
    char *base = wstr_escape_json(entry->path);
    if (base == NULL) {
        merror("Error escaping '%s'", entry->path);
        return;
    }

    if (storage == FIM_DB_DISK) { // disk storage enabled
        if ((size_t)fprintf(((fim_tmp_file *) arg)->fd, "%s\n", base) != (strlen(base) + sizeof(char))) {
            merror("%s - %s", entry->path, strerror(errno));
            goto end;
        }

        fflush(((fim_tmp_file *) arg)->fd);

    } else { // memory storage enabled
        W_Vector_insert(((fim_tmp_file *) arg)->list, base);
    }

    ((fim_tmp_file *) arg)->elements++;

end:
    os_free(base);
}

void fim_db_callback_sync_path_range(__attribute__((unused))fdb_t *fim_sql, fim_entry *entry,
    __attribute__((unused))pthread_mutex_t *mutex, __attribute__((unused))void *alert,
    __attribute__((unused))void *mode, __attribute__((unused))void *w_event) {

    cJSON * entry_data = fim_entry_json(entry->path, entry->data);
    char * plain = dbsync_state_msg("syscheck", entry_data);
    mdebug1("Sync Message for %s sent: %s", entry->path, plain);
    fim_send_sync_msg(plain);
    os_free(plain);
}

int fim_db_get_count_entry_data(fdb_t * fim_sql) {
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_COUNT_DATA);
    int res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_COUNT_DATA]);

    if(res == SQLITE_ROW) {
        return sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_COUNT_DATA], 0);
    }
    else {
        merror("Step error getting count entry data: %s", sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }
}

int fim_db_get_count_entry_path(fdb_t * fim_sql) {
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_COUNT_PATH);
    int res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_COUNT_PATH]);

    if(res == SQLITE_ROW) {
        return sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_COUNT_PATH], 0);
    }
    else {
        merror("Step error getting count entry path: %s", sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }
}
