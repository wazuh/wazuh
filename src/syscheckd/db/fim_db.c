/**
 * @file fim_db.h
 * @brief Definition of FIM database library.
 * @date 2019-08-28
 *
 * @copyright Copyright (c) 2020 Wazuh, Inc.
 */

#include "fim_db.h"

#ifdef WAZUH_UNIT_TESTING
#ifdef WIN32
#include "unit_tests/wrappers/windows/synchapi_wrappers.h"
#include "unit_tests/wrappers/windows/libc/stdio_wrappers.h"
#endif
#define static
#endif

const char *SQL_STMT[] = {
// Files
#ifdef WIN32
    [FIMDB_STMT_INSERT_DATA] = "INSERT INTO file_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
#else
    [FIMDB_STMT_INSERT_DATA] = "INSERT INTO file_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
#endif
    [FIMDB_STMT_REPLACE_PATH] = "INSERT OR REPLACE INTO file_entry (path, inode_id, mode, last_event, scanned, options, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
    [FIMDB_STMT_GET_PATH] = "SELECT path, inode_id, mode, last_event, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM file_entry INNER JOIN file_data ON path = ? AND file_data.rowid = file_entry.inode_id;",
    [FIMDB_STMT_UPDATE_DATA] = "UPDATE file_data SET size = ?, perm = ?, attributes = ?, uid = ?, gid = ?, user_name = ?, group_name = ?, hash_md5 = ?, hash_sha1 = ?, hash_sha256 = ?, mtime = ? WHERE rowid = ?;",
    [FIMDB_STMT_UPDATE_PATH] = "UPDATE file_entry SET inode_id = ?, mode = ?, last_event = ? = ?, scanned = ?, options = ?, checksum = ? WHERE path = ?;",
    [FIMDB_STMT_GET_LAST_PATH] = "SELECT path FROM file_entry ORDER BY path DESC LIMIT 1;",
    [FIMDB_STMT_GET_FIRST_PATH] = "SELECT path FROM file_entry ORDER BY path ASC LIMIT 1;",
    [FIMDB_STMT_GET_ALL_ENTRIES] = "SELECT path, inode_id, mode, last_event, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM file_data INNER JOIN file_entry ON inode_id = file_data.rowid ORDER BY PATH ASC;",
    [FIMDB_STMT_GET_NOT_SCANNED] = "SELECT path, inode_id, mode, last_event, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM file_data INNER JOIN file_entry ON inode_id = file_data.rowid WHERE scanned = 0 ORDER BY PATH ASC;",
    [FIMDB_STMT_SET_ALL_UNSCANNED] = "UPDATE file_entry SET scanned = 0;",
    [FIMDB_STMT_GET_PATH_COUNT] = "SELECT count(inode_id), inode_id FROM file_entry WHERE inode_id = (select inode_id from file_entry where path = ?);",
#ifndef WIN32
    [FIMDB_STMT_GET_DATA_ROW] = "SELECT rowid FROM file_data WHERE inode = ? AND dev = ?;",
#else
    [FIMDB_STMT_GET_DATA_ROW] = "SELECT inode_id FROM file_entry WHERE path = ?",
#endif
    [FIMDB_STMT_GET_COUNT_RANGE] = "SELECT count(*) FROM file_entry INNER JOIN file_data ON file_data.rowid = file_entry.inode_id WHERE path BETWEEN ? and ? ORDER BY path;",
    [FIMDB_STMT_GET_PATH_RANGE] = "SELECT path, inode_id, mode, last_event, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM file_entry INNER JOIN file_data ON file_data.rowid = file_entry.inode_id WHERE path BETWEEN ? and ? ORDER BY path;",
    [FIMDB_STMT_DELETE_PATH] = "DELETE FROM file_entry WHERE path = ?;",
    [FIMDB_STMT_DELETE_DATA] = "DELETE FROM file_data WHERE rowid = ?;",
    [FIMDB_STMT_GET_PATHS_INODE] = "SELECT path FROM file_entry INNER JOIN file_data ON file_data.rowid=file_entry.inode_id WHERE file_data.inode=? AND file_data.dev=?;",
    [FIMDB_STMT_GET_PATHS_INODE_COUNT] = "SELECT count(*) FROM file_entry INNER JOIN file_data ON file_data.rowid=file_entry.inode_id WHERE file_data.inode=? AND file_data.dev=?;",
    [FIMDB_STMT_SET_SCANNED] = "UPDATE file_entry SET scanned = 1 WHERE path = ?;",
    [FIMDB_STMT_GET_INODE_ID] = "SELECT inode_id FROM file_entry WHERE path = ?",
    [FIMDB_STMT_GET_COUNT_PATH] = "SELECT count(*) FROM file_entry",
    [FIMDB_STMT_GET_COUNT_DATA] = "SELECT count(*) FROM file_data",
    [FIMDB_STMT_GET_INODE] = "SELECT inode FROM file_data where rowid=(SELECT inode_id FROM file_entry WHERE path = ?)",
#ifdef WIN32
    [FIMDB_STMT_REPLACE_REG_DATA] = "INSERT OR REPLACE INTO registry_data (key_id, name, type, size, hash_md5, hash_sha1, hash_sha256, scanned, last_event, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [FIMDB_STMT_REPLACE_REG_KEY] = "INSERT OR REPLACE INTO registry_key (id, path, perm, uid, gid, user_name, group_name, mtime, arch, scanned, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [FIMDB_STMT_GET_REG_KEY] = "SELECT id, path, perm, uid, gid, user_name, group_name, mtime, arch, scanned, checksum FROM registry_key WHERE path = ?;",
    [FIMDB_STMT_GET_REG_DATA] = "SELECT key_id, name, type, size, hash_md5, hash_sha1, hash_sha256, scanned, last_event, checksum FROM registry_data WHERE name = ? AND key_id = ?;",
    [FIMDB_STMT_UPDATE_REG_DATA] = "UPDATE registry_data SET type = ?, size = ?, hash_md5 = ?, hash_sha1 = ?, hash_sha256 = ?, scanned = ?, last_event = ?, checksum = ? WHERE key_id = ? AND name = ?;",
    [FIMDB_STMT_UPDATE_REG_KEY] = "UPDATE registry_key SET perm = ?, uid = ?, gid = ?, user_name = ?, group_name = ?, mtime = ?, arch = ?, scanned = ?, checksum = ? WHERE path = ?;",
    [FIMDB_STMT_GET_ALL_REG_ENTRIES] = "SELECT id, path, perm, uid, gid, user_name, group_name, mtime, arch, registry_key.scanned, registry_key.checksum, key_id, name, type, size, hash_md5, hash_sha1, hash_sha256, registry_data.scanned, last_event, registry_data.checksum FROM registry_data INNER JOIN registry_key ON registry_key.id = registry_data.key_id ORDER BY PATH ASC;",
    [FIMDB_STMT_GET_REG_KEY_NOT_SCANNED] = "SELECT id, path, perm, uid, gid, user_name, group_name, mtime, arch, scanned, checksum FROM registry_key WHERE scanned = 0;",
    [FIMDB_STMT_GET_REG_DATA_NOT_SCANNED] = "SELECT key_id, name, type, size, hash_md5, hash_sha1, hash_sha256, scanned, last_event, checksum FROM registry_data WHERE scanned = 0;",
    [FIMDB_STMT_SET_ALL_REG_KEY_UNSCANNED] = "UPDATE registry_key SET scanned = 0;",
    [FIMDB_STMT_SET_REG_KEY_UNSCANNED] = "UPDATE registry_key SET scanned = 0 WHERE path = ?;",
    [FIMDB_STMT_SET_ALL_REG_DATA_UNSCANNED] = "UPDATE registry_data SET scanned = 0;",
    [FIMDB_STMT_SET_REG_DATA_UNSCANNED] = "UPDATE registry_data SET scanned = 0 WHERE name = ? AND key_id = ?;",
    [FIMDB_STMT_GET_REG_ROWID] = "SELECT id FROM registry_key WHERE path = ?;",
    [FIMDB_STMT_DELETE_REG_KEY_PATH] = "DELETE FROM registry_key WHERE path = ?;",
    [FIMDB_STMT_DELETE_REG_DATA] = "DELETE FROM registry_data WHERE name = ? AND key_id = ?;",
    [FIMDB_STMT_DELETE_REG_DATA_PATH] = "DELETE FROM registry_data WHERE key_id = (SELECT id FROM registry_key WHERE path = ?);",
    [FIMDB_STMT_GET_COUNT_REG_KEY] = "SELECT count(*) FROM registry_key;",
    [FIMDB_STMT_GET_COUNT_REG_DATA] = "SELECT count(*) FROM registry_data;",
    [FIMDB_STMT_GET_COUNT_REG_KEY_AND_DATA] = "SELECT count(*) FROM registry_key INNER JOIN registry_data WHERE registry_data.key_id = registry_key.id;",
    [FIMDB_STMT_GET_LAST_REG_KEY] = "SELECT path FROM registry_key ORDER BY path DESC LIMIT 1;",
    [FIMDB_STMT_GET_FIRST_REG_KEY] = "SELECT path FROM registry_key ORDER BY path ASC LIMIT 1;",
    [FIMDB_STMT_GET_REG_COUNT_RANGE] = "SELECT count(*) FROM registry_key INNER JOIN registry_data ON registry_data.key_id = registry_key.id WHERE path BETWEEN ? and ? ORDER BY path;",
    [FIMDB_STMT_GET_REG_PATH_RANGE] = "SELECT id, path, perm, uid, gid, user_name, group_name, mtime, arch, registry_key.scanned, registry_key.checksum, key_id, name, type, size, hash_md5, hash_sha1, hash_sha256, registry_data.scanned, last_event, registry_data.checksum FROM registry_key INNER JOIN registry_data ON registry_data.key_id = registry_key.id WHERE path BETWEEN ? and ? ORDER BY path;",
    [FIMDB_STMT_SET_REG_KEY_SCANNED] = "UPDATE registry_data SET scanned = 1 WHERE name = ? AND key_id = ?;",
    [FIMDB_STMT_SET_REG_DATA_SCANNED] = "UPDATE registry_key SET scanned = 1 WHERE path = ?;",
    [FIMDB_STMT_GET_REG_KEY_ROWID] = "SELECT id, path, perm, uid, gid, user_name, group_name, mtime, arch, scanned, checksum FROM registry_key WHERE id = ?;",
    [FIMDB_STMT_GET_REG_DATA_ROWID] = "SELECT key_id, name, type, size, hash_md5, hash_sha1, hash_sha256, scanned, last_event, checksum FROM registry_data WHERE key_id = ?;",
#endif
};

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

int fim_db_process_get_query(fdb_t *fim_sql, int type, int index,
                             void (*callback)(fdb_t *, fim_entry *, int , void *), int storage, void * arg) {
    int result;
    int i;
    for (i = 0; result = sqlite3_step(fim_sql->stmt[index]), result == SQLITE_ROW; i++) {
        fim_entry *entry = type == FIM_TYPE_REGISTRY ? fim_db_decode_registry(index, fim_sql->stmt[index])
                                                     : fim_db_decode_full_row(fim_sql->stmt[index]);
        callback(fim_sql, entry, storage, arg);
        free_entry(entry);
    }

    fim_db_check_transaction(fim_sql);

    return result != SQLITE_DONE ? FIMDB_ERR : FIMDB_OK;
}

int fim_db_multiple_row_query(fdb_t *fim_sql,
                              int index,
                              void *(*decode)(sqlite3_stmt *),
                              void (*free_row)(void *),
                              void (*callback)(fdb_t *, void *, int, void *),
                              int storage,
                              void *arg) {
    int result;
    int i;

    if (decode == NULL || callback == NULL || free_row == NULL) {
        return FIMDB_ERR;
    }

    for (i = 0; result = sqlite3_step(fim_sql->stmt[index]), result == SQLITE_ROW; i++) {
        void *decoded_row = decode(fim_sql->stmt[index]);
        if (decoded_row != NULL) {
            callback(fim_sql, decoded_row, storage, arg);
            free_row(decoded_row);
        }
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

void fim_db_callback_save_string(__attribute__((unused))fdb_t * fim_sql, char *str, int storage, void *arg) {
    char *base = str;
    if (base == NULL) {
        merror("Error escaping '%s'", str);
        return;
    }

    if (storage == FIM_DB_DISK) { // disk storage enabled
        if ((size_t)fprintf(((fim_tmp_file *) arg)->fd, "%s\n", base) != (strlen(base) + sizeof(char))) {
            merror("%s - %s", str, strerror(errno));
            goto end;
        }

             fflush(((fim_tmp_file *) arg)->fd);

    } else {
        W_Vector_insert(((fim_tmp_file *) arg)->list, base);
    }

    ((fim_tmp_file *) arg)->elements++;

end:
    os_free(base);
}

void fim_db_callback_save_path(__attribute__((unused))fdb_t * fim_sql, fim_entry *entry, int storage, void *arg) {
    char *path = entry->type == FIM_TYPE_FILE ? entry->file_entry.path : entry->registry_entry.key->path;

    char *base = wstr_escape_json(path);
    if (base == NULL) {
        merror("Error escaping '%s'", path);
        return;
    }

    if (storage == FIM_DB_DISK) { // disk storage enabled
        if ((size_t)fprintf(((fim_tmp_file *) arg)->fd, "%s\n", base) != (strlen(base) + sizeof(char))) {
            merror("%s - %s", path, strerror(errno));
            goto end;
        }

        fflush(((fim_tmp_file *) arg)->fd);

    } else {
        W_Vector_insert(((fim_tmp_file *) arg)->list, base);
    }

    ((fim_tmp_file *) arg)->elements++;

end:
    os_free(base);
}

int fim_db_get_count(fdb_t *fim_sql, int index) {

    if (index == FIMDB_STMT_GET_COUNT_REG_KEY || index == FIMDB_STMT_GET_COUNT_REG_DATA ||
        index == FIMDB_STMT_GET_COUNT_PATH    || index == FIMDB_STMT_GET_COUNT_DATA) {
        fim_db_clean_stmt(fim_sql, index);

        if (sqlite3_step(fim_sql->stmt[index]) == SQLITE_ROW) {
            return sqlite3_column_int(fim_sql->stmt[index], 0);
        } else {
            return FIMDB_ERR;
        }
    }
    return FIMDB_ERR;
}

int fim_db_process_read_file(fdb_t *fim_sql, fim_tmp_file *file, int type, pthread_mutex_t *mutex,
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
            // fgets() adds \n(newline) to the end of the string,
            // so it must be removed.
            if (fgets(line, sizeof(line), file->fd)) {
                size_t len = strlen(line);

                if (len > 2 && line[len - 1] == '\n') {
                    line[len - 1] = '\0';
                }
                else {
                    merror("Temporary path file '%s' is corrupt: missing line end.", file->path);
                    continue;
                }

                path = wstr_unescape_json(line);
            }
        }
        else {
            path = wstr_unescape_json((char *) W_Vector_get(file->list, i));
        }

        if (path) {
            w_mutex_lock(mutex);
            fim_entry *entry = type == FIM_TYPE_FILE ? fim_db_get_path(fim_sql, path) :
                                                       fim_db_get_registry_key(fim_sql, path);

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
