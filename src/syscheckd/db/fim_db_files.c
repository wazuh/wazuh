/**
 * @file fim_db_files.c
 * @brief Definition of FIM database for files library.
 * @date 2020-09-9
 *
 * @copyright Copyright (c) 2020 Wazuh, Inc.
 */

#include "fim_db_files.h"

extern const char *SQL_STMT[];

// bindings
/**
 * @brief Binds data into a insert data statement.
 *
 * @param fim_sql FIM database structure.
 * @param entry FIM entry data structure.
 */
static void fim_db_bind_insert_data(fdb_t *fim_sql, fim_file_data *entry);


/**
 * @brief Binds a range of paths.
 *
 * @param fim_sql FIM database structure.
 * @param file_path File name of the file to insert.
 * @param row_id Row id to be bound.
 * @param entry FIM entry data structure.
 */
static void fim_db_bind_replace_path(fdb_t *fim_sql, const char *file_path,
                                    int row_id, fim_file_data *entry);


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
                                  unsigned long int inode,
                                  unsigned long int dev);


/**
 * @brief Binds data into an update entry data statement.
 *
 * @param fim_sql FIM database structure.
 * @param entry FIM entry data structure.
 * @param row_id Row id in file_data table.
 */
static void fim_db_bind_update_data(fdb_t *fim_sql,
                                    fim_file_data *entry,
                                    int *row_id);

/**
 * @brief Binds data into a delete data id statement.
 *
 * @param fim_sql FIM database structure.
 * @param row The especific row.
 */
static void fim_db_bind_delete_data_id(fdb_t *fim_sql, int row);

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

int fim_db_get_not_scanned(fdb_t * fim_sql, fim_tmp_file **file, int storage) {
    if ((*file = fim_db_create_temp_file(storage)) == NULL) {
        return FIMDB_ERR;
    }

    int ret = fim_db_process_get_query(fim_sql, FIM_TYPE_FILE, FIMDB_STMT_GET_NOT_SCANNED,
                                       fim_db_callback_save_path, storage, (void*) *file);

    if (*file && (*file)->elements == 0) {
        fim_db_clean_file(file, storage);
    }

    return ret;

}

// LCOV_EXCL_START
int fim_db_delete_not_scanned(fdb_t * fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage) {
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_FILE, mutex, fim_db_remove_path, storage,
                                    (void *) true, (void *) FIM_SCHEDULED, NULL);
}

int fim_db_delete_range(fdb_t * fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage, fim_event_mode mode) {
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_FILE, mutex, fim_db_remove_path, storage,
                                    (void *) false, (void *) mode, NULL);
}

int fim_db_process_missing_entry(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage,
                                 fim_event_mode mode, whodata_evt * w_evt) {
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_FILE, mutex, fim_db_remove_path, storage,
                                    (void *) true, (void *) (fim_event_mode) mode, (void *) w_evt);
}
// LCOV_EXCL_STOP

fim_entry *fim_db_decode_full_row(sqlite3_stmt *stmt) {

    fim_entry *entry = NULL;

    os_calloc(1, sizeof(fim_entry), entry);
    entry->type = FIM_TYPE_FILE;
    os_strdup((char *)sqlite3_column_text(stmt, 0), entry->file_entry.path);

    os_calloc(1, sizeof(fim_file_data), entry->file_entry.data);
    entry->file_entry.data->mode = (unsigned int)sqlite3_column_int(stmt, 2);
    entry->file_entry.data->last_event = (time_t)sqlite3_column_int(stmt, 3);
    entry->file_entry.data->scanned = (time_t)sqlite3_column_int(stmt, 4);
    entry->file_entry.data->options = (time_t)sqlite3_column_int(stmt, 5);
    strncpy(entry->file_entry.data->checksum, (char *)sqlite3_column_text(stmt, 6), sizeof(os_sha1) - 1);
    entry->file_entry.data->dev = (unsigned long int)sqlite3_column_int(stmt, 7);
    entry->file_entry.data->inode = (unsigned long int)sqlite3_column_int64(stmt, 8);
    entry->file_entry.data->size = (unsigned int)sqlite3_column_int(stmt, 9);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 10), entry->file_entry.data->perm);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 11), entry->file_entry.data->attributes);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 12), entry->file_entry.data->uid);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 13), entry->file_entry.data->gid);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 14), entry->file_entry.data->user_name);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 15), entry->file_entry.data->group_name);
    strncpy(entry->file_entry.data->hash_md5, (char *)sqlite3_column_text(stmt, 16), sizeof(os_md5) - 1);
    strncpy(entry->file_entry.data->hash_sha1, (char *)sqlite3_column_text(stmt, 17), sizeof(os_sha1) - 1);
    strncpy(entry->file_entry.data->hash_sha256, (char *)sqlite3_column_text(stmt, 18), sizeof(os_sha256) - 1);
    entry->file_entry.data->mtime = (unsigned int)sqlite3_column_int(stmt, 19);

    return entry;
}

/* No needed bind FIMDB_STMT_GET_LAST_ROWID, FIMDB_STMT_GET_NOT_SCANNED,
   FIMDB_STMT_SET_ALL_UNSCANNED, FIMDB_STMT_DELETE_UNSCANNED */

/* FIMDB_STMT_INSERT_DATA */
void fim_db_bind_insert_data(fdb_t *fim_sql, fim_file_data *entry) {
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
void fim_db_bind_replace_path(fdb_t *fim_sql, const char *file_path, int row_id, fim_file_data *entry) {
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 1, file_path, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 2, row_id);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 3, entry->mode);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 4, entry->last_event);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 5, entry->scanned);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 6, entry->options);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH], 7, entry->checksum, -1, NULL);
}

/* FIMDB_STMT_GET_PATH, FIMDB_STMT_GET_PATH_COUNT, FIMDB_STMT_DELETE_PATH, FIMDB_STMT_GET_DATA_ROW */
void fim_db_bind_path(fdb_t *fim_sql, int index, const char *file_path) {
    if (index == FIMDB_STMT_GET_PATH || index == FIMDB_STMT_GET_PATH_COUNT
       || index == FIMDB_STMT_DELETE_PATH || index == FIMDB_STMT_GET_DATA_ROW) {
        sqlite3_bind_text(fim_sql->stmt[index], 1, file_path, -1, NULL);
    }
}

/* FIMDB_STMT_GET_PATHS_INODE, FIMDB_STMT_GET_PATHS_INODE_COUNT, FIMDB_STMT_GET_DATA_ROW */
void fim_db_bind_get_inode(fdb_t *fim_sql, int index, unsigned long int inode, unsigned long int dev) {
    if (index == FIMDB_STMT_GET_PATHS_INODE || index == FIMDB_STMT_GET_PATHS_INODE_COUNT
        || index == FIMDB_STMT_GET_DATA_ROW) {
        sqlite3_bind_int64(fim_sql->stmt[index], 1, inode);
        sqlite3_bind_int(fim_sql->stmt[index], 2, dev);
    }
}

/* FIMDB_STMT_UPDATE_file_data */
void fim_db_bind_update_data(fdb_t *fim_sql, fim_file_data *entry, int *row_id) {
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

char **fim_db_get_paths_from_inode(fdb_t *fim_sql, unsigned long int inode, unsigned long int dev) {
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

int fim_db_insert_data(fdb_t *fim_sql, fim_file_data *entry, int *row_id) {
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
        // Update file_data
        fim_db_clean_stmt(fim_sql, FIMDB_STMT_UPDATE_DATA);
        fim_db_bind_update_data(fim_sql, entry, row_id);

        if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_UPDATE_DATA]), res != SQLITE_DONE) {
            merror("Step error updating data row_id '%d': %s", *row_id, sqlite3_errmsg(fim_sql->db));
            return FIMDB_ERR;
        }
    }

    return FIMDB_OK;
}

int fim_db_insert_path(fdb_t *fim_sql, const char *file_path, fim_file_data *entry, int inode_id) {
    int res;

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_REPLACE_PATH);
    fim_db_bind_replace_path(fim_sql, file_path, inode_id, entry);

    if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_REPLACE_PATH]), res != SQLITE_DONE) {
            merror("Step error replacing path '%s': %s", file_path, sqlite3_errmsg(fim_sql->db));
            return FIMDB_ERR;
    }

    return FIMDB_OK;
}

int fim_db_insert(fdb_t *fim_sql, const char *file_path, fim_file_data *new, fim_file_data *saved) {
    int inode_id;
    int res, res_data, res_path;
    unsigned int nodes_count;

    // Add event
    if (!saved) {
        if (syscheck.file_limit_enabled) {
            nodes_count = fim_db_get_count_entries(syscheck.database);
            if (nodes_count >= syscheck.file_limit) {
                fim_sql->full = true;
                mdebug1("Couldn't insert '%s' entry into DB. The DB is full, please check your configuration.",
                        file_path);
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

void fim_db_remove_path(fdb_t *fim_sql, fim_entry *entry, pthread_mutex_t *mutex,
     __attribute__((unused))void *alert,
     __attribute__((unused))void *fim_ev_mode,
     __attribute__((unused))void *w_evt) {

    int *send_alert = (int *) alert;
    fim_event_mode mode = (fim_event_mode) fim_ev_mode;
    int rows = 0;
    int conf;

    if(entry->type == FIM_TYPE_FILE) {

        conf = fim_configuration_directory(entry->file_entry.path, "file");

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
            mdebug2(FIM_DELETE_EVENT_PATH_NOCONF, entry->file_entry.path);
            return;
        }
    }

    w_mutex_lock(mutex);

    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH_COUNT);
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_DATA);
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_PATH);
    fim_db_bind_path(fim_sql, FIMDB_STMT_GET_PATH_COUNT, entry->file_entry.path);

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
            fim_db_bind_path(fim_sql, FIMDB_STMT_DELETE_PATH, entry->file_entry.path);
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
        if (pos = fim_configuration_directory(entry->file_entry.path,
            FIM_ENTRY_TYPE[entry->type]), pos < 0) {
            goto end;
        }

        w_mutex_lock(mutex);
        json_event = fim_json_event(entry->file_entry.path, NULL, entry->file_entry.data, pos, FIM_DELETE, mode,
                                    whodata_event, NULL);
        w_mutex_unlock(mutex);

        if (!strcmp(FIM_ENTRY_TYPE[entry->type], "file") && syscheck.opts[pos] & CHECK_SEECHANGES) {
            fim_diff_process_delete_file(entry->file_entry.path);
        }

        if (json_event) {
            mdebug2(FIM_FILE_MSG_DELETE, entry->file_entry.path);
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

int fim_db_get_count_file_data(fdb_t * fim_sql) {
    int res = fim_db_get_count(fim_sql, FIMDB_STMT_GET_COUNT_DATA);

    if(res == FIMDB_ERR) {
        merror("Step error getting count entry data: %s", sqlite3_errmsg(fim_sql->db));
    }
    return res;
}

int fim_db_get_count_file_entry(fdb_t * fim_sql) {
    int res = fim_db_get_count(fim_sql, FIMDB_STMT_GET_COUNT_PATH);

    if(res == FIMDB_ERR) {
        merror("Step error getting count entry path: %s", sqlite3_errmsg(fim_sql->db));
    }
    return res;
}
