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
 * @brief Binds data into a insert data statement.
 *
 * @param fim_sql FIM database structure.
 * @param index Index of the particular statement.
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

int fim_db_get_path_range(fdb_t *fim_sql, char *start, char *top, fim_tmp_file **file, int storage) {
    if ((*file = fim_db_create_temp_file(storage)) == NULL) {
        return FIMDB_ERR;
    }

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH_RANGE);
    fim_db_bind_range(fim_sql, FIMDB_STMT_GET_PATH_RANGE, start, top);

    int ret = fim_db_process_get_query(fim_sql, FIM_TYPE_FILE, FIMDB_STMT_GET_PATH_RANGE,
                                       fim_db_callback_save_path, storage, (void*) *file);

    if (*file && (*file)->elements == 0) {
        fim_db_clean_file(file, storage);
    }

    return ret;
}

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

int fim_db_sync_path_range(fdb_t * fim_sql, pthread_mutex_t *mutex, fim_tmp_file *file, int storage) {
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_FILE, mutex, fim_db_callback_sync_path_range, storage,
                                    NULL, NULL, NULL);
}

int fim_db_delete_not_scanned(fdb_t * fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage) {
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_FILE, mutex, fim_db_remove_path, storage,
                                    (void *) true, (void *) FIM_SCHEDULED, NULL);
}

int fim_db_delete_range(fdb_t * fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage) {
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_FILE, mutex, fim_db_remove_path, storage,
                                    (void *) false, (void *) FIM_SCHEDULED, NULL);
}

int fim_db_process_missing_entry(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage,
                                 fim_event_mode mode, whodata_evt * w_evt) {
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_FILE, mutex, fim_db_remove_path, storage,
                                    (void *) true, (void *) (fim_event_mode) mode, (void *) w_evt);
}

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
            nodes_count = fim_db_get_count_file_entry(syscheck.database);
            if (nodes_count >= syscheck.file_limit) {
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

void fim_db_callback_calculate_checksum(__attribute__((unused)) fdb_t *fim_sql, char *checksum,
    __attribute__((unused))int storage, void *arg) {

    EVP_DigestUpdate((EVP_MD_CTX *)arg, checksum, strlen(checksum));
}

int fim_db_data_checksum_range(fdb_t *fim_sql, const char *start, const char *top,
                                long id, int n, pthread_mutex_t *mutex) {
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
            merror("Step error getting path range, first half 'start %s' 'top %s' (i:%d): %s", start, top, i,
                   sqlite3_errmsg(fim_sql->db));
            w_mutex_unlock(mutex);
            goto end;
        }
        entry = fim_db_decode_full_row(fim_sql->stmt[FIMDB_STMT_GET_PATH_RANGE]);
        if (i == (m - 1) && entry->file_entry.path) {
            os_strdup(entry->file_entry.path, str_pathlh);
        }
        //Type of storage not required
        fim_db_callback_calculate_checksum(fim_sql, entry->file_entry.data->checksum, FIM_DB_DISK, (void *)ctx_left);
        free_entry(entry);
    }

    //Calculate checksum of the second half
    for (i = m; i < n; i++) {
        if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATH_RANGE]) != SQLITE_ROW) {
            merror("Step error getting path range, second half 'start %s' 'top %s' (i:%d): %s", start, top, i,
                   sqlite3_errmsg(fim_sql->db));
            w_mutex_unlock(mutex);
            goto end;
        }
        entry = fim_db_decode_full_row(fim_sql->stmt[FIMDB_STMT_GET_PATH_RANGE]);
        if (i == m && entry->file_entry.path) {
            os_free(str_pathuh);
            os_strdup(entry->file_entry.path, str_pathuh);
        }
        //Type of storage not required
        fim_db_callback_calculate_checksum(fim_sql, entry->file_entry.data->checksum, FIM_DB_DISK, (void *)ctx_right);
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

        json_event = fim_json_event(entry->file_entry.path, NULL, entry->file_entry.data, pos, FIM_DELETE, mode,
                                    whodata_event, NULL);

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

void fim_db_callback_sync_path_range(__attribute__((unused))fdb_t *fim_sql, fim_entry *entry,
    __attribute__((unused))pthread_mutex_t *mutex, __attribute__((unused))void *alert,
    __attribute__((unused))void *mode, __attribute__((unused))void *w_event) {

    cJSON * file_data = fim_entry_json(entry->file_entry.path, entry->file_entry.data);
    char * plain = dbsync_state_msg("syscheck", file_data);
    mdebug1("Sync Message for %s sent: %s", entry->file_entry.path, plain);
    fim_send_sync_msg(plain);
    os_free(plain);
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
