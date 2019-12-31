#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include "fim_db.h"

static fdb_t fim_db;

static const char *SQL_STMT[] = {
    [FIMDB_STMT_INSERT_DATA] = "INSERT INTO entry_data (dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [FIMDB_STMT_INSERT_PATH] = "INSERT INTO entry_path (path, inode_id, mode, last_event, entry_type, scanned, options, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
    [FIMDB_STMT_GET_PATH] = "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_path INNER JOIN entry_data ON path = ? AND entry_data.rowid = entry_path.inode_id;",
    [FIMDB_STMT_GET_INODE] = "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_path INNER JOIN entry_data ON inode = ? AND dev = ? AND entry_data.rowid = entry_path.inode_id;",
    [FIMDB_STMT_GET_LAST_ROWID] = "SELECT last_insert_rowid()",
    [FIMDB_STMT_GET_ALL_ENTRIES] = "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_data INNER JOIN entry_path ON inode_id = entry_data.rowid ORDER BY PATH ASC;",
    [FIMDB_STMT_GET_NOT_SCANNED] = "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_data INNER JOIN entry_path ON inode_id = entry_data.rowid WHERE scanned = 0 ORDER BY PATH ASC;",
    [FIMDB_STMT_SET_ALL_UNSCANNED] = "UPDATE entry_path SET scanned = 0;",
    [FIMDB_STMT_DELETE_UNSCANNED] = "DELETE FROM entry_path WHERE scanned = 0;",
    [FIMDB_STMT_UPDATE_ENTRY_DATA] = "UPDATE entry_data SET size = ?, perm = ?, attributes = ?, uid = ?, gid = ?, user_name = ?, group_name = ?, hash_md5 = ?, hash_sha1 = ?, hash_sha256 = ?, mtime = ? WHERE dev = ? AND inode = ?;",
    [FIMDB_STMT_UPDATE_ENTRY_PATH] = "UPDATE entry_path SET mode = ?, last_event = ?, entry_type = ?, scanned = ?, options = ?, checksum = ? WHERE inode_id = (SELECT rowid FROM entry_data WHERE dev = ? AND inode = ?);",
    [FIMDB_STMT_GET_PATH_COUNT] = "SELECT count(*), inode_id FROM entry_path WHERE path = ?;",
    [FIMDB_STMT_DELETE_DATA_ID] = "DELETE FROM entry_data WHERE rowid = ?;",
    [FIMDB_STMT_GET_DATA_ROW] = "SELECT rowid FROM entry_data WHERE inode = ? AND dev = ?;",
    [FIMDB_STMT_DELETE_DATA_ROW] = "DELETE FROM entry_data WHERE rowid = ?;",
    [FIMDB_STMT_DELETE_PATH_INODE] = "DELETE FROM entry_path WHERE inode_id = ?;",
    [FIMDB_STMT_DELETE_PATH] = "DELETE FROM entry_path WHERE path = ?;",
    [FIMDB_STMT_DISABLE_SCANNED] = "UPDATE entry_data SET scanned = 0;",
    [FIMDB_STMT_GET_UNIQUE_FILE] = "SELECT path, inode_id, mode, last_event, entry_type, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime FROM entry_path INNER JOIN entry_data ON inode = ? AND dev = ? AND entry_data.rowid = entry_path.inode_id AND entry_path.path = ?;"
};

static fim_entry *fim_decode_full_row(sqlite3_stmt *stmt);
static int fim_exec_simple_wquery(const char *query);
static int fim_db_process_get_query(fdb_stmt query_id, const char * start, const char * end, void (*callback)(fim_entry *, void *), void * arg);


int fim_db_clean(void) {
    if(w_is_file(FIM_DB_PATH)) {
        return remove(FIM_DB_PATH);
    }
    return FIMDB_OK;
}


int fim_db_init(const bool MEM) {
    memset(&fim_db, 0, sizeof(fdb_t));
    fim_db.transaction.interval = COMMIT_INTERVAL;
    char * path = (MEM == true)? FIM_DB_MEM : FIM_DB_PATH;

    if(fim_db_clean() < 0) {
        return FIMDB_ERR;
    }

    if (wdb_create_file(path, schema_fim_sql, MEM, &fim_db.db) < 0) {
        return FIMDB_ERR;
    }

    if (MEM == false &&
        sqlite3_open_v2(path, &fim_db.db, SQLITE_OPEN_READWRITE, NULL)) {
            return FIMDB_ERR;
    }

    if (fim_exec_simple_wquery("BEGIN;") == FIMDB_ERR) {
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}


int fim_db_insert(const char* file_path, fim_entry_data *entry) {

    int retval = FIMDB_ERR;

    // Insert in entry_data
    sqlite3_stmt *stmt = fim_db_cache(FIMDB_STMT_INSERT_DATA);
    if (!stmt) {
        goto end;
    }
    sqlite3_bind_int(stmt, 1, entry->dev);
    sqlite3_bind_int(stmt, 2, entry->inode);
    sqlite3_bind_int(stmt, 3, entry->size);
    sqlite3_bind_text(stmt, 4, entry->perm, -1, NULL);
    sqlite3_bind_text(stmt, 5, entry->attributes, -1, NULL);
    sqlite3_bind_text(stmt, 6, entry->uid, -1, NULL);
    sqlite3_bind_text(stmt, 7, entry->gid, -1, NULL);
    sqlite3_bind_text(stmt, 8, entry->user_name, -1, NULL);
    sqlite3_bind_text(stmt, 9, entry->group_name, -1, NULL);
    sqlite3_bind_text(stmt, 10, entry->hash_md5, -1, NULL);
    sqlite3_bind_text(stmt, 11, entry->hash_sha1, -1, NULL);
    sqlite3_bind_text(stmt, 12, entry->hash_sha256, -1, NULL);
    sqlite3_bind_int(stmt, 13, entry->mtime);

    switch(sqlite3_step(stmt)) {
    case SQLITE_DONE:
        // Get rowid
        if (stmt = fim_db_cache(FIMDB_STMT_GET_LAST_ROWID), !stmt) {
            goto end;
        }
        int row_id;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            row_id = sqlite3_column_int(stmt, 0);
        } else {
            merror("SQL ERROR: %s", sqlite3_errmsg(fim_db.db));
            goto end;
        }
        // Insert in inode_path
        if (stmt = fim_db_cache(FIMDB_STMT_INSERT_PATH), !stmt) {
            goto end;
        }
        sqlite3_bind_text(stmt, 1, file_path, -1, NULL);
        sqlite3_bind_int(stmt, 2, row_id);
        sqlite3_bind_int(stmt, 3, entry->mode);
        sqlite3_bind_int(stmt, 4, entry->last_event);
        sqlite3_bind_int(stmt, 5, entry->entry_type);
        sqlite3_bind_int(stmt, 6, entry->scanned);
        sqlite3_bind_int(stmt, 7, entry->options);
        sqlite3_bind_text(stmt, 8, entry->checksum, -1, NULL);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            merror("SQL ERROR: %s", sqlite3_errmsg(fim_db.db));
            goto end;
        }
        break;

    case SQLITE_CONSTRAINT: // File already in entry_data (link)
        // Update entry_data
        if (stmt = fim_db_cache(FIMDB_STMT_UPDATE_ENTRY_DATA), !stmt) {
            goto end;
        }
        sqlite3_bind_int(stmt, 1, entry->size);
        sqlite3_bind_text(stmt, 2, entry->perm, -1, NULL);
        sqlite3_bind_text(stmt, 3, entry->attributes, -1, NULL);
        sqlite3_bind_text(stmt, 4, entry->uid, -1, NULL);
        sqlite3_bind_text(stmt, 5, entry->gid, -1, NULL);
        sqlite3_bind_text(stmt, 6, entry->user_name, -1, NULL);
        sqlite3_bind_text(stmt, 7, entry->group_name, -1, NULL);
        sqlite3_bind_text(stmt, 8, entry->hash_md5, -1, NULL);
        sqlite3_bind_text(stmt, 9, entry->hash_sha1, -1, NULL);
        sqlite3_bind_text(stmt, 10, entry->hash_sha256, -1, NULL);
        sqlite3_bind_int(stmt, 11, entry->mtime);
        sqlite3_bind_int(stmt, 12, entry->dev);
        sqlite3_bind_int(stmt, 13, entry->inode);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            printf("SQL ERROR: %s", sqlite3_errmsg(fim_db.db));
            goto end;
        }

        // Add to entry_path
        // Get ID
        if (stmt = fim_db_cache(FIMDB_STMT_GET_DATA_ROW), !stmt) {
            goto end;
        }
        sqlite3_bind_int(stmt, 1, entry->inode);
        sqlite3_bind_int(stmt, 2, entry->dev);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int data_id = sqlite3_column_int(stmt, 0);
            // Insert in inode_path
            if (stmt = fim_db_cache(FIMDB_STMT_INSERT_PATH), !stmt) {
                goto end;
            }
            sqlite3_bind_text(stmt, 1, file_path, -1, NULL);
            sqlite3_bind_int(stmt, 2, data_id);
            sqlite3_bind_int(stmt, 3, entry->mode);
            sqlite3_bind_int(stmt, 4, entry->last_event);
            sqlite3_bind_int(stmt, 5, entry->entry_type);
            sqlite3_bind_int(stmt, 6, entry->scanned);
            sqlite3_bind_int(stmt, 7, entry->options);
            sqlite3_bind_text(stmt, 8, entry->checksum, -1, NULL);

            int res = sqlite3_step(stmt);
            if (res != SQLITE_DONE && res != SQLITE_CONSTRAINT) {
                printf("SQL ERROR (%i): %s", res, sqlite3_errmsg(fim_db.db));
                goto end;
            }
        } else {
            goto end;
        }
    }

    retval = FIMDB_OK;
    fim_check_transaction();
end:
    return retval;
}


int fim_db_remove_path(const char * file_path) {
    int retval = FIMDB_ERR;
    sqlite3_stmt *stmt = fim_db_cache(FIMDB_STMT_GET_PATH_COUNT);
    if (!stmt) {
        goto end;
    }

    sqlite3_bind_text(stmt, 1, file_path, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int rows = sqlite3_column_int(stmt, 0);
        switch (rows) {
        case 0:
            // No entries with this path.
            break;
        case 1:
            // The inode has only one entry, delete the entry data.
            if (stmt = fim_db_cache(FIMDB_STMT_DELETE_DATA_ID), !stmt) {
                goto end;
            }
            sqlite3_bind_text(stmt, 1, sqlite3_column_text(stmt, 1), -1, NULL);
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                goto end;
            }
            // Fallthrough
        default:
            // The inode has more entries, delete only this path.
            if (stmt = fim_db_cache(FIMDB_STMT_DELETE_PATH), !stmt) {
                goto end;
            }
            sqlite3_bind_text(stmt, 1, file_path, -1, NULL);
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                goto end;
            }
            break;
        }
    }

    retval = FIMDB_OK;
end:
    fim_check_transaction();
    return retval;
}


int fim_db_remove_inode(const unsigned long int inode, const unsigned long int dev) {
    int retval = FIMDB_ERR;
    sqlite3_stmt *stmt = fim_db_cache(FIMDB_STMT_GET_DATA_ROW);
    if (!stmt) {
        goto end;
    }

    sqlite3_bind_int(stmt, 1, inode);
    sqlite3_bind_int(stmt, 2, dev);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int row_id = sqlite3_column_int(stmt, 0);
        // Delete the entry data.
        if (stmt = fim_db_cache(FIMDB_STMT_DELETE_DATA_ROW), !stmt) {
            goto end;
        }
        sqlite3_bind_int(stmt, 1, row_id);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            goto end;
        }

        // Delete all paths with this inode.
        if (stmt = fim_db_cache(FIMDB_STMT_DELETE_PATH_INODE), !stmt) {
            goto end;
        }
        sqlite3_bind_int(stmt, 1, row_id);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            goto end;
        }
    }

    retval = FIMDB_OK;
end:
    fim_check_transaction();
    return retval;
}


fim_entry * fim_db_get_inode(const unsigned long int inode, const unsigned long int dev) {

    fim_entry *entry = NULL;

    sqlite3_stmt *stmt = fim_db_cache(FIMDB_STMT_GET_INODE);
    if (!stmt) {
        goto end;
    }
    sqlite3_bind_int(stmt, 1, inode);
    sqlite3_bind_int(stmt, 2, dev);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        entry = calloc(1, sizeof(fim_entry));
        entry->path = os_AddStrArray((char *)sqlite3_column_text(stmt, 0), entry->path);
        entry->data = calloc(1, sizeof(fim_entry_data));

        entry->data->mode = (unsigned int)sqlite3_column_int(stmt, 2);
        entry->data->last_event = (time_t)sqlite3_column_int(stmt, 3);
        entry->data->entry_type = (fim_entry_type)sqlite3_column_int(stmt, 4);
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
    } else {
        goto end;
    }

    // Add more paths if needed.
    int result = 0;
    while (result = sqlite3_step(stmt), result == SQLITE_ROW) {
        entry->path = os_AddStrArray((char *)sqlite3_column_text(stmt, 0), entry->path);
    }

end:
    fim_check_transaction();
    return entry;
}


fim_entry * fim_db_get_path(const char * file_path) {
    fim_entry *entry = NULL;
    sqlite3_stmt *stmt = fim_db_cache(FIMDB_STMT_GET_PATH);
    if (!stmt) {
        goto end;
    }
    sqlite3_bind_text(stmt, 1, file_path, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        entry = calloc(1, sizeof(fim_entry));
        entry->path = os_AddStrArray((char *)sqlite3_column_text(stmt, 0), entry->path);
        entry->data = calloc(1, sizeof(fim_entry_data));

        entry->data->mode = (unsigned int)sqlite3_column_int(stmt, 2);
        entry->data->last_event = (time_t)sqlite3_column_int(stmt, 3);
        entry->data->entry_type = (fim_entry_type)sqlite3_column_int(stmt, 4);
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
    }

end:
    fim_check_transaction();
    return entry;
}


int fim_db_set_not_scanned(void) {
    int ret = FIMDB_ERR;
    sqlite3_stmt *stmt = fim_db_cache(FIMDB_STMT_DISABLE_SCANNED);
    if (!stmt) {
        fim_check_transaction();
        return ret;
    }


    if (sqlite3_step(stmt) == SQLITE_DONE) {
        ret = FIMDB_OK;
    }

    fim_check_transaction();
    return ret;
}


int fim_db_get_all(void (*callback)(fim_entry *, void *), void * arg) {
    return fim_db_process_get_query(FIMDB_STMT_GET_ALL_ENTRIES, NULL, NULL, callback, arg);
}


int fim_db_get_range(const char * start, const char * end, void (*callback)(fim_entry *, void *), void * arg) {
    return fim_db_process_get_query(FIMDB_STMT_GET_ALL_ENTRIES, start, end, callback, arg);
}


int fim_db_get_not_scanned(void (*callback)(fim_entry *, void *), void * arg) {
    return fim_db_process_get_query(FIMDB_STMT_GET_NOT_SCANNED, NULL, NULL, callback, arg);
}


fim_entry *fim_decode_full_row(sqlite3_stmt *stmt) {

    fim_entry *entry = calloc(1, sizeof(fim_entry));
    entry->path = os_AddStrArray((char *)sqlite3_column_text(stmt, 0), entry->path);
    entry->data = calloc(1, sizeof(fim_entry_data));

    entry->data->mode = (unsigned int)sqlite3_column_int(stmt, 2);
    entry->data->last_event = (time_t)sqlite3_column_int(stmt, 3);
    entry->data->entry_type = (fim_entry_type)sqlite3_column_int(stmt, 4);
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

    fim_check_transaction();
    return entry;
}


int fim_db_set_all_unscanned(void) {
    int retval = fim_exec_simple_wquery(SQL_STMT[FIMDB_STMT_SET_ALL_UNSCANNED]);
    fim_check_transaction();
    return retval;
}


int fim_db_delete_unscanned(void) {
    int retval = fim_exec_simple_wquery(SQL_STMT[FIMDB_STMT_DELETE_UNSCANNED]);
    fim_check_transaction();
    return retval;
}


int fim_exec_simple_wquery(const char *query) {
    char *error = NULL;
    sqlite3_exec(fim_db.db, query, NULL, NULL, &error);
    if (error) {
        merror("SQL ERROR: %s", error);
        sqlite3_free(error);
        return FIMDB_ERR;
    }
    return FIMDB_OK;
}


int fim_db_update(const unsigned long int inode, const unsigned long int dev, fim_entry_data *entry) {
    int retval = FIMDB_ERR;
    // Update entry_data
    sqlite3_stmt *stmt = fim_db_cache(FIMDB_STMT_UPDATE_ENTRY_DATA);
    if (!stmt) {
        goto end;
    }

    sqlite3_bind_int(stmt, 1, entry->size);
    sqlite3_bind_text(stmt, 2, entry->perm, -1, NULL);
    sqlite3_bind_text(stmt, 3, entry->attributes, -1, NULL);
    sqlite3_bind_text(stmt, 4, entry->uid, -1, NULL);
    sqlite3_bind_text(stmt, 5, entry->gid, -1, NULL);
    sqlite3_bind_text(stmt, 6, entry->user_name, -1, NULL);
    sqlite3_bind_text(stmt, 7, entry->group_name, -1, NULL);
    sqlite3_bind_text(stmt, 8, entry->hash_md5, -1, NULL);
    sqlite3_bind_text(stmt, 9, entry->hash_sha1, -1, NULL);
    sqlite3_bind_text(stmt, 10, entry->hash_sha256, -1, NULL);
    sqlite3_bind_int(stmt, 11, entry->mtime);
    sqlite3_bind_int(stmt, 12, entry->dev);
    sqlite3_bind_int(stmt, 13, entry->inode);

    int result;
    if (result = sqlite3_step(stmt), result != SQLITE_DONE) {
        merror("SQL ERROR: %s", sqlite3_errmsg(fim_db.db));
        goto end;
    }

    // Update entry_path
    if (stmt = fim_db_cache(FIMDB_STMT_UPDATE_ENTRY_PATH), !stmt) {
        goto end;
    }

    sqlite3_bind_int(stmt, 1, entry->mode);
    sqlite3_bind_int(stmt, 2, entry->last_event);
    sqlite3_bind_int(stmt, 3, entry->entry_type);
    sqlite3_bind_int(stmt, 4, entry->scanned);
    sqlite3_bind_int(stmt, 5, entry->options);
    sqlite3_bind_text(stmt, 6, entry->checksum, -1, NULL);
    sqlite3_bind_int(stmt, 7, entry->dev);
    sqlite3_bind_int(stmt, 8, entry->inode);
    if (result = sqlite3_step(stmt), result != SQLITE_DONE) {
        merror("SQL ERROR: %s", sqlite3_errmsg(fim_db.db));
        goto end;
    }

    retval = FIMDB_OK;
end:
    fim_check_transaction();
    return retval;
}


int fim_db_process_get_query(fdb_stmt query_id, const char * start, const char * end, void (*callback)(fim_entry *, void *), void * arg) {
    sqlite3_stmt *stmt = fim_db_cache(query_id);
    if (!stmt) {
        fim_check_transaction();
        return FIMDB_ERR;
    }

    int result;
    char init_found = 0;
    while (result = sqlite3_step(stmt), result == SQLITE_ROW) {
        char *path = (char *)sqlite3_column_text(stmt, 0);
        if (!path) {
            continue;
        }

        if (!init_found && start && strcmp(start, path)) {
            continue;
        }
        init_found = 1;

        fim_entry *entry = fim_decode_full_row(stmt);
        callback((void *) entry, arg);
        free_entry(entry);

        if (end && !strcmp(end, path)) {
            result = SQLITE_DONE;
            break;
        }
    }

    fim_check_transaction();
    return result != SQLITE_DONE ? FIMDB_ERR : FIMDB_OK;
}


void fim_check_transaction() {
    time_t now = time(NULL);
    if (fim_db.transaction.last_commit + fim_db.transaction.interval <= now) {
        if (!fim_db.transaction.last_commit) {
            fim_db.transaction.last_commit = now;
            return;
        }

        // If the completion of the transaction fails, we do not update the timestamp
        if (fim_exec_simple_wquery("END;") != FIMDB_ERR) {
            mdebug1("Database transaction completed.");
            fim_db.transaction.last_commit = now;
            while (fim_exec_simple_wquery("BEGIN;") == FIMDB_ERR);
        }
    }
}


sqlite3_stmt *fim_db_cache(fdb_stmt index) {
    sqlite3_stmt *stmt = NULL;

    if (index >= WDB_STMT_SIZE) {
        merror("Error in fim_db_cache(): Invalid index: %d.", (int) index);
        goto end;
    } else if (!fim_db.stmt[index]) {
        if (sqlite3_prepare_v2(fim_db.db, SQL_STMT[index], -1, &fim_db.stmt[index], NULL) != SQLITE_OK) {
            merror("Error in fim_db_cache(): %s", sqlite3_errmsg(fim_db.db));
            goto end;
        }
    } else if (sqlite3_reset(fim_db.stmt[index]) != SQLITE_OK || sqlite3_clear_bindings(fim_db.stmt[index]) != SQLITE_OK) {
        wdb_finalize(fim_db.stmt[index]);

        if (sqlite3_prepare_v2(fim_db.db, SQL_STMT[index], -1, &fim_db.stmt[index], NULL) != SQLITE_OK) {
            merror("Error in fim_db_cache(): %s", sqlite3_errmsg(fim_db.db));
            goto end;
        }
    }

    stmt = fim_db.stmt[index];
end:
    return stmt;
}


fim_entry * fim_db_get_unique_file(const char * file_path, const unsigned long int inode, const unsigned long int dev) {
    sqlite3_stmt *stmt = fim_db_cache(FIMDB_STMT_GET_UNIQUE_FILE);
    fim_entry *entry = NULL;
    if (!stmt) {
        goto end;
    }

    sqlite3_bind_int(stmt, 1, inode);
    sqlite3_bind_int(stmt, 2, dev);
    sqlite3_bind_text(stmt, 3, file_path, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        entry = calloc(1, sizeof(fim_entry));
        entry->path = os_AddStrArray((char *)sqlite3_column_text(stmt, 0), entry->path);
        entry->data = calloc(1, sizeof(fim_entry_data));

        entry->data->mode = (unsigned int)sqlite3_column_int(stmt, 2);
        entry->data->last_event = (time_t)sqlite3_column_int(stmt, 3);
        entry->data->entry_type = (fim_entry_type)sqlite3_column_int(stmt, 4);
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
    }

end:
    fim_check_transaction();
    return entry;
}


void fim_force_commit() {
    fim_db.transaction.last_commit = 1;
    fim_check_transaction();
}
