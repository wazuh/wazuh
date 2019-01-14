/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"

static const char *SQL_INSERT_EVENT = "INSERT INTO fim_event (id_file, type, date, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, attributes) VALUES (?, ?, datetime(?, 'unixepoch', 'localtime'), ?, ?, ?, ?, ?, ?, ?, ?, datetime(?, 'unixepoch', 'localtime'), ?, ?, ?);";
static const char *SQL_INSERT_FILE = "INSERT INTO fim_file (path, type) VALUES (?, ?);";
static const char *SQL_FIND_FILE = "SELECT id FROM fim_file WHERE type = ? AND path = ?;";
static const char *SQL_SELECT_LAST_EVENT = "SELECT type FROM fim_event WHERE id = (SELECT MAX(fim_event.id) FROM fim_event, fim_file WHERE fim_file.type = ? AND path = ? AND fim_file.id = id_file);";
static const char *SQL_DELETE_EVENT = "DELETE FROM fim_event;";
static const char *SQL_DELETE_FILE = "DELETE FROM fim_file;";

/* Find file: returns ID, or 0 if it doesn't exists, or -1 on error. */
int wdb_insert_file(sqlite3 *db, const char *path, int type) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_prepare(db, SQL_INSERT_FILE, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, path, -1, NULL);
    sqlite3_bind_text(stmt, 2, type == WDB_FILE_TYPE_FILE ? "file" : "registry", -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE)
        result = (int)sqlite3_last_insert_rowid(db);
    else {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        result = -1;
    }

    sqlite3_finalize(stmt);
    return result;
}

/* Find file, Returns ID, or -1 on error. */
int wdb_find_file(sqlite3 *db, const char *path, int type) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_prepare(db, SQL_FIND_FILE, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, type == WDB_FILE_TYPE_FILE ? "file" : "registry", -1, NULL);
    sqlite3_bind_text(stmt, 2, path, -1, NULL);

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        result = sqlite3_column_int(stmt, 0);
        break;
    case SQLITE_DONE:
        result = 0;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        result = -1;
    }

    sqlite3_finalize(stmt);
    return result;
}

/* Get last state from file: returns WDB_FIM_*, or -1 on error. */
int wdb_get_last_fim(sqlite3 *db, const char *path, int type) {
    sqlite3_stmt *stmt = NULL;
    const char *event = NULL;
    int result;

    if (wdb_prepare(db, SQL_SELECT_LAST_EVENT, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, type == WDB_FILE_TYPE_FILE ? "file" : "registry", -1, NULL);
    sqlite3_bind_text(stmt, 2, path, -1, NULL);

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        event = (const char*)sqlite3_column_text(stmt, 0);
        result = !strcmp(event, "modified") ? WDB_FIM_MODIFIED : !strcmp(event, "added") ? WDB_FIM_ADDED : !strcmp(event, "readded") ? WDB_FIM_READDED : WDB_FIM_DELETED;
        break;
    case SQLITE_DONE:
        result = WDB_FIM_NOT_FOUND;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        result = -1;
    }

    sqlite3_finalize(stmt);
    return result;
}

/* Insert FIM entry. Returns ID, or -1 on error. */
int wdb_insert_fim(sqlite3 *db, int type, long timestamp, const char *f_name, const char *event, const sk_sum_t *sum) {
    sqlite3_stmt *stmt = NULL;
    int id_file;
    int result;

    if (wdb_prepare(db, SQL_INSERT_EVENT, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        return -1;
    }

    switch ((id_file = wdb_find_file(db, f_name, type))) {
    case -1:
        return -1;

    case 0:
        if ((id_file = wdb_insert_file(db, f_name, type)) < 0) {
            return -1;
        }
    }

    sqlite3_bind_int(stmt, 1, id_file);
    sqlite3_bind_text(stmt, 2, event, -1, NULL);
    sqlite3_bind_int64(stmt, 3, timestamp);

    if (sum && strcmp(event, "deleted")) {
        char perm[7];
        snprintf(perm, 7, "%06o", sum->perm);

        sqlite3_bind_int64(stmt, 4, atol(sum->size));
        sqlite3_bind_text(stmt, 5, (!sum->win_perm) ? perm : sum->win_perm, -1, NULL);

        // UID and GID from Windows is 0. It should be NULL
        sqlite3_bind_int(stmt, 6, atoi(sum->uid));
        sqlite3_bind_int(stmt, 7, atoi(sum->gid));

        sqlite3_bind_text(stmt, 8, sum->md5, -1, NULL);
        sqlite3_bind_text(stmt, 9, sum->sha1, -1, NULL);

        if (sum->uname){
            sqlite3_bind_text(stmt, 10, sum->uname, -1, NULL);
            sqlite3_bind_text(stmt, 11, sum->gname, -1, NULL);
        }
        else{ // Old agents
            sqlite3_bind_null(stmt, 10); // uname
            sqlite3_bind_null(stmt, 11); // gname
        }

        if (sum->mtime)
            sqlite3_bind_int64(stmt, 12, sum->mtime);
        else // Old agents
            sqlite3_bind_null(stmt, 12); // mtime

        if (sum->inode)
            sqlite3_bind_int64(stmt, 13, sum->inode);
        else // Old agents
            sqlite3_bind_null(stmt, 13); // inode

        if (sum->sha256)
            sqlite3_bind_text(stmt, 14, sum->sha256, -1, NULL);
        else // Old agents
            sqlite3_bind_null(stmt, 14); // sha256

        if (sum->attrs)
            sqlite3_bind_int(stmt, 15, sum->attrs);
        else // Old agents
            sqlite3_bind_null(stmt, 15); // attributes
    } else {
        sqlite3_bind_null(stmt, 4);
        sqlite3_bind_null(stmt, 5);
        sqlite3_bind_null(stmt, 6);
        sqlite3_bind_null(stmt, 7);
        sqlite3_bind_null(stmt, 8);
        sqlite3_bind_null(stmt, 9);
        sqlite3_bind_null(stmt, 10);
        sqlite3_bind_null(stmt, 11);
        sqlite3_bind_null(stmt, 12);
        sqlite3_bind_null(stmt, 13);
        sqlite3_bind_null(stmt, 14);
        sqlite3_bind_null(stmt, 15);
    }

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_last_insert_rowid(db) : -1;
    sqlite3_finalize(stmt);
    return result;
}

/* Delete FIM events of an agent. Returns number of affected rows on success or -1 on error. */
int wdb_delete_fim(int id) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    char *name = id ? wdb_agent_name(id) : strdup("localhost");
    int result;

    if (!name)
        return -1;

    db = wdb_open_agent(id, name);
    free(name);

    if (!db)
        return -1;

    // Delete files first to maintain reference integrity on insertion

    if (wdb_prepare(db, SQL_DELETE_FILE, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        return -1;
    }

    result = wdb_step(stmt);
    sqlite3_finalize(stmt);

    if (result != SQLITE_DONE) {
        sqlite3_close_v2(db);
        return -1;
    }

    // Delete events

    if (wdb_prepare(db, SQL_DELETE_EVENT, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        return -1;
    }

    result = wdb_step(stmt) == SQLITE_DONE ? sqlite3_changes(db) : -1;
    sqlite3_finalize(stmt);
    wdb_vacuum(db);
    sqlite3_close_v2(db);
    return result;
}

/* Delete FIM events of all agents */
void wdb_delete_fim_all() {
    int *agents = wdb_get_all_agents();
    int i;

    if (agents) {
        wdb_delete_fim(0);

        for (i = 0; agents[i] >= 0; i++)
            wdb_delete_fim(agents[i]);

        free(agents);
    }
}

int wdb_syscheck_load(wdb_t * wdb, const char * file, char * output, size_t size) {
    sqlite3_stmt * stmt;
    sk_sum_t sum;
    char *str_perm;

    memset(&sum, 0, sizeof(sk_sum_t));

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_LOAD) < 0) {
        merror("DB(%s) Can't cache statement", wdb->agent_id);
        return -1;
    }

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        merror("DB(%s) Can't begin transaction", wdb->agent_id);
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_FIM_LOAD];

    if (sqlite3_bind_text(stmt, 1, file, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        return -1;
    }

    switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:

        sum.changes = (long)sqlite3_column_int64(stmt, 0);
        sum.size = (char *)sqlite3_column_text(stmt, 1);
        str_perm = (char *)sqlite3_column_text(stmt, 2);
        sum.uid = (char *)sqlite3_column_text(stmt, 3);
        sum.gid = (char *)sqlite3_column_text(stmt, 4);
        sum.md5 = (char *)sqlite3_column_text(stmt, 5);
        sum.sha1 = (char *)sqlite3_column_text(stmt, 6);
        sum.uname = (char *)sqlite3_column_text(stmt, 7);
        sum.gname = (char *)sqlite3_column_text(stmt, 8);
        sum.mtime = (long)sqlite3_column_int64(stmt, 9);
        sum.inode = (long)sqlite3_column_int64(stmt, 10);
        sum.sha256 = (char *)sqlite3_column_text(stmt, 11);
        sum.date_alert = (long)sqlite3_column_int64(stmt, 12);
        sum.attrs = (unsigned int)sqlite3_column_int(stmt, 13);

        if (*str_perm != '|') {
            sum.perm = strtol(str_perm, NULL, 8);
        } else {
            sum.win_perm = str_perm;
        }

        output[size - 1] = '\0';
        return sk_build_sum(&sum, output, size);

    case SQLITE_DONE:
        *output = 0;
        return 0;

    default:
        merror("DB(%s) sqlite3_step(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_syscheck_save(wdb_t * wdb, int ftype, char * checksum, const char * file) {
    sk_sum_t sum;

    memset(&sum, 0, sizeof(sk_sum_t));

    if (sk_decode_extradata(&sum, checksum) < 0) {
        mdebug1("Checksum: %s", checksum);
        return -1;
    }

    if (sk_decode_sum(&sum, checksum, NULL) < 0) {
        mdebug1("Checksum: %s", checksum);
        return -1;
    }

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        merror("DB(%s) Can't begin transaction", wdb->agent_id);
        return -1;
    }

    switch (wdb_fim_find_entry(wdb, file)) {
    case -1:
        mdebug1("DB(%s) Can't find file by name", wdb->agent_id);
        return -1;

    case 0:
        // File not found, add

        if (wdb_fim_insert_entry(wdb, file, ftype, &sum) < 0) {
            mdebug1("DB(%s) Can't insert file entry", wdb->agent_id);
            return -1;
        }

        break;

    default:
        // Update entry

        if (wdb_fim_update_entry(wdb, file, &sum) < 1) {
            mdebug1("DB(%s) Can't update file entry", wdb->agent_id);
            return -1;
        }
    }

    return 0;
}

// Find file entry: returns 1 if found, 0 if not, or -1 on error.
int wdb_fim_find_entry(wdb_t * wdb, const char * path) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_FIND_ENTRY) < 0) {
        merror("DB(%s) Can't cache statement", wdb->agent_id);
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_FIM_FIND_ENTRY];

    sqlite3_bind_text(stmt, 1, path, -1, NULL);

    switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:
        return 1;
        break;
    case SQLITE_DONE:
        return 0;
        break;
    default:
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_fim_insert_entry(wdb_t * wdb, const char * file, int ftype, const sk_sum_t * sum) {
    sqlite3_stmt *stmt = NULL;
    char s_perm[16];
    const char * s_ftype;

    switch (ftype) {
    case WDB_FILE_TYPE_FILE:
        s_ftype = "file";
        break;
    case WDB_FILE_TYPE_REGISTRY:
        s_ftype = "registry";
        break;
    default:
        merror("DB(%s) Invalid file type '%d'", wdb->agent_id, ftype);
        return -1;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_INSERT_ENTRY) < 0) {
        merror("DB(%s) Can't cache statement", wdb->agent_id);
        return -1;
    }

    snprintf(s_perm, sizeof(s_perm), "%06o", sum->perm);
    stmt = wdb->stmt[WDB_STMT_FIM_INSERT_ENTRY];

    sqlite3_bind_text(stmt, 1, file, -1, NULL);
    sqlite3_bind_text(stmt, 2, s_ftype, -1, NULL);
    sqlite3_bind_text(stmt, 3, sum->size, -1, NULL);
    sqlite3_bind_text(stmt, 4, (!sum->win_perm) ? s_perm : sum->win_perm, -1, NULL);
    sqlite3_bind_text(stmt, 5, sum->uid, -1, NULL);
    sqlite3_bind_text(stmt, 6, sum->gid, -1, NULL);
    sqlite3_bind_text(stmt, 7, sum->md5, -1, NULL);
    sqlite3_bind_text(stmt, 8, sum->sha1, -1, NULL);
    sqlite3_bind_text(stmt, 9, sum->uname, -1, NULL);
    sqlite3_bind_text(stmt, 10, sum->gname, -1, NULL);
    sqlite3_bind_int64(stmt, 11, sum->mtime);
    sqlite3_bind_int64(stmt, 12, sum->inode);
    sqlite3_bind_text(stmt, 13, sum->sha256, -1, NULL);
    sqlite3_bind_int(stmt, 14, sum->attrs);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_fim_update_entry(wdb_t * wdb, const char * file, const sk_sum_t * sum) {
    sqlite3_stmt *stmt = NULL;
    char s_perm[16];

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_UPDATE_ENTRY) < 0) {
        merror("DB(%s) Can't cache statement", wdb->agent_id);
        return -1;
    }

    snprintf(s_perm, sizeof(s_perm), "%06o", sum->perm);
    stmt = wdb->stmt[WDB_STMT_FIM_UPDATE_ENTRY];


    sqlite3_bind_int64(stmt, 1, sum->changes);
    sqlite3_bind_text(stmt, 2, sum->size, -1, NULL);
    sqlite3_bind_text(stmt, 3, (!sum->win_perm) ? s_perm : sum->win_perm, -1, NULL);
    sqlite3_bind_text(stmt, 4, sum->uid, -1, NULL);
    sqlite3_bind_text(stmt, 5, sum->gid, -1, NULL);
    sqlite3_bind_text(stmt, 6, sum->md5, -1, NULL);
    sqlite3_bind_text(stmt, 7, sum->sha1, -1, NULL);
    sqlite3_bind_text(stmt, 8, sum->uname, -1, NULL);
    sqlite3_bind_text(stmt, 9, sum->gname, -1, NULL);
    sqlite3_bind_int64(stmt, 10, sum->mtime);
    sqlite3_bind_int64(stmt, 11, sum->inode);
    sqlite3_bind_text(stmt, 12, sum->sha256, -1, NULL);
    sqlite3_bind_int(stmt, 13, sum->attrs);
    sqlite3_bind_text(stmt, 14, file, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return sqlite3_changes(wdb->db);
    } else {
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}

// Delete file entry: returns 1 if found, 0 if not, or -1 on error.
int wdb_fim_delete(wdb_t * wdb, const char * path) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_DELETE) < 0) {
        merror("DB(%s) Can't cache statement", wdb->agent_id);
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_FIM_DELETE];

    sqlite3_bind_text(stmt, 1, path, -1, NULL);

    switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:
        return 0;
        break;
    case SQLITE_DONE:
        return 0;
        break;
    default:
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_fim_update_date_entry(wdb_t * wdb, const char *path) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_UPDATE_DATE) < 0) {
        merror("DB(%s) Can't cache statement", wdb->agent_id);
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_FIM_UPDATE_DATE];

    sqlite3_bind_text(stmt, 1, path, -1, NULL);

    switch (sqlite3_step(stmt)) {
    case SQLITE_DONE:
        mdebug2("DB(%s) Updated date field for file '%s' to '%ld'", wdb->agent_id, path, (long)time(NULL));
        return 0;
    default:
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_fim_clean_old_entries(wdb_t * wdb) {
    sqlite3_stmt *stmt = NULL;
    char *file;
    int result, del_result;
    long tscheck3 = 0;
    long date;

    if(result = wdb_scan_info_get (wdb, "fim", "fim_third_check", &tscheck3), result < 0) {
        mdebug1("DB(%s) Can't get scan_info entry", wdb->agent_id);
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_FIM_FIND_DATE_ENTRIES) < 0) {
        merror("DB(%s) Can't cache statement", wdb->agent_id);
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_FIM_FIND_DATE_ENTRIES];
    sqlite3_bind_int64(stmt, 1, tscheck3);

    while(result = sqlite3_step(stmt), result != SQLITE_DONE) {
        switch (result) {
            case SQLITE_ROW:
                //call to delete
                file = (char *)sqlite3_column_text(stmt, 0);
                date = sqlite3_column_int64(stmt, 13);
                mdebug1("DB(%s) Cleaning DDBB. Deleting entry '%s' date<tscheck3 '%ld'<'%ld'.", wdb->agent_id, file, date, tscheck3);
                if(strcmp(file, "internal_options.conf") != 0 && strcmp(file, "ossec.conf") != 0) {
                    if (del_result = wdb_fim_delete(wdb, file), del_result < 0) {
                        mdebug2("DB(%s) Can't delete Syscheck entry '%s'.", wdb->agent_id, file);
                    }
                }
                break;
            default:
                mdebug1("DB(%s) sqlite3_step(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
                return -1;
        }
    }

    return 0;
}
