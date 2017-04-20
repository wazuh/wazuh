/*
 * Wazuh SQLite integration
 * Copyright (C) 2016 Wazuh Inc.
 * July 5, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"
#include "defs.h"

static const char *SQL_INSERT_AGENT = "INSERT INTO agent (id, name, ip, key, date_add, `group`) VALUES (?, ?, ?, ?, datetime(CURRENT_TIMESTAMP, 'localtime'), ?);";
static const char *SQL_UPDATE_AGENT_NAME = "UPDATE agent SET name = ? WHERE id = ?;";
static const char *SQL_UPDATE_AGENT_VERSION = "UPDATE agent SET os = ?, version = ?, shared_sum = ? WHERE id = ?;";
static const char *SQL_UPDATE_AGENT_KEEPALIVE = "UPDATE agent SET last_keepalive = datetime(?, 'unixepoch', 'localtime') WHERE id = ?;";
static const char *SQL_SELECT_AGENT_STATUS = "SELECT status FROM agent WHERE id = ?;";
static const char *SQL_UPDATE_AGENT_STATUS = "UPDATE agent SET status = ? WHERE id = ?;";
static const char *SQL_UPDATE_AGENT_GROUP = "UPDATE agent SET `group` = ? WHERE id = ?;";
static const char *SQL_SELECT_FIM_OFFSET = "SELECT fim_offset FROM agent WHERE id = ?;";
static const char *SQL_SELECT_REG_OFFSET = "SELECT reg_offset FROM agent WHERE id = ?;";
static const char *SQL_UPDATE_FIM_OFFSET = "UPDATE agent SET fim_offset = ? WHERE id = ?;";
static const char *SQL_UPDATE_REG_OFFSET = "UPDATE agent SET reg_offset = ? WHERE id = ?;";
static const char *SQL_DELETE_AGENT = "DELETE FROM agent WHERE id = ?;";
static const char *SQL_SELECT_AGENT = "SELECT name FROM agent WHERE id = ?;";
static const char *SQL_SELECT_AGENTS = "SELECT id FROM agent WHERE id != 0;";
static const char *SQL_FIND_AGENT = "SELECT id FROM agent WHERE name = ? AND ip = ?;";

/* Insert agent. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_insert_agent(int id, const char *name, const char *ip, const char *key, const char *group) {
    int result = 0;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_INSERT_AGENT, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);
    sqlite3_bind_text(stmt, 2, name, -1, NULL);

    if (ip)
        sqlite3_bind_text(stmt, 3, ip, -1, NULL);
    else
        sqlite3_bind_null(stmt, 3);
    if (key)
        sqlite3_bind_text(stmt, 4, key, -1, NULL);
    else
        sqlite3_bind_null(stmt, 4);

    sqlite3_bind_text(stmt, 5, group ? group : DEFAULT_GROUP, -1, NULL);

    result = wdb_step(stmt) == SQLITE_DONE ? wdb_create_agent_db(id, name) : -1;
    sqlite3_finalize(stmt);
    wdb_close_global();
    return result;
}

/* Update agent name. It doesn't rename agent DB file. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_update_agent_name(int id, const char *name) {
    int result = 0;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_UPDATE_AGENT_NAME, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, name, -1, NULL);
    sqlite3_bind_int(stmt, 2, id);

    result = wdb_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    wdb_close_global();
    return result;
}

/* Update agent version. It opens and closes the DB. Returns number of affected rows or -1 on error. */
int wdb_update_agent_version(int id, const char *os, const char *version, const char *shared_sum) {
    int result = 0;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_UPDATE_AGENT_VERSION, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, os, -1, NULL);
    sqlite3_bind_text(stmt, 2, version, -1, NULL);
    sqlite3_bind_text(stmt, 3, shared_sum, -1, NULL);
    sqlite3_bind_int(stmt, 4, id);

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_changes(wdb_global) : -1;
    sqlite3_finalize(stmt);
    wdb_close_global();
    return result;
}

/* Update agent's last keepalive time. It opens and closes the DB. Returns number of affected rows or -1 on error. */
int wdb_update_agent_keepalive(int id, long keepalive) {
    int result = 0;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_UPDATE_AGENT_KEEPALIVE, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, keepalive);
    sqlite3_bind_int(stmt, 2, id);

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_changes(wdb_global) : -1;
    sqlite3_finalize(stmt);
    wdb_close_global();
    return result;
}

/* Delete agent. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_remove_agent(int id) {
    int result;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_DELETE_AGENT, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);

    result = wdb_step(stmt) == SQLITE_DONE ? wdb_remove_agent_db(id) : -1;
    sqlite3_finalize(stmt);
    wdb_close_global();
    return result;
}

/* Get name from agent. The string must be freed after using. Returns NULL on error. */
char* wdb_agent_name(int id) {
    sqlite3_stmt *stmt = NULL;
    char *result = NULL;

    if (wdb_open_global() < 0)
        return NULL;

    if (wdb_prepare(wdb_global, SQL_SELECT_AGENT, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return NULL;
    }

    sqlite3_bind_int(stmt, 1, id);

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        result = strdup((char*)sqlite3_column_text(stmt, 0));
        break;
    case SQLITE_DONE:
        result = NULL;
        break;
    default:
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        result = NULL;
    }

    sqlite3_finalize(stmt);
    wdb_close_global();
    return result;
}

/* Create database for agent from profile. Returns 0 on success or -1 on error. */
int wdb_create_agent_db(int id, const char *name) {
    const char *ROOT = "root";
    char path[OS_FLSIZE + 1];
    char buffer[4096];
    FILE *source;
    FILE *dest;
    size_t nbytes;
    int result = 0;
    uid_t uid;
    gid_t gid;

    if (!name)
        return -1;

    snprintf(path, OS_FLSIZE, "%s/%s", WDB_DIR, WDB_PROF_NAME);

    if (!(source = fopen(path, "r"))) {
        debug1("%s: Profile database not found, creating.", ARGV0);

        if (wdb_create_profile(path) < 0)
            return -1;

        // Retry to open

        if (!(source = fopen(path, "r"))) {
            merror("%s: Couldn't open profile '%s'.", ARGV0, path);
            return -1;
        }
    }

    snprintf(path, OS_FLSIZE, "%s%s/agents/%03d-%s.db", isChroot() ? "/" : "", WDB_DIR, id, name);

    if (!(dest = fopen(path, "w"))) {
        fclose(source);
        merror("%s: Couldn't create database '%s'.", ARGV0, path);
        return -1;
    }

    while (nbytes = fread(buffer, 1, 4096, source), nbytes) {
        if (fwrite(buffer, 1, nbytes, dest) != nbytes) {
            result = -1;
            break;
        }
    }

    fclose(source);
    fclose(dest);

    if (result < 0)
        return -1;

    uid = Privsep_GetUser(ROOT);
    gid = Privsep_GetGroup(GROUPGLOBAL);

    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror(USER_ERROR, ARGV0, ROOT, GROUPGLOBAL);
        return -1;
    }

    if (chown(path, uid, gid) < 0) {
        merror(CHOWN_ERROR, ARGV0, path, errno, strerror(errno));
        return -1;
    }

    if (chmod(path, 0660) < 0) {
        merror(CHMOD_ERROR, ARGV0, path, errno, strerror(errno));
        return -1;
    }

    return 0;
}

/* Create database for agent from profile. Returns 0 on success or -1 on error. */
int wdb_remove_agent_db(int id) {
    char path[OS_FLSIZE + 1];
    char path_aux[OS_FLSIZE + 1];
    char *name = wdb_agent_name(id);

    if (!name)
        return -1;

    snprintf(path, OS_FLSIZE, "%s%s/agents/%03d-%s.db", isChroot() ? "/" : "", WDB_DIR, id, name);
    free(name);

    if (!remove(path)) {
        snprintf(path_aux, OS_FLSIZE, "%s-shm", path);
        remove(path_aux);
        snprintf(path_aux, OS_FLSIZE, "%s-wal", path);
        remove(path_aux);
        return 0;
    } else
        return -1;
}

/* Get an array containint the ID of every agent (except 0), ended with -1 */
int* wdb_get_all_agents() {
    int i;
    int n = 1;
    int *array;
    sqlite3_stmt *stmt = NULL;

    if (!(array = malloc(sizeof(int)))) {
        merror("%s: ERROR: wdb_get_all_agents(): memory error", ARGV0);
        return NULL;
    }

    if (wdb_open_global() < 0) {
        free(array);
        return NULL;
    }

    if (wdb_prepare(wdb_global, SQL_SELECT_AGENTS, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        wdb_close_global();
        free(array);
        return NULL;
    }

    for (i = 0; wdb_step(stmt) == SQLITE_ROW; i++) {
        if (i + 1 == n) {
            int *newarray;

            if (!(newarray = realloc(array, sizeof(int) * (n *= 2)))) {
                merror("%s: ERROR: wdb_get_all_agents(): memory error", ARGV0);
                free(array);
                sqlite3_finalize(stmt);
                wdb_close_global();
                return NULL;
            }

            array = newarray;
        }

        array[i] = sqlite3_column_int(stmt, 0);
    }

    array[i] = -1;

    sqlite3_finalize(stmt);
    wdb_close_global();
    return array;
}

/* Find agent by name and address. Returns id if success or -1 on failure. */
int wdb_find_agent(const char *name, const char *ip) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_FIND_AGENT, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        wdb_close_global();
        return -1;
    }

    sqlite3_bind_text(stmt, 1, name, -1, NULL);
    sqlite3_bind_text(stmt, 2, ip, -1, NULL);

    result = wdb_step(stmt) == SQLITE_ROW ? sqlite3_column_int(stmt, 0) : -1;
    sqlite3_finalize(stmt);
    return result;
}

/* Get the file offset. Returns -1 on error or NULL. */
long wdb_get_agent_offset(int id_agent, int type) {
    int result;
    const char *sql;
    sqlite3_stmt *stmt;

    switch (type) {
    case WDB_SYSCHECK:
        sql = SQL_SELECT_FIM_OFFSET;
        break;
    case WDB_SYSCHECK_REGISTRY:
        sql = SQL_SELECT_REG_OFFSET;
        break;
    default:
        return -1;
    }

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, sql, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id_agent);
    result = wdb_step(stmt) == SQLITE_ROW ? sqlite3_column_int64(stmt, 0) : -1;

    sqlite3_finalize(stmt);
    wdb_close_global();
    return result;
}

/* Set the file offset. Returns number of affected rows, or -1 on failure. */
int wdb_set_agent_offset(int id_agent, int type, long offset) {
    int result;
    const char *sql;
    sqlite3_stmt *stmt;

    switch (type) {
    case WDB_SYSCHECK:
        sql = SQL_UPDATE_FIM_OFFSET;
        break;
    case WDB_SYSCHECK_REGISTRY:
        sql = SQL_UPDATE_REG_OFFSET;
        break;
    default:
        return -1;
    }

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, sql, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, offset);
    sqlite3_bind_int(stmt, 2, id_agent);

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_changes(wdb_global) : -1;
    sqlite3_finalize(stmt);
    wdb_close_global();
    return result;
}

/* Set agent updating status. Returns WDB_AGENT_*, or -1 on error. */
int wdb_get_agent_status(int id_agent) {
    int result;
    const char *status;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_SELECT_AGENT_STATUS, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id_agent);

    if (wdb_step(stmt) == SQLITE_ROW) {
        status = (const char*)sqlite3_column_text(stmt, 0);
        result = !strcmp(status, "empty") ? WDB_AGENT_EMPTY : !strcmp(status, "pending") ? WDB_AGENT_PENDING : WDB_AGENT_UPDATED;
    } else
        result = -1;

    sqlite3_finalize(stmt);
    wdb_close_global();
    return result;
}

/* Set agent updating status. Returns number of affected rows, or -1 on error. */
int wdb_set_agent_status(int id_agent, int status) {
    int result;
    const char *str_status;
    sqlite3_stmt *stmt;

    switch (status) {
    case WDB_AGENT_EMPTY:
        str_status = "empty";
        break;
    case WDB_AGENT_PENDING:
        str_status = "pending";
        break;
    case WDB_AGENT_UPDATED:
        str_status = "updated";
        break;
    default:
        return -1;
    }

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_UPDATE_AGENT_STATUS, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, str_status, -1, NULL);
    sqlite3_bind_int(stmt, 2, id_agent);

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_changes(wdb_global) : -1;
    sqlite3_finalize(stmt);
    wdb_close_global();
    return result;
}

/* Update agent group. It opens and closes the DB. Returns number of affected rows or -1 on error. */
int wdb_update_agent_group(int id, const char *group) {
    int result = 0;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_UPDATE_AGENT_GROUP, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group, -1, NULL);
    sqlite3_bind_int(stmt, 2, id);

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_changes(wdb_global) : -1;
    sqlite3_finalize(stmt);
    wdb_close_global();
    return result;
}
