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

static const char *SQL_INSERT_AGENT = "INSERT INTO agent (id, name, ip, key) VALUES (?, ?, ?, ?);";
static const char *SQL_UPDATE_AGENT = "UPDATE agent SET os = ?, version = ? WHERE id = ?;";
static const char *SQL_DISABLE_AGENT = "UPDATE agent SET enabled = 0 WHERE id = ?;";
static const char *SQL_DELETE_AGENT = "DELETE FROM agent WHERE id = ?;";
static const char *SQL_SELECT_AGENT = "SELECT name FROM agent WHERE id = ?;";

/* Insert agent. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_insert_agent(int id, const char *name, const char *ip, const char *key) {
    int result = 0;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (sqlite3_prepare_v2(wdb_global, SQL_INSERT_AGENT, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);
    sqlite3_bind_text(stmt, 2, name, -1, NULL);
    sqlite3_bind_text(stmt, 3, ip, -1, NULL);
    sqlite3_bind_text(stmt, 4, key, -1, NULL);

    result = sqlite3_step(stmt) == SQLITE_DONE ? wdb_create_agent_db(id, name) : -1;
    sqlite3_finalize(stmt);
    wdb_close_global();
    return result;
}

/* Update agent info. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_update_agent(int id, const char *os, const char *version) {
    int result = 0;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (sqlite3_prepare_v2(wdb_global, SQL_UPDATE_AGENT, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, os, -1, NULL);
    sqlite3_bind_text(stmt, 2, version, -1, NULL);
    sqlite3_bind_int(stmt, 3, id);

    result = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    wdb_close_global();
    return result;
}

/* Disable agent. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_disable_agent(int id) {
    int result = 0;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (sqlite3_prepare_v2(wdb_global, SQL_DISABLE_AGENT, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);

    result = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
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

    if (sqlite3_prepare_v2(wdb_global, SQL_DELETE_AGENT, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);

    result = sqlite3_step(stmt) == SQLITE_DONE ? wdb_remove_agent_db(id) : -1;
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

    if (sqlite3_prepare_v2(wdb_global, SQL_SELECT_AGENT, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return NULL;
    }

    sqlite3_bind_int(stmt, 1, id);

    switch (sqlite3_step(stmt)) {
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
    char path[OS_FLSIZE + 1];
    char buffer[4096];
    FILE *source;
    FILE *dest;
    size_t nbytes;
    int retval = 0;

    if (!name)
        return -1;

    snprintf(path, OS_FLSIZE, "%s/%s", WDB_DIR, WDB_GLOB_NAME);

    if (!(source = fopen(path, "r"))) {
        debug1("%s: Couldn't open profile '%s'.", ARGV0, path);
        return -1;
    }

    snprintf(path, OS_FLSIZE, "%s%s/agents/%d-%s.db", isChroot() ? "/" : "", WDB_DIR, id, name);

    if (!(dest = fopen(path, "w"))) {
        debug1("%s: Couldn't create database '%s'.", ARGV0, path);
        return -1;
    }

    while (nbytes = fread(buffer, 1, 4096, source), nbytes) {
        if (fwrite(buffer, 1, nbytes, dest) != nbytes) {
            retval = -1;
            break;
        }
    }

    fclose(source);
    fclose(dest);
    return retval;
}

/* Create database for agent from profile. Returns 0 on success or -1 on error. */
int wdb_remove_agent_db(int id) {
    char path[OS_FLSIZE + 1];
    char path_aux[OS_FLSIZE + 1];
    char *name = wdb_agent_name(id);

    if (!name)
        return -1;

    snprintf(path, OS_FLSIZE, "%s%s/agents/%d-%s.db", isChroot() ? "/" : "", WDB_DIR, id, name);
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
