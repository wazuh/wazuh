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

static const char *SQL_INSERT_AGENT = "INSERT INTO agent (id, name, ip, key, date_add) VALUES (?, ?, ?, ?, datetime(CURRENT_TIMESTAMP, 'localtime'));";
static const char *SQL_UPDATE_AGENT_NAME = "UPDATE agent SET name = ? WHERE id = ?;";
static const char *SQL_UPDATE_AGENT_VERSION = "UPDATE agent SET os = ?, version = ? WHERE id = ?;";
static const char *SQL_UPDATE_AGENT_KEEPALIVE = "UPDATE agent SET last_keepalive = datetime(CURRENT_TIMESTAMP, 'localtime') WHERE id = ?;";
static const char *SQL_DELETE_AGENT = "DELETE FROM agent WHERE id = ?;";
static const char *SQL_SELECT_AGENT = "SELECT name FROM agent WHERE id = ?;";
static const char *SQL_SELECT_AGENTS = "SELECT id FROM agent WHERE id != 0;";

/* Insert agent. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_insert_agent(int id, const char *name, const char *ip, const char *key) {
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

/* Update agent version info. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_update_agent_version(int id, const char *os, const char *version) {
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
    sqlite3_bind_int(stmt, 3, id);

    result = wdb_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    wdb_close_global();
    return result;
}

/* Update agent keepalive timestamp. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_update_agent_keepalive(int id) {
    int result = 0;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_UPDATE_AGENT_KEEPALIVE, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);

    result = wdb_step(stmt) == SQLITE_DONE ? 0 : -1;
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
    char path[OS_FLSIZE + 1];
    char buffer[4096];
    FILE *source;
    FILE *dest;
    size_t nbytes;
    int retval = 0;

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
            retval = -1;
            break;
        }
    }

    fclose(source);
    fclose(dest);

    return retval == 0 ? chmod(path, 0640) : retval;
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

    if (wdb_open_global() < 0)
        return NULL;

    if (wdb_prepare(wdb_global, SQL_SELECT_AGENTS, -1, &stmt, NULL)) {
        debug1("%s: SQLite: %s", ARGV0, sqlite3_errmsg(wdb_global));
        wdb_close_global();
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
