/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * July 5, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"
#include "defs.h"

#ifdef WIN32
#define chown(x, y, z) 0
#endif

static const char *SQL_INSERT_AGENT = "INSERT INTO agent (id, name, ip, internal_key, date_add, `group`) VALUES (?, ?, ?, ?, datetime(CURRENT_TIMESTAMP, 'localtime'), ?);";
static const char *SQL_INSERT_AGENT_KEEP_DATE = "INSERT INTO agent (id, name, ip, internal_key, date_add, `group`) VALUES (?, ?, ?, ?, ?, ?);";
static const char *SQL_UPDATE_AGENT_NAME = "UPDATE agent SET name = ? WHERE id = ?;";
static const char *SQL_UPDATE_AGENT_VERSION = "UPDATE agent SET os_name = ?, os_version = ?, os_major = ?, os_minor = ?, os_codename = ?, os_platform = ?, os_build = ?, os_uname = ?, os_arch = ?, version = ?, config_sum = ?, merged_sum = ?, manager_host = ?, node_name = ? WHERE id = ?;";
static const char *SQL_UPDATE_AGENT_KEEPALIVE = "UPDATE agent SET last_keepalive = datetime(?, 'unixepoch', 'localtime') WHERE id = ?;";
static const char *SQL_SELECT_AGENT_STATUS = "SELECT status FROM agent WHERE id = ?;";
static const char *SQL_UPDATE_AGENT_STATUS = "UPDATE agent SET status = ? WHERE id = ?;";
static const char *SQL_UPDATE_AGENT_GROUP = "UPDATE agent SET `group` = ? WHERE id = ?;";
static const char *SQL_INSERT_AGENT_GROUP = "INSERT INTO `group` (name) VALUES(?)";
static const char *SQL_SELECT_AGENT_GROUP = "SELECT `group` FROM agent WHERE id = ?;";
static const char *SQL_INSERT_AGENT_BELONG = "INSERT INTO belongs (id_group, id_agent) VALUES(?, ?)";
static const char *SQL_DELETE_AGENT_BELONG = "DELETE FROM belongs WHERE id_agent = ?";
static const char *SQL_DELETE_GROUP_BELONG = "DELETE FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = ? );";
static const char *SQL_SELECT_FIM_OFFSET = "SELECT fim_offset FROM agent WHERE id = ?;";
static const char *SQL_SELECT_REG_OFFSET = "SELECT reg_offset FROM agent WHERE id = ?;";
static const char *SQL_UPDATE_FIM_OFFSET = "UPDATE agent SET fim_offset = ? WHERE id = ?;";
static const char *SQL_UPDATE_REG_OFFSET = "UPDATE agent SET reg_offset = ? WHERE id = ?;";
static const char *SQL_DELETE_AGENT = "DELETE FROM agent WHERE id = ?;";
static const char *SQL_SELECT_AGENT = "SELECT name FROM agent WHERE id = ?;";
static const char *SQL_SELECT_AGENTS = "SELECT id FROM agent WHERE id != 0;";
static const char *SQL_FIND_AGENT = "SELECT id FROM agent WHERE name = ? AND ip = ?;";
static const char *SQL_FIND_GROUP = "SELECT id FROM `group` WHERE name = ?;";
static const char *SQL_SELECT_GROUPS = "SELECT name FROM `group`;";
static const char *SQL_DELETE_GROUP = "DELETE FROM `group` WHERE name = ?;";

/* Insert agent. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_insert_agent(int id, const char *name, const char *ip, const char *key, const char *group, int keep_date) {
    int result = 0;
    sqlite3_stmt *stmt;
    const char * sql = SQL_INSERT_AGENT;
    char *date = NULL;

    if (wdb_open_global() < 0)
        return -1;

    if(keep_date) {
        sql = SQL_INSERT_AGENT_KEEP_DATE;
        date = get_agent_date_added(id);

        if(!date) {
            sql = SQL_INSERT_AGENT;
        }
    }

    if (wdb_prepare(wdb_global, sql, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        if(date){
            free(date);
        }
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

    if(date) {
        sqlite3_bind_text(stmt, 5, date, -1, NULL);
        sqlite3_bind_text(stmt, 6, group, -1, NULL);
    } else {
        sqlite3_bind_text(stmt, 5, group, -1, NULL);
    }

    result = wdb_step(stmt) == SQLITE_DONE ? wdb_create_agent_db(id, name) : -1;
    sqlite3_finalize(stmt);

    if(date) {
        free(date);
    }

    return result;
}

/* Update agent name. It doesn't rename agent DB file. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_update_agent_name(int id, const char *name) {
    int result = 0;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_UPDATE_AGENT_NAME, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, name, -1, NULL);
    sqlite3_bind_int(stmt, 2, id);

    result = wdb_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);

    return result;
}

/* Update agent version. It opens and closes the DB. Returns number of affected rows or -1 on error. */
int wdb_update_agent_version(int id, const char *os_name, const char *os_version, const char *os_major, const char *os_minor, const char *os_codename, const char *os_platform, const char *os_build, const char *os_uname, const char *os_arch, const char *version, const char *config_sum, const char *merged_sum, const char *manager_host, const char *node_name) {
    int result = 0;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_UPDATE_AGENT_VERSION, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, os_name, -1, NULL);
    sqlite3_bind_text(stmt, 2, os_version, -1, NULL);
    sqlite3_bind_text(stmt, 3, os_major, -1, NULL);
    sqlite3_bind_text(stmt, 4, os_minor, -1, NULL);
    sqlite3_bind_text(stmt, 5, os_codename, -1, NULL);
    sqlite3_bind_text(stmt, 6, os_platform, -1, NULL);
    sqlite3_bind_text(stmt, 7, os_build, -1, NULL);
    sqlite3_bind_text(stmt, 8, os_uname, -1, NULL);
    sqlite3_bind_text(stmt, 9, os_arch, -1, NULL);
    sqlite3_bind_text(stmt, 10, version, -1, NULL);
    sqlite3_bind_text(stmt, 11, config_sum, -1, NULL);
    sqlite3_bind_text(stmt, 12, merged_sum, -1, NULL);
    sqlite3_bind_text(stmt, 13, manager_host, -1, NULL);
    sqlite3_bind_text(stmt, 14, node_name, -1, NULL);
    sqlite3_bind_int(stmt, 15, id);

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_changes(wdb_global) : -1;
    sqlite3_finalize(stmt);

    return result;
}

/* Update agent's last keepalive time. It opens and closes the DB. Returns number of affected rows or -1 on error. */
int wdb_update_agent_keepalive(int id, long keepalive) {
    int result = 0;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_UPDATE_AGENT_KEEPALIVE, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, keepalive);
    sqlite3_bind_int(stmt, 2, id);

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_changes(wdb_global) : -1;
    sqlite3_finalize(stmt);

    return result;
}

/* Delete agent. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_remove_agent(int id) {
    int result;
    sqlite3_stmt *stmt;
    char * name;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_DELETE_AGENT, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        return -1;
    }

    name = wdb_agent_name(id);

    sqlite3_bind_int(stmt, 1, id);
    result = wdb_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);

    result = result && name ? wdb_remove_agent_db(id, name) : -1;

    free(name);
    return result;
}

/* Get name from agent. The string must be freed after using. Returns NULL on error. */
char* wdb_agent_name(int id) {
    sqlite3_stmt *stmt = NULL;
    char *result = NULL;

    if (wdb_open_global() < 0)
        return NULL;

    if (wdb_prepare(wdb_global, SQL_SELECT_AGENT, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
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
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        result = NULL;
    }

    sqlite3_finalize(stmt);

    return result;
}

/* Get group from agent. The string must be freed after using. Returns NULL on error. */
char* wdb_agent_group(int id) {
    sqlite3_stmt *stmt = NULL;
    char *result = NULL;

    if (wdb_open_global() < 0)
        return NULL;

    if (wdb_prepare(wdb_global, SQL_SELECT_AGENT_GROUP, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        return NULL;
    }

    sqlite3_bind_int(stmt, 1, id);

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        result = (char*)sqlite3_column_text(stmt, 0);
        if(result){
            result = strdup((char*)sqlite3_column_text(stmt, 0));
        }
        break;
    case SQLITE_DONE:
        result = NULL;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        result = NULL;
    }

    sqlite3_finalize(stmt);

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
        mdebug1("Profile database not found, creating.");

        if (wdb_create_profile(path) < 0)
            return -1;

        // Retry to open

        if (!(source = fopen(path, "r"))) {
            merror("Couldn't open profile '%s'.", path);
            return -1;
        }
    }

    snprintf(path, OS_FLSIZE, "%s%s/agents/%03d-%s.db", isChroot() ? "/" : "", WDB_DIR, id, name);

    if (!(dest = fopen(path, "w"))) {
        fclose(source);
        merror("Couldn't create database '%s'.", path);
        return -1;
    }

    while (nbytes = fread(buffer, 1, 4096, source), nbytes) {
        if (fwrite(buffer, 1, nbytes, dest) != nbytes) {
            result = -1;
            break;
        }
    }

    fclose(source);
    if (fclose(dest) == -1) {
        merror("Couldn't write/close file %s completely ", path);
        return -1;
    }

    if (result < 0)
        return -1;

    uid = Privsep_GetUser(ROOT);
    gid = Privsep_GetGroup(GROUPGLOBAL);

    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror(USER_ERROR, ROOT, GROUPGLOBAL);
        return -1;
    }

    if (chown(path, uid, gid) < 0) {
        merror(CHOWN_ERROR, path, errno, strerror(errno));
        return -1;
    }

    if (chmod(path, 0660) < 0) {
        merror(CHMOD_ERROR, path, errno, strerror(errno));
        return -1;
    }

    return 0;
}

/* Create database for agent from profile. Returns 0 on success or -1 on error. */
int wdb_remove_agent_db(int id, const char * name) {
    char path[OS_FLSIZE + 1];
    char path_aux[OS_FLSIZE + 1];

    snprintf(path, OS_FLSIZE, "%s%s/agents/%03d-%s.db", isChroot() ? "/" : "", WDB_DIR, id, name);

    if (!remove(path)) {
        snprintf(path_aux, OS_FLSIZE, "%s-shm", path);
        if (remove(path_aux) < 0) {
            mdebug2(DELETE_ERROR, path_aux, errno, strerror(errno));
        }
        snprintf(path_aux, OS_FLSIZE, "%s-wal", path);
        if (remove(path_aux) < 0) {
            mdebug2(DELETE_ERROR, path_aux, errno, strerror(errno));
        }
        return 0;
    } else
        return -1;
}

/* Get an array containing the ID of every agent (except 0), ended with -1 */
int* wdb_get_all_agents() {
    int i;
    int n = 1;
    int *array;
    sqlite3_stmt *stmt = NULL;

    if (!(array = malloc(sizeof(int)))) {
        merror("wdb_get_all_agents(): memory error");
        return NULL;
    }

    if (wdb_open_global() < 0) {
        free(array);
        return NULL;
    }

    if (wdb_prepare(wdb_global, SQL_SELECT_AGENTS, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        wdb_close_global();
        free(array);
        return NULL;
    }

    for (i = 0; wdb_step(stmt) == SQLITE_ROW; i++) {
        if (i + 1 == n) {
            int *newarray;

            if (!(newarray = realloc(array, sizeof(int) * (n *= 2)))) {
                merror("wdb_get_all_agents(): memory error");
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

    return array;
}

/* Find agent by name and address. Returns id if success or -1 on failure. */
int wdb_find_agent(const char *name, const char *ip) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_FIND_AGENT, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
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
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id_agent);
    result = wdb_step(stmt) == SQLITE_ROW ? sqlite3_column_int64(stmt, 0) : -1;
    sqlite3_finalize(stmt);

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
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, offset);
    sqlite3_bind_int(stmt, 2, id_agent);

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_changes(wdb_global) : -1;
    sqlite3_finalize(stmt);

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
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id_agent);

    if (wdb_step(stmt) == SQLITE_ROW) {
        status = (const char*)sqlite3_column_text(stmt, 0);
        result = !strcmp(status, "empty") ? WDB_AGENT_EMPTY : !strcmp(status, "pending") ? WDB_AGENT_PENDING : WDB_AGENT_UPDATED;
    } else
        result = -1;

    sqlite3_finalize(stmt);

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
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, str_status, -1, NULL);
    sqlite3_bind_int(stmt, 2, id_agent);

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_changes(wdb_global) : -1;
    sqlite3_finalize(stmt);

    return result;
}

/* Update agent group. It opens and closes the DB. Returns number of affected rows or -1 on error. */
int wdb_update_agent_group(int id, char *group) {
    int result = 0;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_UPDATE_AGENT_GROUP, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group, -1, NULL);
    sqlite3_bind_int(stmt, 2, id);

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_changes(wdb_global) : -1;
    sqlite3_finalize(stmt);

    if(wdb_update_agent_multi_group(id,group) < 0){
        return -1;
    }

    return result;
}

/* Update agent multi group. It opens and closes the DB. Returns number of affected rows or -1 on error. */
int wdb_update_agent_multi_group(int id, char *group) {
    int result = 0;

    /* Wipe out the agent multi groups relation for this agent */
    if (wdb_delete_agent_belongs(id) < 0) {
        return -1;
    }

    /* Update the belongs table if multi group */
    const char delim[2] = ",";
    if (group) {
        char *multi_group;

        multi_group = strchr(group, MULTIGROUP_SEPARATOR);

        if (multi_group) {

            /* Get the first group */
            multi_group = strtok(group, delim);

            while( multi_group != NULL ) {

                /* Update de groups table */
                int id_group = wdb_find_group(multi_group);

                if(id_group <= 0){
                    id_group = wdb_insert_group(multi_group);
                }

                if (wdb_update_agent_belongs(id_group,id) < 0){
                    return -1;
                }

                multi_group = strtok(NULL, delim);
            }
        } else {

            /* Update de groups table */
            int id_group = wdb_find_group(group);

            if(id_group <= 0){
                id_group = wdb_insert_group(group);
            }

            if ( wdb_update_agent_belongs(id_group,id) < 0){
                return -1;
            }
        }
    }

    return result;
}

/* Find group by name. Returns id if success or -1 on failure. */
int wdb_find_group(const char *name) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_FIND_GROUP, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        wdb_close_global();
        return -1;
    }

    sqlite3_bind_text(stmt, 1, name, -1, NULL);

    result = wdb_step(stmt) == SQLITE_ROW ? sqlite3_column_int(stmt, 0) : -1;
    sqlite3_finalize(stmt);
    return result;
}

/* Insert a new group. Returns id if success or -1 on failure. */
int wdb_insert_group(const char *name) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_INSERT_AGENT_GROUP, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        wdb_close_global();
        return -1;
    }

    sqlite3_bind_text(stmt, 1, name, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE)
        result = (int)sqlite3_last_insert_rowid(wdb_global);
    else {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        result = -1;
    }

    sqlite3_finalize(stmt);
    return result;
}

/* Update agent belongs table. It opens and closes the DB. Returns number of affected rows or -1 on error. */
int wdb_update_agent_belongs(int id_group, int id_agent) {
    int result = 0;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_INSERT_AGENT_BELONG, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id_group);
    sqlite3_bind_int(stmt, 2, id_agent);

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_changes(wdb_global) : -1;
    sqlite3_finalize(stmt);

    return result;
}

/* Delete agent belongs table. It opens and closes the DB. Returns number of affected rows or -1 on error. */
int wdb_delete_agent_belongs(int id_agent) {
    int result = 0;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_DELETE_AGENT_BELONG, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id_agent);

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_changes(wdb_global) : -1;
    sqlite3_finalize(stmt);

    return result;
}

int wdb_update_groups(const char *dirname) {
    int result =  0;
    int i;
    int n = 1;
    char **array;
    sqlite3_stmt *stmt = NULL;

    if (!(array = (char**) calloc(1, sizeof(char*)))) {
        merror("wdb_update_groups(): memory error");
        return -1;
    }

    if (wdb_open_global() < 0) {
        free(array);
        return -1;
    }

    if (wdb_prepare(wdb_global, SQL_SELECT_GROUPS, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        wdb_close_global();
        free(array);
        return -1;
    }

    for (i = 0; wdb_step(stmt) == SQLITE_ROW; i++) {
        if (i + 1 == n) {
            char **newarray;

            if (!(newarray = (char **)realloc(array, sizeof(char *) * (n *= 2)))) {
                merror("wdb_update_groups(): memory error");
                sqlite3_finalize(stmt);
                wdb_close_global();
                return -1;
            }

            array = newarray;
        }
        os_strdup((char*)sqlite3_column_text(stmt, 0),array[i]);
    }

    array[i] = NULL;

    sqlite3_finalize(stmt);

    for(i=0;array[i];i++){
        /* Check if the group exists in dir */
        char group_path[PATH_MAX + 1] = {0};
        DIR *dp;

        if (snprintf(group_path, PATH_MAX + 1, "%s/%s", dirname,array[i]) > PATH_MAX) {
            merror("At wdb_update_groups(): path too long.");
            continue;
        }

        dp = opendir(group_path);

        /* Group doesnt exists anymore, delete it */
        if (!dp) {
            if (wdb_remove_group_db((char *)array[i]) < 0){
                free_strarray(array);
                return -1;
            }
        }
        closedir(dp);
    }

    free_strarray(array);

    /* Add new groups from the folder /etc/shared if they dont exists on database */
    DIR *dir;
    struct dirent *dirent;

    if (!(dir = opendir(dirname))) {
        mterror(WDB_DATABASE_LOGTAG, "Couldn't open directory '%s': %s.", dirname, strerror(errno));
        return -1;
    }

    while ((dirent = readdir(dir))){
        if (dirent->d_name[0] != '.'){
            char path[PATH_MAX];
            snprintf(path,PATH_MAX,"%s/%s",dirname,dirent->d_name);

            if (!IsDir(path)) {
                if(wdb_find_group(dirent->d_name) <= 0){
                    wdb_insert_group(dirent->d_name);
                }
            }
        }
    }
    closedir(dir);

    return result;
}

/* Delete group from belongs table. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_remove_group_from_belongs_db(const char *name) {

    int result;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    // Delete from belongs
    if (wdb_prepare(wdb_global, SQL_DELETE_GROUP_BELONG, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, name, -1, NULL);

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_changes(wdb_global) : -1;
    sqlite3_finalize(stmt);

    return result;
}

/* Delete group. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_remove_group_db(const char *name) {

    if(wdb_remove_group_from_belongs_db(name) == -1){
        merror("At wdb_remove_group_from_belongs_db(): couldn't delete '%s' from 'belongs' table.", name);
        return -1;
    }

    int result;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_DELETE_GROUP, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, name, -1, NULL);

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_changes(wdb_global) : -1;
    sqlite3_finalize(stmt);

    return result;
}

int wdb_agent_belongs_first_time(){
    int i;
    char *group;
    int *agents;

    if ((agents = wdb_get_all_agents())) {

        for (i = 0; agents[i] != -1; i++) {
            group = wdb_agent_group(agents[i]);

            if(group){
                wdb_update_agent_multi_group(agents[i],group);
                free(group);
            }
        }
        free(agents);
    }

    return 0;
}

char *get_agent_date_added(int agent_id){
    char path[PATH_MAX + 1] = {0};
    char line[OS_BUFFER_SIZE] = {0};
    char * sep;
    FILE *fp;

    snprintf(path,PATH_MAX,"%s", isChroot() ? TIMESTAMP_FILE : DEFAULTDIR TIMESTAMP_FILE);

    fp = fopen(path, "r");

    if (!fp) {
        return NULL;
    }

    while (fgets(line, OS_BUFFER_SIZE, fp)) {
        if (sep = strchr(line, ' '), sep) {
            *sep = '\0';
        } else {
            continue;
        }

        if(atoi(line) == agent_id){
            /* Extract date */
            char **data;
            char * date = NULL;
            *sep = ' ';

            data = OS_StrBreak(' ',line,5);

            if(data == NULL) {
                fclose(fp);
                return NULL;
            }

            /* Date is 3 and 4 */
            wm_strcat(&date,data[3],' ');
            wm_strcat(&date,data[4],' ');

            if(date == NULL) {
                fclose(fp);
                free_strarray(data);
                return NULL;
            }

            char *endl = strchr(date, '\n');

            if (endl) {
                *endl = '\0';
            }

            fclose(fp);
            free_strarray(data);
            return date;
        }
    }

    fclose(fp);
    return NULL;
}