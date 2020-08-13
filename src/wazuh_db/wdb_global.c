/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"

// List of agent information fields in global DB
static const char *global_db_agent_fields[] = { 
        "config_sum",
        "ip",
        "manager_host",
        "merged_sum",
        "name",
        "node_name",
        "os_arch",
        "os_build",
        "os_codename",
        "os_major",
        "os_minor",
        "os_name",
        "os_platform",
        "os_uname",
        "os_version",
        "version",
        "last_keepalive",
        "fim_offset",
        "reg_offset",
        NULL
};

cJSON* wdb_global_get_agent_labels(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_LABELS_GET) < 0) {
        mdebug1("cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_LABELS_GET];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

int wdb_global_del_agent_labels(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_LABELS_DEL) < 0) {
        mdebug1("cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_LABELS_DEL];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_set_agent_label(wdb_t *wdb, int id, char* key, char* value) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_LABELS_SET) < 0) {
        mdebug1("cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_LABELS_SET];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 2, key, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 3, value, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_update_unsynced_agents(wdb_t *wdb,cJSON * json_agent){
    sqlite3_stmt *stmt = NULL;
    int n = 0;
    int agent_id = 0;
    cJSON *json_field = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_UPDATE_UNSYNCED_AGENTS) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_UPDATE_UNSYNCED_AGENTS];

     for (n = 0 ; global_db_agent_fields[n] ; n++){
        // Every column name of Global DB is stored in global_db_agent_fields 
        json_field = cJSON_GetObjectItemCaseSensitive(json_agent, global_db_agent_fields[n]);
        if (cJSON_IsNumber(json_field)){
            if (sqlite3_bind_int(stmt, n + 1 , json_field->valueint) != SQLITE_OK) {
                merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                return OS_INVALID;
            }
       
        } else if (cJSON_IsString(json_field) && json_field->valuestring != NULL) {
            if (sqlite3_bind_text(stmt, n + 1 , json_field->valuestring, -1, NULL) != SQLITE_OK) {
                merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                return OS_INVALID;
            }
        
        } else{
            if (sqlite3_bind_null(stmt, n+1) != SQLITE_OK) {
                merror("DB(%s) sqlite3_bind_null(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                return OS_INVALID;
            }
        }
    }

    if (sqlite3_bind_int(stmt, n+1, WDB_SYNCED) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    json_field = cJSON_GetObjectItemCaseSensitive(json_agent, "id");
    agent_id = cJSON_IsNumber(json_field) ? json_field->valueint : -1; 

    if (sqlite3_bind_int(stmt, n+2, agent_id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}
