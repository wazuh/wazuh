/*
 * Wazuh DB helper module for agents database
 * Copyright (C) 2015, Wazuh Inc.
 * February 10, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb_agents.h"
#include "cJSON.h"
#include "os_err.h"
#include "wazuh_db/wdb.h"

cJSON* wdb_agents_get_sys_osinfo(wdb_t *wdb){
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_OSINFO_GET);

    if (stmt == NULL) {
        return NULL;
    }

    cJSON* result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

bool wdb_agents_find_package(wdb_t *wdb, const char* reference){
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_PROGRAM_FIND);

    if (stmt == NULL) {
        return FALSE;
    }

    sqlite3_bind_text(stmt, 1, reference, -1, NULL);

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        return TRUE;
    case SQLITE_DONE:
        return FALSE;
    default:
        mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
        return FALSE;
    }
}

int wdb_agents_send_packages(wdb_t *wdb) {
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_SYS_PROGRAMS_GET);
    if (!stmt) {
        return OS_INVALID;
    }

    return wdb_exec_stmt_send(stmt, wdb->peer);
}

int wdb_agents_send_hotfixes(wdb_t *wdb) {
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_SYS_HOTFIXES_GET);
    if (!stmt) {
        return OS_INVALID;
    }

    return wdb_exec_stmt_send(stmt, wdb->peer);
}

int wdb_agents_get_packages(wdb_t *wdb, cJSON** response) {
    cJSON* status_response = cJSON_CreateObject();
    if (!status_response) {
        return OS_MEMERR;
    }
    int status = OS_SUCCESS;

    int sync = wdbi_check_sync_status(wdb, WDB_SYSCOLLECTOR_PACKAGES);
    if (1 == sync) {
        if (OS_SUCCESS == (status = wdb_agents_send_packages(wdb))) {
            cJSON_AddStringToObject(status_response, "status", "SUCCESS");
        }
        else {
            cJSON_AddStringToObject(status_response, "status", "ERROR");
        }
    }
    else if (0 == sync){
        cJSON_AddStringToObject(status_response, "status", "NOT_SYNCED");
    }
    else {
        cJSON_AddStringToObject(status_response, "status", "ERROR");
        status = OS_INVALID;
    }

    *response = status_response;
    return status;
}

int wdb_agents_get_hotfixes(wdb_t *wdb,cJSON** response) {
    cJSON* status_response = cJSON_CreateObject();
    if (!status_response) {
        return OS_MEMERR;
    }
    int status = OS_SUCCESS;

    int sync = wdbi_check_sync_status(wdb, WDB_SYSCOLLECTOR_HOTFIXES);
    if (1 == sync) {
        if (OS_SUCCESS == (status = wdb_agents_send_hotfixes(wdb))) {
            cJSON_AddStringToObject(status_response, "status", "SUCCESS");
        }
        else{
            cJSON_AddStringToObject(status_response, "status", "ERROR");
        }
    }
    else if (0 == sync){
        cJSON_AddStringToObject(status_response, "status", "NOT_SYNCED");
    }
    else {
        cJSON_AddStringToObject(status_response, "status", "ERROR");
        status = OS_INVALID;
    }

    *response = status_response;
    return status;
}
