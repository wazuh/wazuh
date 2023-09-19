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

int wdb_agents_set_sys_osinfo_triaged(wdb_t *wdb){
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_OSINFO_SET_TRIAGED);

    if (stmt == NULL) {
        return OS_INVALID;
    }

    return wdb_exec_stmt_silent(stmt);
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

bool wdb_agents_find_cve(wdb_t *wdb, const char* cve, const char* reference){
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVES_FIND_CVE);

    if (stmt == NULL) {
        return FALSE;
    }

    sqlite3_bind_text(stmt, 1, cve, -1, NULL);
    sqlite3_bind_text(stmt, 2, reference, -1, NULL);

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

cJSON* wdb_agents_insert_vuln_cves(wdb_t *wdb,
                                   const char* name,
                                   const char* version,
                                   const char* architecture,
                                   const char* cve,
                                   const char* reference,
                                   const char* type,
                                   const char* status,
                                   bool check_pkg_existence,
                                   const char* severity,
                                   double cvss2_score,
                                   double cvss3_score,
                                   const char *external_references,
                                   const char *condition,
                                   const char *title,
                                   const char *published,
                                   const char *updated) {
    char* status_to_insert = NULL;

    cJSON* result = cJSON_CreateObject();
    if (!result) {
        return NULL;
    }

    if (wdb_agents_find_cve(wdb, cve, reference)) {
        cJSON_AddStringToObject(result, "action", "UPDATE");
    }
    else {
        cJSON_AddStringToObject(result, "action", "INSERT");
    }

    if (check_pkg_existence && !wdb_agents_find_package(wdb, reference)) {
        os_strdup(VULN_CVES_STATUS_OBSOLETE, status_to_insert);
    } else {
        os_strdup(status, status_to_insert);
    }

    // On UPDATE the status is replaced with VALID and any feed related field is also updated
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVES_INSERT);

    if (stmt) {
        sqlite3_bind_text(stmt, 1, name, -1, NULL);
        sqlite3_bind_text(stmt, 2, version, -1, NULL);
        sqlite3_bind_text(stmt, 3, architecture, -1, NULL);
        sqlite3_bind_text(stmt, 4, cve, -1, NULL);
        sqlite3_bind_text(stmt, 5, reference, -1, NULL);
        sqlite3_bind_text(stmt, 6, type, -1, NULL);
        sqlite3_bind_text(stmt, 7, status_to_insert, -1, NULL);
        if (severity) {
            sqlite3_bind_text(stmt, 8, severity, -1, NULL);
        } else {
            sqlite3_bind_null(stmt, 8);
        }
        sqlite3_bind_double(stmt, 9, cvss2_score);
        sqlite3_bind_double(stmt, 10, cvss3_score);
        if (external_references) {
            sqlite3_bind_text(stmt, 11, external_references, -1, NULL);
        } else {
            sqlite3_bind_null(stmt, 11);
        }
        if (condition) {
            sqlite3_bind_text(stmt, 12, condition, -1, NULL);
        } else {
            sqlite3_bind_null(stmt, 12);
        }
        if (title) {
            sqlite3_bind_text(stmt, 13, title, -1, NULL);
        } else {
            sqlite3_bind_null(stmt, 13);
        }
        if (published) {
            sqlite3_bind_text(stmt, 14, published, -1, NULL);
        } else {
            sqlite3_bind_null(stmt, 14);
        }
        if (updated) {
            sqlite3_bind_text(stmt, 15, updated, -1, NULL);
        } else {
            sqlite3_bind_null(stmt, 15);
        }

        if (OS_SUCCESS == wdb_exec_stmt_silent(stmt)) {
            cJSON_AddStringToObject(result, "status", "SUCCESS");
        }
        else {
            mdebug1("Exec statement error %s", sqlite3_errmsg(wdb->db));
            cJSON_AddStringToObject(result, "status", "ERROR");
        }
    }
    else {
        cJSON_AddStringToObject(result, "status", "ERROR");
    }

    os_free(status_to_insert);
    return result;
}

int wdb_agents_update_vuln_cves_status(wdb_t *wdb, const char* old_status, const char* new_status, const char* type) {
    sqlite3_stmt* stmt = NULL;

    if (old_status && new_status && !type) {
        bool update_all = (strcmp(old_status, "*") == 0);

        stmt = wdb_init_stmt_in_cache(wdb, update_all ? WDB_STMT_VULN_CVES_UPDATE_ALL : WDB_STMT_VULN_CVES_UPDATE);

        if (stmt == NULL) {
            return OS_INVALID;
        }

        if (update_all) {
            sqlite3_bind_text(stmt, 1, new_status, -1, NULL);
        } else {
            sqlite3_bind_text(stmt, 1, new_status, -1, NULL);
            sqlite3_bind_text(stmt, 2, old_status, -1, NULL);
        }
    }
    else if (!old_status && new_status && type){
        stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVES_UPDATE_BY_TYPE);

        if (stmt == NULL) {
            return OS_INVALID;
        }

        sqlite3_bind_text(stmt, 1, new_status, -1, NULL);
        sqlite3_bind_text(stmt, 2, type, -1, NULL);
    }
    else {
        return OS_INVALID;
    }

    return wdb_exec_stmt_silent(stmt);
}

int wdb_agents_remove_vuln_cves(wdb_t *wdb, const char* cve, const char* reference) {
    if (!cve || !reference) {
        mdebug1("Invalid data provided");
        return OS_INVALID;
    }

    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVES_DELETE_ENTRY);

    if (stmt == NULL) {
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, cve, -1, NULL);
    sqlite3_bind_text(stmt, 2, reference, -1, NULL);

    return wdb_exec_stmt_silent(stmt);
}

wdbc_result wdb_agents_remove_vuln_cves_by_status(wdb_t *wdb, const char* status, char **output) {
    wdbc_result wdb_res = WDBC_ERROR;

    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVES_SELECT_BY_STATUS);

    if (stmt == NULL) {
        return wdb_res;
    }

    //Prepare SQL query
    if (sqlite3_bind_text(stmt, 1, status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return wdb_res;
    }

    //Execute SQL query limited by size
    int sql_status = SQLITE_ERROR;
    cJSON* cves = wdb_exec_stmt_sized(stmt, WDB_MAX_RESPONSE_SIZE, &sql_status, STMT_MULTI_COLUMN);

    if (SQLITE_DONE == sql_status) wdb_res = WDBC_OK;
    else if (SQLITE_ROW == sql_status) wdb_res = WDBC_DUE;
    else {
        merror("Failed to retrieve vulnerabilities with status %s from the database", status);
        return wdb_res;
    }

    cJSON *cve = NULL;
    cJSON_ArrayForEach(cve, cves) {
        cJSON* json_cve_id = cJSON_GetObjectItem(cve,"cve");
        cJSON* json_reference = cJSON_GetObjectItem(cve,"reference");

        if (cJSON_IsString(json_cve_id) && cJSON_IsString(json_reference)) {
            //Delete the vulnerability
            if (OS_SUCCESS != wdb_agents_remove_vuln_cves(wdb, json_cve_id->valuestring, json_reference->valuestring)) {
                merror("Error removing vulnerability from the inventory database: %s", json_cve_id->valuestring);
                cJSON_Delete(cves);
                return WDBC_ERROR;
            }
        }
    }

    //Printing the results
    *output = cJSON_PrintUnformatted(cves);
    cJSON_Delete(cves);

    return wdb_res;
}

int wdb_agents_set_packages_triaged(wdb_t *wdb) {
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_SYS_PROGRAMS_SET_TRIAGED);
    if (!stmt) {
        return OS_INVALID;
    }

    return wdb_exec_stmt_silent(stmt);
}

int wdb_agents_send_packages(wdb_t *wdb, bool not_triaged_only) {
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, not_triaged_only ? WDB_STMT_SYS_PROGRAMS_GET_NOT_TRIAGED :  WDB_STMT_SYS_PROGRAMS_GET);
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

int wdb_agents_get_packages(wdb_t *wdb, bool not_triaged_only, cJSON** response) {
    cJSON* status_response = cJSON_CreateObject();
    if (!status_response) {
        return OS_MEMERR;
    }
    int status = OS_SUCCESS;

    int sync = wdbi_check_sync_status(wdb, WDB_SYSCOLLECTOR_PACKAGES);
    if (1 == sync) {
        if (OS_SUCCESS == (status = wdb_agents_send_packages(wdb, not_triaged_only))) {
            if (OS_SUCCESS == (status = wdb_agents_set_packages_triaged(wdb))){
                cJSON_AddStringToObject(status_response, "status", "SUCCESS");
            }
            else {
                cJSON_AddStringToObject(status_response, "status", "ERROR");
            }
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
