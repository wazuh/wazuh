#include "wdb_agents.h"

int wdb_agents_insert_vuln_cves(wdb_t *wdb, const char* name, const char* version, const char* architecture, const char* cve) {

    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVES_INSERT);
    if (stmt == NULL) {
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, name, -1, NULL);
    sqlite3_bind_text(stmt, 2, version, -1, NULL);
    sqlite3_bind_text(stmt, 3, architecture, -1, NULL);
    sqlite3_bind_text(stmt, 4, cve, -1, NULL);

    return wdb_exec_stmt_silent(stmt);
}

int wdb_agents_update_status_vuln_cves(wdb_t *wdb, const char* old_status, const char* new_status, const char* type) {
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

wdbc_result wdb_agents_remove_by_status_vuln_cves(wdb_t *wdb, const char* status, char **output) {
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
    cJSON* cves = wdb_exec_stmt_sized(stmt, WDB_MAX_RESPONSE_SIZE, &sql_status);

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

int wdb_agents_clear_vuln_cves(wdb_t *wdb) {

    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVES_CLEAR);
    if (stmt == NULL) {
        return OS_INVALID;
    }

    return wdb_exec_stmt_silent(stmt);
}
