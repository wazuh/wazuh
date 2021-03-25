#include "wdb_agents.h"

bool wdb_agents_find_package(wdb_t *wdb, const char* reference){
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_PROGRAM_FIND);

    if (stmt == NULL) {
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, reference, -1, NULL);

    switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:
        return TRUE;
    case SQLITE_DONE:
        return FALSE;
    default:
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return FALSE;
    }
}

bool wdb_agents_find_cve(wdb_t *wdb, const char* cve, const char* reference){
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVE_FIND_CVE);

    if (stmt == NULL) {
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, cve, -1, NULL);
    sqlite3_bind_text(stmt, 2, reference, -1, NULL);

    switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:
        return TRUE;
    case SQLITE_DONE:
        return FALSE;
    default:
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return FALSE;
    }
}

cJSON* wdb_agents_insert_vuln_cve(wdb_t *wdb,
                               const char* name,
                               const char* version,
                               const char* architecture,
                               const char* cve,
                               const char* reference,
                               const char* type,
                               const char* status,
                               bool check_pkg_existance) {

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

    if (check_pkg_existance && !wdb_agents_find_package(wdb, reference)) {
        cJSON_AddStringToObject(result, "status", "PKG_NOT_FOUND");
    }
    else {
        sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVE_INSERT);

        if (stmt) {
            sqlite3_bind_text(stmt, 1, name, -1, NULL);
            sqlite3_bind_text(stmt, 2, version, -1, NULL);
            sqlite3_bind_text(stmt, 3, architecture, -1, NULL);
            sqlite3_bind_text(stmt, 4, cve, -1, NULL);
            sqlite3_bind_text(stmt, 5, reference, -1, NULL);
            sqlite3_bind_text(stmt, 6, type, -1, NULL);
            sqlite3_bind_text(stmt, 7, status, -1, NULL);

            if (OS_SUCCESS == wdb_exec_stmt_silent(stmt)) {
                cJSON_AddStringToObject(result, "status", "SUCCESS");
            }
            else {
                mdebug1("Exec statement error %s", sqlite3_errmsg(wdb->db));
                cJSON_AddStringToObject(result, "status", "ERROR");
            }
        }
        else {
            mdebug1("Cannot cache statement");
            cJSON_AddStringToObject(result, "status", "ERROR");
        }
    }

    return result;
}

int wdb_agents_update_status_vuln_cves(wdb_t *wdb, const char* old_status, const char* new_status) {

    bool update_all = (strcmp(old_status, "*") == 0);

    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, update_all ? WDB_STMT_VULN_CVES_UPDATE_ALL : WDB_STMT_VULN_CVES_UPDATE);

    if (stmt == NULL) {
        return OS_INVALID;
    }

    if (update_all) {
        sqlite3_bind_text(stmt, 1, new_status, -1, NULL);
    } else {
        sqlite3_bind_text(stmt, 1, new_status, -1, NULL);
        sqlite3_bind_text(stmt, 2, old_status, -1, NULL);
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
    sqlite3_stmt* stmt = NULL;
    unsigned response_size = 2; //Starts with "[]" size
    wdbc_result wdb_res = WDBC_UNKNOWN;

    os_calloc(WDB_MAX_RESPONSE_SIZE, sizeof(char), *output);
    char *response_aux = *output;

    //Prepare SQL query
    if (stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVES_SELECT_BY_STATUS), !stmt) {
        mdebug1("Cannot cache statement");
        snprintf(*output, WDB_MAX_RESPONSE_SIZE, "%s", "Cannot cache statement");
        return WDBC_ERROR;
    }
    if (sqlite3_bind_text(stmt, 1, status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        snprintf(*output, WDB_MAX_RESPONSE_SIZE, "%s", "Cannot bind sql statement");
        return WDBC_ERROR;
    }

    //Add array start
    *response_aux++ = '[';

    while (wdb_res == WDBC_UNKNOWN) {
        //Get vulnerabilities info
        cJSON* sql_vulns_response = wdb_exec_stmt(stmt);

        if (sql_vulns_response && sql_vulns_response->child) {
            cJSON* json_vuln = sql_vulns_response->child;
            cJSON* json_cve = cJSON_GetObjectItem(json_vuln,"cve");
            cJSON* json_reference = cJSON_GetObjectItem(json_vuln,"reference");

            if (cJSON_IsString(json_cve) && cJSON_IsString(json_reference)) {
                //Print vulnerability info
                char *vuln_str = cJSON_PrintUnformatted(json_vuln);
                unsigned vuln_len = strlen(vuln_str);

                //Check if new vulnerability fits in response
                if (response_size+vuln_len+1 < WDB_MAX_RESPONSE_SIZE) {
                    //Delete the vulnerability
                    if (OS_SUCCESS != wdb_agents_remove_vuln_cves(wdb, json_cve->valuestring, json_reference->valuestring)) {
                        merror("Error removing vulnerability from the inventory database: %s", json_cve->valuestring);
                        wdb_res = WDBC_ERROR;
                    }
                    else {
                        //Add new vulnerability
                        memcpy(response_aux, vuln_str, vuln_len);
                        response_aux+=vuln_len;
                        //Add separator
                        *response_aux++ = ',';
                        //Save size
                        response_size += vuln_len+1;
                    }
                }
                else {
                    //Pending vulnerabilities but buffer is full
                    wdb_res = WDBC_DUE;
                }
                os_free(vuln_str);
            }
        }
        else {
            //All vulnerabilities have been obtained
            wdb_res = WDBC_OK;
        }
        cJSON_Delete(sql_vulns_response);
    }

    if (wdb_res != WDBC_ERROR) {
        if (response_size > 2) {
            //Remove last ','
            response_aux--;
        }
        //Add array end
        *response_aux = ']';
    }
    return wdb_res;
}

int wdb_agents_clear_vuln_cves(wdb_t *wdb) {

    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVES_CLEAR);
    if (stmt == NULL) {
        return OS_INVALID;
    }

    return wdb_exec_stmt_silent(stmt);
}
