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
        merror("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
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
        merror("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
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

int wdb_agents_clear_vuln_cve(wdb_t *wdb) {

    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVE_CLEAR);
    if (stmt == NULL) {
        return OS_INVALID;
    }

    return wdb_exec_stmt_silent(stmt);
}

int wdb_agents_update_status_vuln_cve(wdb_t *wdb, const char* old_status, const char* new_status) {

    bool update_all = (strcmp(old_status, "*") == 0);

    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, update_all ? WDB_STMT_VULN_CVE_UPDATE_ALL : WDB_STMT_VULN_CVE_UPDATE);

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
