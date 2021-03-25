#include "wdb_agents.h"

int wdb_agents_find_package(wdb_t *wdb, const char* reference){
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_PROGRAM_FIND);

    if (stmt == NULL) {
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, reference, -1, NULL);

    switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:
        return 1;
        break;
    case SQLITE_DONE:
        return 0;
        break;
    default:
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_agents_find_cve(wdb_t *wdb, const char* cve, const char* reference){
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVE_FIND_CVE);

    if (stmt == NULL) {
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, cve, -1, NULL);
    sqlite3_bind_text(stmt, 2, reference, -1, NULL);

    switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:
        return 1;
        break;
    case SQLITE_DONE:
        return 0;
        break;
    default:
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_agents_insert_vuln_cve(wdb_t *wdb, 
                               const char* name, 
                               const char* version, 
                               const char* architecture, 
                               const char* cve,
                               const char* reference,
                               const char* type,
                               const char* status,
                               int check_pkg_existance) {
    
    int pkg_response = check_pkg_existance ? wdb_agents_find_package(wdb, reference) : 0;
    int res = 0;
    int result = 0;
    int cve_response = 0;

    if ((check_pkg_existance && pkg_response == 1) || !check_pkg_existance) {
        cve_response = wdb_agents_find_cve(wdb, cve, reference);
        if (cve_response != -1) {
            sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVE_INSERT);

            if (stmt == NULL) {
                res = OS_INVALID;
            }

            sqlite3_bind_text(stmt, 1, name, -1, NULL);
            sqlite3_bind_text(stmt, 2, version, -1, NULL);
            sqlite3_bind_text(stmt, 3, architecture, -1, NULL);
            sqlite3_bind_text(stmt, 4, cve, -1, NULL);
            sqlite3_bind_text(stmt, 5, reference, -1, NULL);
            sqlite3_bind_text(stmt, 6, type, -1, NULL);
            sqlite3_bind_text(stmt, 7, status, -1, NULL);

            res = wdb_exec_stmt_silent(stmt);

            if(cve_response == 1){
                if(res != OS_INVALID){
                    result = UPDATE_SUCCESS;
                } else {
                    result = UPDATE_ERROR;
                }
            } else if (cve_response == 0){
                if (res != OS_INVALID) {
                    result = INSERT_SUCCESS;
                } else {
                    result = INSERT_ERROR;
                }
            }
        } else {
            result = CVE_ERROR;
        }
    } else if(check_pkg_existance && pkg_response == 0){
        result = PACKAGE_NOT_FOUND;
    } 
    else {
        result = PACKAGE_ERROR;
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
