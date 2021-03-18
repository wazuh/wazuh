#include "wdb_agents.h"

int wdb_agents_insert_vuln_cve(wdb_t *wdb, const char* name, const char* version, const char* architecture, const char* cve) {

    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVE_INSERT);
    if (stmt == NULL) {
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, name, -1, NULL);
    sqlite3_bind_text(stmt, 2, version, -1, NULL);
    sqlite3_bind_text(stmt, 3, architecture, -1, NULL);
    sqlite3_bind_text(stmt, 4, cve, -1, NULL);

    return wdb_exec_stmt_silent(stmt);
}

int wdb_agents_clear_vuln_cve(wdb_t *wdb) {

    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVE_CLEAR);
    if (stmt == NULL) {
        return OS_INVALID;
    }

    return wdb_exec_stmt_silent(stmt);
}

int wdb_agents_update_vuln_cve(wdb_t *wdb, const char* old_status, const char* new_status) {
    sqlite3_stmt* stmt = NULL;
    
    if (strcmp(old_status, "*") == 0) {
        stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVE_UPDATE_ALL);
    } else {
        stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_VULN_CVE_UPDATE);
    }
    
    if (stmt == NULL) {
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, new_status, -1, NULL);
    sqlite3_bind_text(stmt, 2, old_status, -1, NULL);

    return wdb_exec_stmt_silent(stmt);
}
