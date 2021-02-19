#include "wdb_agents.h"

int wdb_agents_insert_vuln_cve(wdb_t *wdb, const char* name, const char* version, const char* architecture, const char* cve) {

    sqlite3_stmt* stmt = wdb_start_cached_transaction(wdb, WDB_STMT_VULN_CVE_INSERT);
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

    sqlite3_stmt* stmt = wdb_start_cached_transaction(wdb, WDB_STMT_VULN_CVE_CLEAR);
    if (stmt == NULL) {
        return OS_INVALID;
    }

    return wdb_exec_stmt_silent(stmt);
}
