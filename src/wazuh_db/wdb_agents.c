#include "wdb.h"

int wdb_agents_insert_vuln_cve(wdb_t *wdb, const char* name, const char* version, const char* architecture, const char* cve) {
    sqlite3_stmt *stmt = NULL;

    //JJP wrap transaction and statement cache
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_VULN_CVE_INSERT) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_VULN_CVE_INSERT];
    
    //JJP wrap sqlite and error
    if (sqlite3_bind_text(stmt, 1, name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 2, version, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 3, architecture, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 4, cve, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    //wrap all this if it doesnt exist
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

int wdb_agents_clear_vuln_cve(wdb_t *wdb) {
    sqlite3_stmt *stmt = NULL;

    //JJP wrap transaction and statement cache
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_VULN_CVE_CLEAR) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_VULN_CVE_CLEAR];
   
    //wrap all this if it doesnt exist
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