/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"

int wdb_scan_info_init (wdb_t *wdb) {
    int result = 0;

    if (result = wdb_scan_info_insert(wdb, "fim"), result < 0) {
        merror("DB(%s) Couldn't initialize fim scan info into database", wdb->agent_id);
    }

    if (result = wdb_scan_info_insert(wdb, "syscollector"), result < 0) {
        merror("DB(%s) Couldn't initialize syscollector scan info into database", wdb->agent_id);
    }

    return result;
}

// Find scan_info entry: returns 1 if found, 0 if not, or -1 on error.
int wdb_scan_info_find (wdb_t * wdb, const char * module) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCAN_INFO_FIND) < 0) {
        merror("DB(%s) Cannot cache statement", wdb->agent_id);
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCAN_INFO_FIND];

    sqlite3_bind_text(stmt, 1, module, -1, NULL);

    switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:
        return 1;
        break;
    case SQLITE_DONE:
        return 0;
        break;
    default:
        mdebug1("DB(%s) at sqlite3_step(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}

// Initialize to 0 all data in a row into scan_info: returns -1 on error, 0 success
int wdb_scan_info_insert (wdb_t * wdb, const char *module) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCAN_INFO_INSERT) < 0) {
        merror("DB(%s) Cannot cache statement", wdb->agent_id);
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCAN_INFO_INSERT];

    sqlite3_bind_text(stmt, 1, module, -1, NULL);
    sqlite3_bind_int64(stmt, 2, 0);
    sqlite3_bind_int64(stmt, 3, 0);
    sqlite3_bind_int64(stmt, 4, 0);
    sqlite3_bind_int64(stmt, 5, 0);
    sqlite3_bind_int64(stmt, 6, 0);
    sqlite3_bind_int64(stmt, 7, 0);
    sqlite3_bind_int64(stmt, 8, 0);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}

// Update field from scan_info table: return -1 on error 0 success
int wdb_scan_info_update(wdb_t * wdb, const char *module, const char *field, long value) {
    sqlite3_stmt *stmt = NULL;

    if(strcmp(field, "first_start") == 0) {
        if (wdb_stmt_cache(wdb, WDB_STMT_SCAN_INFO_UPDATEFS) < 0) {
            merror("DB(%s) Cannot cache statement", wdb->agent_id);
            return -1;
        }
        stmt = wdb->stmt[WDB_STMT_SCAN_INFO_UPDATEFS];
        sqlite3_bind_int64(stmt, 2, value);
        sqlite3_bind_text(stmt, 3, module, -1, NULL);
    }
    if(strcmp(field, "first_end") == 0) {
        if (wdb_stmt_cache(wdb, WDB_STMT_SCAN_INFO_UPDATEFE) < 0) {
            merror("DB(%s) Cannot cache statement", wdb->agent_id);
            return -1;
        }
        stmt = wdb->stmt[WDB_STMT_SCAN_INFO_UPDATEFE];
        sqlite3_bind_int64(stmt, 2, value);
        sqlite3_bind_text(stmt, 3, module, -1, NULL);
    }
    if(strcmp(field, "start_scan") == 0) {
        if (wdb_stmt_cache(wdb, WDB_STMT_SCAN_INFO_UPDATESS) < 0) {
            merror("DB(%s) Cannot cache statement", wdb->agent_id);
            return -1;
        }
        stmt = wdb->stmt[WDB_STMT_SCAN_INFO_UPDATESS];
        sqlite3_bind_text(stmt, 2, module, -1, NULL);
    }
    if(strcmp(field, "end_scan") == 0) {
        if (wdb_stmt_cache(wdb, WDB_STMT_SCAN_INFO_UPDATEES) < 0) {
            merror("DB(%s) Cannot cache statement", wdb->agent_id);
            return -1;
        }
        stmt = wdb->stmt[WDB_STMT_SCAN_INFO_UPDATEES];
        sqlite3_bind_text(stmt, 2, module, -1, NULL);
    }
    if(strcmp(field, "fim_first_check") == 0) {
        if (wdb_stmt_cache(wdb, WDB_STMT_SCAN_INFO_UPDATE1C) < 0) {
            merror("DB(%s) Cannot cache statement", wdb->agent_id);
            return -1;
        }
        stmt = wdb->stmt[WDB_STMT_SCAN_INFO_UPDATE1C];
        sqlite3_bind_text(stmt, 2, module, -1, NULL);
    }
    if(strcmp(field, "fim_second_check") == 0) {
        if (wdb_stmt_cache(wdb, WDB_STMT_SCAN_INFO_UPDATE2C) < 0) {
            merror("DB(%s) Cannot cache statement", wdb->agent_id);
            return -1;
        }
        stmt = wdb->stmt[WDB_STMT_SCAN_INFO_UPDATE2C];
        sqlite3_bind_text(stmt, 2, module, -1, NULL);
    }
    if(strcmp(field, "fim_third_check") == 0) {
        if (wdb_stmt_cache(wdb, WDB_STMT_SCAN_INFO_UPDATE3C) < 0) {
            merror("DB(%s) Cannot cache statement", wdb->agent_id);
            return -1;
        }
        stmt = wdb->stmt[WDB_STMT_SCAN_INFO_UPDATE3C];
        sqlite3_bind_text(stmt, 2, module, -1, NULL);
    }

    sqlite3_bind_int64(stmt, 1, value);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return sqlite3_changes(wdb->db);
    } else {
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
        return -1;
    }
}

// Get time (first/last-start/end) in output of scan "module": return -1 on error 1 success and 0 if not find
int wdb_scan_info_get(wdb_t * wdb, const char *module, char *field, long *output) {
    sqlite3_stmt *stmt = NULL;

    if(strcmp(field, "first_start") == 0) {
        if (wdb_stmt_cache(wdb, WDB_STMT_SCAN_INFO_GETFS) < 0) {
            merror("DB(%s) Cannot cache statement", wdb->agent_id);
            return -1;
        }
        stmt = wdb->stmt[WDB_STMT_SCAN_INFO_GETFS];
    }
    if(strcmp(field, "first_end") == 0) {
        if (wdb_stmt_cache(wdb, WDB_STMT_SCAN_INFO_GETFE) < 0) {
            merror("DB(%s) Cannot cache statement", wdb->agent_id);
            return -1;
        }
        stmt = wdb->stmt[WDB_STMT_SCAN_INFO_GETFE];
    }
    if(strcmp(field, "start_scan") == 0) {
        if (wdb_stmt_cache(wdb, WDB_STMT_SCAN_INFO_GETSS) < 0) {
            merror("DB(%s) Cannot cache statement", wdb->agent_id);
            return -1;
        }
        stmt = wdb->stmt[WDB_STMT_SCAN_INFO_GETSS];
    }
    if(strcmp(field, "end_scan") == 0) {
        if (wdb_stmt_cache(wdb, WDB_STMT_SCAN_INFO_GETES) < 0) {
            merror("DB(%s) Cannot cache statement", wdb->agent_id);
            return -1;
        }
        stmt = wdb->stmt[WDB_STMT_SCAN_INFO_GETES];
    }
    if(strcmp(field, "fim_first_check") == 0) {
        if (wdb_stmt_cache(wdb, WDB_STMT_SCAN_INFO_GET1C) < 0) {
            merror("DB(%s) Cannot cache statement", wdb->agent_id);
            return -1;
        }
        stmt = wdb->stmt[WDB_STMT_SCAN_INFO_GET1C];
    }
    if(strcmp(field, "fim_second_check") == 0) {
        if (wdb_stmt_cache(wdb, WDB_STMT_SCAN_INFO_GET2C) < 0) {
            merror("DB(%s) Cannot cache statement", wdb->agent_id);
            return -1;
        }
        stmt = wdb->stmt[WDB_STMT_SCAN_INFO_GET2C];
    }
    if(strcmp(field, "fim_third_check") == 0) {
        if (wdb_stmt_cache(wdb, WDB_STMT_SCAN_INFO_GET3C) < 0) {
            merror("DB(%s) Cannot cache statement", wdb->agent_id);
            return -1;
        }
        stmt = wdb->stmt[WDB_STMT_SCAN_INFO_GET3C];
    }

    sqlite3_bind_text(stmt, 1, module, -1, NULL);

    switch (sqlite3_step(stmt)) {
        case SQLITE_ROW:
           *output = sqlite3_column_int64(stmt, 0);
            return 1;
            break;
        case SQLITE_DONE:
           *output = 0;
            return 0;
            break;
        default:
            mdebug1("DB(%s) at sqlite3_step(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
            return -1;
    }
}

// Update checks control: return 0 on success
int wdb_scan_info_fim_checks_control (wdb_t * wdb, const char *last_check) {
    int result;
    long value;
    long last = atol(last_check);

    if(result = wdb_scan_info_get(wdb, "fim", "fim_second_check", &value), result < 0) {
        mdebug1("DB(%s) Cannot get scan_info entry", wdb->agent_id);
    }
    if(result = wdb_scan_info_update(wdb, "fim", "fim_third_check", value), result < 0) {
        mdebug1("DB(%s) Cannot update scan_info entry", wdb->agent_id);
    }
    if(result = wdb_scan_info_get(wdb, "fim", "fim_first_check", &value), result < 0) {
        mdebug1("DB(%s) Cannot get scan_info entry", wdb->agent_id);
    }
    if(result = wdb_scan_info_update(wdb, "fim", "fim_second_check", value), result < 0) {
        mdebug1("DB(%s) Cannot update scan_info entry", wdb->agent_id);
    }
    if(result = wdb_scan_info_update(wdb, "fim", "fim_first_check", last), result < 0) {
        mdebug1("DB(%s) Cannot update scan_info entry", wdb->agent_id);
    }

    return 0;
}