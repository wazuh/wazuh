/*
 * Wazuh SQLite integration
 * Copyright (C) 2017 Wazuh Inc.
 * April 23, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"

// Save CIS-CAT scan results.
int wdb_ciscat_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * benchmark, int pass, int fail, int error, int notchecked, int unknown, int score) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        merror("at wdb_ciscat_save(): cannot begin transaction");
        return -1;
    }

    if (wdb_ciscat_insert(wdb,
        scan_id,
        scan_time,
        benchmark,
        pass,
        fail,
        error,
        notchecked,
        unknown,
        score) < 0) {

        return -1;
    }

    return 0;
}

// Insert CIS-CAT results tuple. Return 0 on success or -1 on error.
int wdb_ciscat_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * benchmark, int pass, int fail, int error, int notchecked, int unknown, int score) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_CISCAT_INSERT) > 0) {
        merror("at wdb_ciscat_insert(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_CISCAT_INSERT];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, scan_time, -1, NULL);
    sqlite3_bind_text(stmt, 3, benchmark, -1, NULL);
    if (pass >= 0)
        sqlite3_bind_int(stmt, 4, pass);
    else
        sqlite3_bind_null(stmt, 4);

    if (fail >= 0)
        sqlite3_bind_int(stmt, 5, fail);
    else
        sqlite3_bind_null(stmt, 5);

    if (error >= 0)
        sqlite3_bind_int(stmt, 6, error);
    else
        sqlite3_bind_null(stmt, 6);

    if (notchecked >= 0)
        sqlite3_bind_int(stmt, 7, notchecked);
    else
        sqlite3_bind_null(stmt, 7);

    if (unknown >= 0)
        sqlite3_bind_int(stmt, 8, unknown);
    else
        sqlite3_bind_null(stmt, 8);

    if (score >= 0)
        sqlite3_bind_int(stmt, 9, score);
    else
        sqlite3_bind_null(stmt, 9);

    if (sqlite3_step(stmt) == SQLITE_DONE){
        return 0;
    }
    else {
        merror("at wdb_ciscat_insert(): sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}
