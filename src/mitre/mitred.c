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

#include "mitred.h"

void main(){
    sqlite3 * db;
    char path[4097];
    char *sql;
    char *err_msg = 0;
    int rc;

    // Try to open DB
    snprintf(path, sizeof(path), "var/db/mitre.db");
    
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL)) {
        mdebug1("No SQLite global database found, creating.");
        sqlite3_close_v2(db);

        // Retry to open
        if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL)) {
            merror("Can't open SQLite database '%s': %s", path, sqlite3_errmsg(db));
            sqlite3_close_v2(db);
            goto end;
        }
    }

    // Create Mitre tables
    sql = "DROP TABLE IF EXISTS attack;"
            "DROP TABLE IF EXISTS has_phase;"
            "DROP TABLE IF EXISTS has_platform;" 
            "CREATE TABLE attack(id TEXT PRIMARY KEY, json TEXT);" 
            "CREATE TABLE has_phase(attack_id TEXT, phase_name TEXT, FOREIGN KEY(attack_id) REFERENCES attack(id), PRIMARY KEY(attack_id, phase_name));"
            "CREATE TABLE has_platform(attack_id TEXT, platforme_name TEXT, FOREIGN KEY(attack_id) REFERENCES attack(id), PRIMARY KEY(attack_id, platform_name));";

    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    
    if (rc != SQLITE_OK ) {   
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        goto end;
    }     

end:
    return exit(1);
}
