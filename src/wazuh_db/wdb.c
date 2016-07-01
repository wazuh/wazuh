/*
 * Wazuh SQLite integration
 * Copyright (C) 2016 Wazuh Inc.
 * June 06, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"

/* From schema.s and schema.sql */
extern const char *SCHEMA_SQL;

static void wdb_create_tables();

sqlite3 *wdb;

/* Open global database */
void wdb_open(){

	char dir[OS_FLSIZE + 1];
	int rc;

	// Database dir
	snprintf(dir, OS_FLSIZE, "%s/%s", SQLITE_DIR, SQLITE_DB_NAME);

	// Connect or create the database
	rc = sqlite3_open_v2(dir, &wdb, SQLITE_OPEN_READWRITE, NULL);

	switch (rc) {
	case 0:
		break;

	case SQLITE_CANTOPEN:
		// Create tables if not exists
		merror("%s: INFO: Creating %s", ARGV0, dir);
		if (sqlite3_open_v2(dir, &wdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL))
			ErrorExit("%s: ERROR: Can't open SQLite database: %s\n", ARGV0, sqlite3_errmsg(wdb));

		wdb_create_tables();
		break;

	default:
	    ErrorExit("%s: ERROR: Can't open SQLite database: %s\n", ARGV0, sqlite3_errmsg(wdb));
	}
}

void wdb_create_tables() {
	const char *sql;
	const char *tail;
	sqlite3_stmt *stmt;

	for (sql = SCHEMA_SQL; sql; sql = tail) {
		if (sqlite3_prepare_v2(wdb, sql, -1, &stmt, &tail))
			ErrorExit("%s: ERROR: Can't create table: %s", ARGV0, sqlite3_errmsg(wdb));

		sqlite3_step(stmt);
		sqlite3_reset(stmt);
	}
}
