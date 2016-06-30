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

#include "db.h"

/* From schema.s and schema.sql */
extern const char *SCHEMA_SQL;

static void db_create_tables();

sqlite3 *db;

/* Open global database */
void db_open(){

	char dir[OS_FLSIZE + 1];
	int rc;

	// Database dir
	snprintf(dir, OS_FLSIZE, "%s/%s", SQLITE_DIR, SQLITE_DB_NAME);

	// Connect or create the database
	rc = sqlite3_open_v2(dir, &db, SQLITE_OPEN_READWRITE, NULL);

	switch (rc) {
	case 0:
		break;

	case SQLITE_CANTOPEN:
		// Create tables if not exists
		merror("%s: INFO: Creating %s", ARGV0, dir);
		if (sqlite3_open_v2(dir, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL))
			ErrorExit("%s: ERROR: Can't open SQLite database: %s\n", ARGV0, sqlite3_errmsg(db));

		db_create_tables();
		break;

	default:
	    ErrorExit("%s: ERROR: Can't open SQLite database: %s\n", ARGV0, sqlite3_errmsg(db));
	}
}

void db_create_tables() {
	const char *sql;
	const char *tail;
	sqlite3_stmt *stmt;

	for (sql = SCHEMA_SQL; sql; sql = tail) {
		if (sqlite3_prepare_v2(db, sql, -1, &stmt, &tail))
			ErrorExit("%s: ERROR: Can't create table: %s", ARGV0, sqlite3_errmsg(db));

		sqlite3_step(stmt);
		sqlite3_reset(stmt);
	}
}
