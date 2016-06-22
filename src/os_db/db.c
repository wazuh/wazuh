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

static const char *SCHEMA_SQLITE_TABLE_AGENT = "\
	CREATE TABLE IF NOT EXISTS agent ( \
		id INTEGER PRIMARY KEY, \
		name TEXT NOT NULL, \
		ip TEXT NOT NULL, \
		key TEXT, \
		os TEXT, \
		version TEXT, \
		date_add NUMERIC \
	) WITHOUT ROWID; \
	\
	CREATE INDEX IF NOT EXISTS agent_name ON agent (name);";

static const char *SCHEMA_SQLITE_TABLE_FIM_FILE = "\
	CREATE TABLE IF NOT EXISTS fim_file ( \
		id INTEGER PRIMARY KEY AUTOINCREMENT, \
		id_agent INTEGER NOT NULL, \
		path TEXT NOT NULL \
	); \
	\
	CREATE INDEX IF NOT EXISTS fim_file_path ON fim_file (id_agent, path);";

static const char *SCHEMA_SQLITE_TABLE_FIM_EVENT = "\
	CREATE TABLE IF NOT EXISTS fim_event ( \
		id INTEGER PRIMARY KEY AUTOINCREMENT, \
		id_agent INTEGER NOT NULL REFERENCES agent (id), \
		id_file INTEGER NOT NULL REFERENCES fim_file (id), \
		event TEXT NOT NULL CHECK (event in ('added', 'modified', 'readded', 'deleted')), \
		date NUMERIC, \
		size INTEGER, \
		perm INTEGER, \
		uid INTEGER, \
		gid INTEGER, \
		md5 TEXT, \
		sha1 TEXT \
	);";

static void db_create_tables();
static void db_create_table(const char * table);

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
	db_create_table(SCHEMA_SQLITE_TABLE_AGENT);
	db_create_table(SCHEMA_SQLITE_TABLE_FIM_FILE);
	db_create_table(SCHEMA_SQLITE_TABLE_FIM_EVENT);
}

void db_create_table(const char *table){
	char *zErrMsg = NULL;

	/* Execute SQL statement */
	if (sqlite3_exec(db, table, 0, 0, &zErrMsg) != SQLITE_OK)
		ErrorExit("%s: ERROR: Create table: SQL error: %s\n", ARGV0, zErrMsg);
}
