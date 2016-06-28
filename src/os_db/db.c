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
		name TEXT, \
		ip TEXT, \
		key TEXT, \
		os TEXT, \
		version TEXT, \
		date_add NUMERIC DEFAULT CURRENT_TIMESTAMP, \
		enabled INTEGER DEFAULT 1 \
	) WITHOUT ROWID; \
	\
	CREATE INDEX IF NOT EXISTS agent_name ON agent (name); \
	CREATE INDEX IF NOT EXISTS agent_ip ON agent (ip); \
	INSERT INTO agent (id) VALUES (0);";

static const char *SCHEMA_SQLITE_TABLE_FIM_FILE = "\
	CREATE TABLE IF NOT EXISTS fim_file ( \
		id INTEGER PRIMARY KEY AUTOINCREMENT, \
		id_agent INTEGER NOT NULL REFERENCES agent (id), \
		path TEXT NOT NULL, \
		type TEXT NOT NULL CHECK (type IN ('file', 'registry')) \
	); \
	\
	CREATE INDEX IF NOT EXISTS fim_file_path ON fim_file (id_agent, path);";

static const char *SCHEMA_SQLITE_TABLE_FIM_EVENT = "\
	CREATE TABLE IF NOT EXISTS fim_event ( \
		id INTEGER PRIMARY KEY AUTOINCREMENT, \
		id_file INTEGER NOT NULL REFERENCES fim_file (id), \
		event TEXT NOT NULL CHECK (event IN ('added', 'modified', 'readded', 'deleted')), \
		date NUMERIC, \
		size INTEGER, \
		perm INTEGER, \
		uid INTEGER, \
		gid INTEGER, \
		md5 TEXT, \
		sha1 TEXT \
	);";

static const char *PRAGMA_JOURNAL_WAL = "PRAGMA journal_mode=WAL;";

static void db_create_tables();
static void db_exec(const char *sql);

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
	db_exec(PRAGMA_JOURNAL_WAL);
	db_exec(SCHEMA_SQLITE_TABLE_AGENT);
	db_exec(SCHEMA_SQLITE_TABLE_FIM_FILE);
	db_exec(SCHEMA_SQLITE_TABLE_FIM_EVENT);
}

void db_exec(const char *sql){
	char *zErrMsg = NULL;

	/* Execute SQL statement */
	if (sqlite3_exec(db, sql, 0, 0, &zErrMsg) != SQLITE_OK)
		ErrorExit("%s: ERROR: SQL error: %s\n", ARGV0, zErrMsg);
}
