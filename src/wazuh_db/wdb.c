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

sqlite3 *wdb = NULL;

/* Open global database */
void wdb_open(){
	char dir[OS_FLSIZE + 1];

	if (!wdb) {
		// Database dir
		snprintf(dir, OS_FLSIZE, "%s/%s", SQLITE_DIR, SQLITE_DB_NAME);

		// Connect to the database

		if (sqlite3_open_v2(dir, &wdb, SQLITE_OPEN_READWRITE, NULL)) {
			merror("%s: ERROR: Can't open SQLite database: %s\n", ARGV0, sqlite3_errmsg(wdb));
			wdb = NULL;
		}
	}
}
