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

sqlite3 *wdb_global = NULL;

/* Open global database. Returns 0 on success or -1 on failure. */
int wdb_open_global() {
	char dir[OS_FLSIZE + 1];

	if (!wdb_global) {
		// Database dir
		snprintf(dir, OS_FLSIZE, "%s%s/%s", isChroot() ? "/" : "", WDB_DIR, WDB_GLOB_NAME);

		// Connect to the database

		if (sqlite3_open_v2(dir, &wdb_global, SQLITE_OPEN_READWRITE, NULL)) {
			merror("%s: ERROR: Can't open SQLite database '%s': %s\n", ARGV0, dir, sqlite3_errmsg(wdb_global));
			sqlite3_close_v2(wdb_global);
			wdb_global = NULL;
		}
	}

	return wdb_global != NULL;
}

/* Close global database */
void wdb_close_global() {
	sqlite3_close(wdb_global);
	wdb_global = NULL;
}

/* Open database for agent */
sqlite3* wdb_open_agent(int id_agent, const char *name) {
	char dir[OS_FLSIZE + 1];
	sqlite3 *db;

    snprintf(dir, OS_FLSIZE, "%s%s/agents/%d-%s.db", isChroot() ? "/" : "", WDB_DIR, id_agent, name);

	if (sqlite3_open_v2(dir, &db, SQLITE_OPEN_READWRITE, NULL)) {
		merror("%s: ERROR: Can't open SQLite database '%s': %s\n", ARGV0, dir, sqlite3_errmsg(wdb_global));
		sqlite3_close_v2(db);
		return NULL;
	}

	return db;
}

/* Get agent name from location string */
char* wdb_agent_loc2name(const char *location) {
    char *name;
	char *end;

	switch (location[0]) {
    case 'r':
	case 's':
	    if (!(strncmp(location, "syscheck", 8) && strncmp(location, "rootcheck", 9)))
		    return strdup("localhost");
		else
		    return NULL;

	case '(':
		name = strdup(location + 1);

		if ((end = strchr(name, ')')))
			*end = '\0';
		else {
			free(name);
			name = NULL;
		}

		return name;

	default:
	    return NULL;
	}
}
