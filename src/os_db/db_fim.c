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
 
#include "db_fim.h"

int db_insert_fim(sqlite3 *db, char * path, char * event, char * md5, char * sha1, char * size, char * uid, char * gid, int perm){
	
	merror("Database: %s, %s, %s, %s, %s, %s, %s, %d", path, event, md5, sha1, size, uid, gid, perm);
	
	return 1;
}