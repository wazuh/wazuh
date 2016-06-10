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
 
#include "db_sqlite.h"

int sqlite_step(sqlite3 *db, sqlite3_stmt *stmt){
	
	int rc;
	rc = sqlite3_step(stmt);
	if(SQLITE_DONE != rc) {
		merror("Database: SQLite Step error (%i): %s\n", rc, sqlite3_errmsg(db));
		return 1;
	} else {
		return 0;
	}
}





void sqlite_connect(sqlite3 *db){
	
	char dir[OS_MAXSTR + 1];
	int rc;
	
	// Database dir
	snprintf(dir, OS_MAXSTR, "%s/%s", SQLITE_DIR, SQLITE_DB_NAME);
	
	// Connect or create the database
	rc = sqlite3_open(dir, &db);
	if( rc ){
	  merror("Database: Can't open SQLite database: %s\n", sqlite3_errmsg(db));
	}else{
	  merror("Database: Opened SQLite database successfully\n");
	}
	
	// Create tables if not exists
	if(sqlite_create_tables(db))
		merror("Database: Can't create database tables\n");
	
}
void sqlite_close(sqlite3 *db){
	sqlite3_close(db);
}

int sqlite_create_tables(sqlite3 *db){
	int error = 0; 
	
	error = sqlite_create_table(db, SCHEMA_SQLITE_TABLE_AGENT);
	
	error = sqlite_create_table(db, SCHEMA_SQLITE_TABLE_FIM_EVENT);
	
	error = sqlite_create_table(db, SCHEMA_SQLITE_TABLE_FIM_FILE_ENTRY);
	
	error = sqlite_create_table(db, SCHEMA_SQLITE_TABLE_FIM_REGISTRY_ENTRY);
	
	error = sqlite_create_table(db, SCHEMA_SQLITE_TABLE_FIM_FILE);
	
	error = sqlite_create_table(db, SCHEMA_SQLITE_TABLE_FIM_REGISTRY);
	
	return error;
}
int sqlite_create_table(sqlite3 *db, char * table){
	char *zErrMsg = 0;
	int  rc;
	
	/* Execute SQL statement */
	rc = sqlite3_exec(db, table, 0, 0, &zErrMsg);
	if( rc != SQLITE_OK ){
		merror("Database: Create table: SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		return 1;
	}else{
		return 0;
	};
	
}