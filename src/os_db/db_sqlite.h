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
 
#include "shared.h"
#include "sqlite3.h"

#define SCHEMA_SQLITE_TABLE_AGENT  "CREATE TABLE IF NOT EXISTS agent(id INTEGER PRIMARY KEY NOT NULL,id_agent TEXT NOT NULL,name INTEGER NOT NULL,ip TEXT,os TEXT,version TEXT,id_key INTEGER NOT NULL,date_add TEXT NOT NULL);"
#define SCHEMA_SQLITE_TABLE_FIM_EVENT  "CREATE TABLE IF NOT EXISTS fim_event(id INTEGER PRIMARY KEY NOT NULL,id_agent INTEGER NOT NULL,id_entry INTEGER NOT NULL,event TEXT NOT NULL,type TEXT NOT NULL,date TEXT NOT NULL);"
#define SCHEMA_SQLITE_TABLE_FIM_FILE_ENTRY  "CREATE TABLE IF NOT EXISTS fim_file_entry(id INTEGER PRIMARY KEY NOT NULL,id_file INTEGER NOT NULL,path TEXT NOT NULL,gid INTEGER,md5 TEXT,perm TEXT,sha1 TEXT,size INTEGER,uid INTEGER);"
#define SCHEMA_SQLITE_TABLE_FIM_REGISTRY_ENTRY  "CREATE TABLE IF NOT EXISTS fim_registry_entry(id INTEGER PRIMARY KEY NOT NULL,id_registry INTEGER NOT NULL,value TEXT NOT NULL);"
#define SCHEMA_SQLITE_TABLE_FIM_FILE  "CREATE TABLE IF NOT EXISTS fim_file(id INTEGER PRIMARY KEY NOT NULL);"
#define SCHEMA_SQLITE_TABLE_FIM_REGISTRY  "CREATE TABLE IF NOT EXISTS fim_registry(id INTEGER PRIMARY KEY NOT NULL);"

void sqlite_connect(sqlite3 *db);
void sqlite_close(sqlite3 *db);
int sqlite_create_tables(sqlite3 *db);
int sqlite_create_table(sqlite3 *db, char * table);
int sqlite_step(sqlite3 *db, sqlite3_stmt *stmt);