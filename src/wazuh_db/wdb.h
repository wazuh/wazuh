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

#ifndef WDB_H
#define WDB_H

#include "sqlite3.h"
#include "analysisd/decoders/decoder.h"

#define WDB_FILE_TYPE_FILE 0
#define WDB_FILE_TYPE_REGISTRY 1

#define wdb_create_global(path) wdb_create_file(path, schema_global_sql)
#define wdb_create_profile(path) wdb_create_file(path, schema_agents_sql)

/* Global SQLite database */
extern sqlite3 *wdb_global;

extern char *schema_global_sql;
extern char *schema_agents_sql;

/* Open global database. Returns 0 on success or -1 on failure. */
int wdb_open_global();

/* Close global database */
void wdb_close_global();

/* Open database for agent */
sqlite3* wdb_open_agent(int id_agent, const char *name);

/* Get agent name from location string */
char* wdb_agent_loc2name(const char *location);

/* Find file: returns ID, or 0 if it doesn't exists, or -1 on error. */
int wdb_find_file(sqlite3 *db, const char *path, int type);

/* Find file, Returns ID, or -1 on error. */
int wdb_insert_file(sqlite3 *db, const char *path, int type);

/* Insert FIM entry. Returns ID, or -1 on error. */
int wdb_insert_fim(int id_agent, const char *location, const char *f_name, const char *event, const SyscheckSum *sum, long int time);

/* Insert policy monitoring entry. Returns ID on success or -1 on error. */
int wdb_insert_pm(int id_agent, const char *location, long int date, const char *log);

/* Update policy monitoring last date. Returns 0 on success or -1 on error. */
int wdb_update_pm(int id_agent, const char *location, const char *log, long int date_last);

/* Insert agent. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_insert_agent(int id, const char *name, const char *ip, const char *key);

/* Update agent name. It doesn't rename agent DB file. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_update_agent_name(int id, const char *name);

/* Update agent version info. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_update_agent_version(int id, const char *os, const char *version);

/* Update agent keepalive timestamp. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_update_agent_keepalive(int id);

/* Delete agent. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_remove_agent(int id);

/* Get name from agent. The string must be freed after using. Returns NULL on error. */
char* wdb_agent_name(int id);

/* Create database for agent from profile. Returns 0 on success or -1 on error. */
int wdb_create_agent_db(int id, const char *name);

/* Create database for agent from profile. Returns 0 on success or -1 on error. */
int wdb_remove_agent_db(int id);

/* Prepare SQL query with availability waiting */
int wdb_prepare(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **stmt, const char **pzTail);

/* Execute statement with availability waiting */
int wdb_step(sqlite3_stmt *stmt);

/* Create new database file from SQL script */
int wdb_create_file(const char *path, const char *source);

/* Get an array containint the ID of every agent (except 0), ended with -1 */
int* wdb_get_all_agents();

/* Delete FIM events of an agent. Returns 0 on success or -1 on error. */
int wdb_delete_fim(int id);

/* Delete FIM events of all agents. */
void wdb_delete_fim_all();

/* Delete PM events of an agent. Returns 0 on success or -1 on error. */
int wdb_delete_pm(int id);

/* Delete PM events of all agents */
void wdb_delete_pm_all();

#endif
