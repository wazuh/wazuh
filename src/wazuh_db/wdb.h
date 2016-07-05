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

/* Global SQLite database */
extern sqlite3 *wdb_global;

/* Open global database */
void wdb_open_global();

/* Close global database */
void wdb_close_global();

/* Open database for agent */
sqlite3* wdb_open_agent(int id_agent, const char *name);

/* Get agent name from location string */
char* wdb_agent_name(const char *location);

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

#endif
