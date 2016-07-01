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
extern sqlite3 *wdb;

/* Open global database */
void wdb_open();

/* Find file: returns ID, or 0 if it doesn't exists, or -1 on error. */
int wdb_find_file(int id_agent, const char *path);

/* Insert file, Returns ID, or -1 on error. */
int wdb_insert_file(int id_agent, const char *path, int type);

/* Insert FIM entry. Returns ID, or -1 on error. */
int wdb_insert_fim(int id_agent, const char *location, const char *f_name, const char *event, const SyscheckSum *sum, long int time);

/* Insert policy monitoring entry. Returns ID on success or -1 on error. */
int wdb_insert_pm(int id_agent, long int date, const char *log);

/* Update policy monitoring last date. Returns 0 on success or -1 on error. */
int wdb_update_pm(int id_agent, const char *log, long int date_last);

#endif
