/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Common API for dealing with databases */

#ifndef _OS_DBOP_H
#define _OS_DBOP_H

/* Connect to the database */
extern void *(*osdb_connect)(const char *host, const char *user, const char *pass, const char *db, unsigned int port, const char *sock);
void *mysql_osdb_connect(const char *host, const char *user, const char *pass, const char *db, unsigned int port, const char *sock);
void *postgresql_osdb_connect(const char *host, const char *user, const char *pass, const char *db, unsigned int port, const char *sock);
void *none_osdb_connect(const char *host, const char *user, const char *pass, const char *db, unsigned int port, const char *sock);

/* Send insert query to the database */
extern int (* osdb_query_insert)(void *db_conn, const char *query);
int mysql_osdb_query_insert(void *db_conn, const char *query);
int postgresql_osdb_query_insert(void *db_conn, const char *query);
int none_osdb_query_insert(void *db_conn, const char *query);

/* Send select query to the database */
extern int (* osdb_query_select)(void *db_conn, const char *query);
int mysql_osdb_query_select(void *db_conn, const char *query);
int postgresql_osdb_query_select(void *db_conn, const char *query);
int none_osdb_query_select(void *db_conn, const char *query);

/* Close connection to the database */
extern void *(*osdb_close)(void *db_conn);
void *mysql_osdb_close(void *db_conn);
void *postgresql_osdb_close(void *db_conn);
void *none_osdb_close(void *db_conn);

/* Escape strings before inserting */
void osdb_escapestr(char *str);

/* Allowed characters */
/* Insert charmap.
 * Available chars: a-z, A-Z, 0-9, -, _, ., %, $, @, (, ), +, *, <space> /
 * Basically: 040-046 (oct)
 *            050-176 (oct)
 */
extern const unsigned char insert_map[256];

#endif /* _OS_DBOP_H */

