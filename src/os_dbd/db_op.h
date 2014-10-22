/* @(#) $Id: ./src/os_dbd/db_op.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */

/* Common API for dealing with databases */


#ifndef _OS_DBOP_H
#define _OS_DBOP_H


/* Connects to the database */
extern void *(*osdb_connect)(const char *host, const char *user, const char *pass, const char *db, unsigned int port, const char *sock);
void *mysql_osdb_connect(const char *host, const char *user, const char *pass, const char *db, unsigned int port, const char *sock);
void *postgresql_osdb_connect(const char *host, const char *user, const char *pass, const char *db, unsigned int port, const char *sock);
void *none_osdb_connect(const char *host, const char *user, const char *pass, const char *db, unsigned int port, const char *sock);

/* Sends insert query to the database */
extern int (* osdb_query_insert)(void *db_conn, const char *query);
int mysql_osdb_query_insert(void *db_conn, const char *query);
int postgresql_osdb_query_insert(void *db_conn, const char *query);
int none_osdb_query_insert(void *db_conn, const char *query);

/* Sends select query to the database */
extern int (* osdb_query_select)(void *db_conn, const char *query);
int mysql_osdb_query_select(void *db_conn, const char *query);
int postgresql_osdb_query_select(void *db_conn, const char *query);
int none_osdb_query_select(void *db_conn, const char *query);

/* Closes connection to the database */
extern void *(*osdb_close)(void *db_conn);
void *mysql_osdb_close(void *db_conn);
void *postgresql_osdb_close(void *db_conn);
void *none_osdb_close(void *db_conn);


/* escape strings before inserting. */
void osdb_escapestr(char *str);


/* Allowed characters */
/* Insert charmap.
 * Available chars: a-z, A-Z, 0-9, -, _, ., %, $, @, (, ), +, *, <space> /
 * Basically: 040-046 (oct)
 *            050-176 (oct)
 * 8/27/2012: Modified to allow new lines - \012
 */
extern const unsigned char insert_map[256];


#endif

/* EOF */
