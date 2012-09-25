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
void *(*osdb_connect)(char *host, char *user, char *pass, char *db, int port, char *sock);
void *mysql_osdb_connect(char *host, char *user, char *pass, char *db, int port, char *sock);
void *postgresql_osdb_connect(char *host, char *user, char *pass, char *db, int port, char *sock);

/* Sends insert query to the database */
int (* osdb_query_insert)(void *db_conn, char *query);
int mysql_osdb_query_insert(void *db_conn, char *query);
int postgresql_osdb_query_insert(void *db_conn, char *query);

/* Sends select query to the database */
int (* osdb_query_select)(void *db_conn, char *query);
int mysql_osdb_query_select(void *db_conn, char *query);
int postgresql_osdb_query_select(void *db_conn, char *query);

/* Closes connection to the database */
void *(*osdb_close)(void *db_conn);
void *mysql_osdb_close(void *db_conn);
void *postgresql_osdb_close(void *db_conn);


/* escape strings before inserting. */
void osdb_escapestr(char *str);


/* Allowed characters */
/* Insert charmap.
 * Available chars: a-z, A-Z, 0-9, -, _, ., %, $, @, (, ), +, *, <space> /
 * Basically: 040-046 (oct)
 *            050-176 (oct)
 * 8/27/2012: Modified to allow new lines - \012
 */
static const unsigned char insert_map[] =
{
    '\000', '\000', '\002', '\003', '\004', '\005', '\006', '\007',
    '\010', '\011', '\001', '\013', '\014', '\015', '\016', '\017',
    '\020', '\021', '\022', '\023', '\024', '\025', '\026', '\027',
    '\030', '\031', '\032', '\033', '\034', '\035', '\036', '\037',
    '\001', '\001', '\001', '\001', '\001', '\001', '\001', '\047',
    '\001', '\001', '\001', '\001', '\001', '\001', '\001', '\001',
    '\001', '\001', '\001', '\001', '\001', '\001', '\001', '\001',
    '\001', '\001', '\001', '\001', '\001', '\001', '\001', '\001',
    '\001', '\001', '\001', '\001', '\001', '\001', '\001', '\001',
    '\001', '\001', '\001', '\001', '\001', '\001', '\001', '\001',
    '\001', '\001', '\001', '\001', '\001', '\001', '\001', '\001',
    '\001', '\001', '\001', '\001', '\001', '\001', '\001', '\001',
    '\001', '\001', '\001', '\001', '\001', '\001', '\001', '\001',
    '\001', '\001', '\001', '\001', '\001', '\001', '\001', '\001',
    '\001', '\001', '\001', '\001', '\001', '\001', '\001', '\001',
    '\001', '\001', '\001', '\001', '\001', '\001', '\001', '\177',
    '\200', '\201', '\202', '\203', '\204', '\205', '\206', '\207',
    '\210', '\211', '\212', '\213', '\214', '\215', '\216', '\217',
    '\220', '\221', '\222', '\223', '\224', '\225', '\226', '\227',
    '\230', '\231', '\232', '\233', '\234', '\235', '\236', '\237',
    '\240', '\241', '\242', '\243', '\244', '\245', '\246', '\247',
    '\250', '\251', '\252', '\253', '\254', '\255', '\256', '\257',
    '\260', '\261', '\262', '\263', '\264', '\265', '\266', '\267',
    '\270', '\271', '\272', '\273', '\274', '\275', '\276', '\277',
    '\300', '\301', '\302', '\303', '\304', '\305', '\306', '\307',
    '\310', '\311', '\312', '\313', '\314', '\315', '\316', '\317',
    '\320', '\321', '\322', '\323', '\324', '\325', '\326', '\327',
    '\330', '\331', '\332', '\333', '\334', '\335', '\336', '\337',
    '\340', '\341', '\342', '\343', '\344', '\345', '\346', '\347',
    '\350', '\351', '\352', '\353', '\354', '\355', '\356', '\357',
    '\360', '\361', '\362', '\363', '\364', '\365', '\366', '\367',
    '\360', '\361', '\362', '\363', '\364', '\365', '\366', '\367',
};


#endif

/* EOF */
