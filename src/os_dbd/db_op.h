/* @(#) $Id$ */

/* Copyright (C) 2003-2007 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */
 
/* Common API for dealing with databases */


#ifndef _OS_DBOP_H
#define _OS_DBOP_H


/* Connects to the database */
void *osdb_connect(char *host, char *user, char *pass, char *db);
int osdb_query(void *db_conn, char *query);


#endif

/* EOF */
