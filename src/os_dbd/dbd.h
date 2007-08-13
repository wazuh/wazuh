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


#ifndef _DBD_H
#define _DBD_H


#include "shared.h"
#include "db_op.h"
#include "config/dbd-config.h"


/** Prototypes **/

/* Read database config */
int OS_ReadDBConf(int test_config, char *cfgfile, DBConfig *db_config);


/* Insert rules in to the database */
int OS_InsertRulesDB(DBConfig *db_config);


/* Database inserting main function */
void OS_DBD(DBConfig *db_config);

#endif
