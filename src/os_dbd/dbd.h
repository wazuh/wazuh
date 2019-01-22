/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DBD_H
#define _DBD_H

#include "shared.h"
#include "db_op.h"
#include "config/dbd-config.h"

/** Prototypes **/

/* Read database config */
int OS_ReadDBConf(int test_config, const char *cfgfile, DBConfig *db_config) __attribute__((nonnull));

/* Inserts server info to the db */
int OS_Server_ReadInsertDB(const DBConfig *db_config) __attribute__((nonnull));

/* Insert rules in to the database */
int OS_InsertRulesDB(DBConfig *db_config) __attribute__((nonnull));

/* Get maximum ID */
int OS_SelectMaxID(const DBConfig *db_config) __attribute__((nonnull));

/* Insert alerts in to the database */
int OS_Alert_InsertDB(const alert_data *al_data, DBConfig *db_config) __attribute__((nonnull));

/* Database inserting main function */
void OS_DBD(DBConfig *db_config) __attribute__((nonnull)) __attribute__((noreturn));

/* Set config pointer for osbd_op */
void osdb_setconfig(DBConfig *db_config);

#endif /* _DBD_H */

