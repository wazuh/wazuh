/* @(#) $Id: ./src/syscheckd/syscheck.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef __SYSCHECK_H

#define __SYSCHECK_H

#include "config/syscheck-config.h"
#define MAX_LINE PATH_MAX+256

/* Notify list size */
#define NOTIFY_LIST_SIZE    32


/* Global config */
syscheck_config syscheck;


/** Function Prototypes **/

/* run_check: checks the integrity of the files against the
 * saved database
 */
void run_check();


/* start_daemon: Runs run_check periodically.
 */
void start_daemon();


/* Read the XML config */
int Read_Syscheck_Config(char * cfgfile);


/* create the database */
int create_db();


/* int run_dbcheck()
 * Checks database for changes.
 */
int run_dbcheck();

/** void os_winreg_check()
 * Checks the registry for changes.
 */
void os_winreg_check();

/* starts real time */
int realtime_start();

/* Adds a directory to real time monitoring. */
int realtime_adddir(char *dir);

/* Process real time queue. */
int realtime_process();

/* Process the content of the file changes. */
char *seechanges_addfile(char *filename);

/* get checksum changes. */
int c_read_file(char *file_name, char *oldsum, char *newsum);

/** Sends syscheck message.
 */
int send_syscheck_msg(char *msg);
int send_rootcheck_msg(char *msg);


#endif

/* EOF */
