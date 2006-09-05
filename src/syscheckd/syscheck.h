/* @(#) $Id$ */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
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

/* Global config */
config syscheck;


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


/* int check_db()
 * Checks database for new files.
 */
int check_db();
  

#endif

/* EOF */
