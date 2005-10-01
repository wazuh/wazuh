/*   $OSSEC, syscheck.h, v0.1, 2005/07/29, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
       

#ifndef __SYSCHECK_H

#define __SYSCHECK_H

#include <stdio.h>

typedef struct _config
{
    char *workdir;
    char *rootkit_files;

    FILE *fp;
    int daemon;
    int notify; /* QUEUE or SYSLOG */

    int queue;
}config;


config rootcheck;

#define QUEUE   101
#define SYSLOG  102

#define MAX_DIR_SIZE    64


/** Prototypes **/

/* run_check: checks the integrity of the files against the
 * saved database
 */
void run_check();

/* start_daemon: Runs run_check periodically.
 */
void start_daemon();


/*** Plugins functions prototypes ***/
void check_rc_files(char *basedir, FILE *fp);

#endif

/* EOF */
