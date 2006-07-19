/*   $OSSEC, syscheck-config.h, v0.1, 2005/07/29, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
       

#ifndef __SYSCHECKC_H

#define __SYSCHECKC_H

#define QUEUE   101
#define SYSLOG  102

#define MAX_DIR_SIZE    64
#define MAX_DIR_ENTRY   128

#define SYSCHECK_DB     "/queue/syscheck/syschecklocal.db"
#define SYS_WIN_DB      "syscheck/syschecklocal.db"
#define SYSCHECK_WAIT   3600
#define SYSCHECK        "syscheck"

/* Checking options */
#define CHECK_MD5SUM        0000001
#define CHECK_PERM          0000002
#define CHECK_SIZE          0000004
#define CHECK_OWNER         0000010
#define CHECK_GROUP         0000020
#define CHECK_SHA1SUM       0000040

#include <stdio.h>

typedef struct _config
{
	char *dir[MAX_DIR_ENTRY +1];
    int opts[MAX_DIR_ENTRY +1];

	char **ignore;

    char *workdir;
    char *remote_db;
    char *db;

    FILE *fp;
    int daemon;
    int notify; /* QUEUE or SYSLOG */
    int rootcheck;

    int time;
    int queue;
}config;

#endif

/* EOF */
