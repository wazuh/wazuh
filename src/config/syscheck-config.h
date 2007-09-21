/* @(#) $Id$ */

/* Copyright (C) 2003-2007 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */
       

#ifndef __SYSCHECKC_H
#define __SYSCHECKC_H


#define MAX_DIR_SIZE    64
#define MAX_DIR_ENTRY   128


#define SYSCHECK_DB     "/queue/syscheck/syschecklocal.db"
#define SYS_WIN_DB      "syscheck/syschecklocal.db"
#define SYS_WIN_REG     "syscheck/syscheckregistry.db"
#define SYS_REG_TMP     "syscheck/syscheck_sum.tmp"
#define SYSCHECK_WAIT   3600


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
    int tsleep;
    int sleep_after;
    int rootcheck;
    int disabled;
    
    int time;
    int queue;
    
    int opts[MAX_DIR_ENTRY +1];

    char *workdir;
    char *remote_db;
    char *db;
    
	char **ignore;
    void **ignore_regex;
    
	char *dir[MAX_DIR_ENTRY +1];

    /* Windows only registry checking */
    #ifdef WIN32
	char **registry_ignore;
    void **registry_ignore_regex;
	char *registry[MAX_DIR_ENTRY +1];
    FILE *reg_fp;
    #endif
    
    FILE *fp;

}config;

#endif

/* EOF */
