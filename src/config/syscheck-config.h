/* @(#) $Id$ */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
       

#ifndef __SYSCHECKC_H
#define __SYSCHECKC_H


#define MAX_DIR_SIZE    64
#define MAX_DIR_ENTRY   128
#define SYSCHECK_WAIT   300


/* Checking options */
#define CHECK_MD5SUM        0000001
#define CHECK_PERM          0000002
#define CHECK_SIZE          0000004
#define CHECK_OWNER         0000010
#define CHECK_GROUP         0000020
#define CHECK_SHA1SUM       0000040
#define CHECK_REALTIME      0000100
#define CHECK_SEECHANGES    0000200


#include <stdio.h>
typedef struct _rtfim
{
    int fd;
    void *dirtb;
    #ifdef WIN32
    HANDLE evt;
    #endif
}rtfim;

typedef struct _config
{
    int tsleep;
    int sleep_after;
    int rootcheck;
    int disabled;
    int scan_on_start;
    int realtime_count;
    
    int time;
    int queue;
    
    int *opts;

    char *workdir;
    char *remote_db;
    char *db;

    char *scan_day;
    char *scan_time;
    
	char **ignore;
    void **ignore_regex;
    
	char **dir;
    void **filerestrict;

    /* Windows only registry checking */
    #ifdef WIN32
	char **registry_ignore;
    void **registry_ignore_regex;
	char **registry;
    FILE *reg_fp;
    #endif
    
    void *fp;

    rtfim *realtime;

}config;

#endif

/* EOF */
