/*   $OSSEC, rootcheck.h, v0.1, 2005/10/03, Daniel B. Cid$   */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
       

#ifndef __CROOTCHECK_H

#define __CROOTCHECK_H

#include <stdio.h>

typedef struct _rkconfig
{
    char *workdir;
    char *basedir;
    char *rootkit_files;
    char *rootkit_trojans;
    char **unixaudit;
    char **ignore;
    char *winaudit;
    char *winmalware;
    char *winapps;
    char **alert_msg;

    FILE *fp;
    int daemon;
    int notify; /* QUEUE or SYSLOG */
    int scanall;
    int readall;
    int disabled;

    /* cmoraes: added */
    int check_dev_disabled;       /*looking for files on /dev */
    int check_sys_disabled;       /* scan whole system looking for other issues */
    int check_proc_disabled;      /* process checking */
    int check_allports_disabled;  /* scan all ports */
    int check_openports_disabled; /* scan open ports */
    int check_intf_disabled;      /* scan interfaces */

    int time;
    int queue;
}rkconfig;

#endif

/* EOF */
