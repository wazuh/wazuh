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
    const char *workdir;
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

    int time;
    int queue;

	struct _checks
	{
        short rc_dev;
        short rc_files;
        short rc_if;
        short rc_pids;
        short rc_ports;
        short rc_sys;
        short rc_trojans;

        #ifdef WIN32

        short rc_winaudit;
        short rc_winmalware;
        short rc_winapps;

        #else

        short rc_unixaudit;

        #endif


    } checks;

}rkconfig;

#endif

/* EOF */
