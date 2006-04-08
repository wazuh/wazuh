/*   $OSSEC, rootcheck.h, v0.1, 2005/10/03, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
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
    char *rootkit_files;
    char *rootkit_trojans;

    FILE *fp;
    int daemon;
    int notify; /* QUEUE or SYSLOG */
    int scanall;
    int readall;

    int time;
    int queue;
}rkconfig;

#endif

/* EOF */
