/*   $OSSEC, logcollector.h, v0.3, 2005/11/11, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#ifndef __LOGREADER_H

#define __LOGREADER_H

#ifndef ARGV0
#define ARGV0 "ossec-logcollector"
#endif

#define FP_TIMEOUT  2

#include "shared.h"



/* Logreader config */
typedef struct _logreader
{
    int mtime;
    char type;
    int ign;
        
	char *file;
	char *logformat;

    void (*read)(int i, int *rc);

    FILE *fp;
}logreader;



/*** Function prototypes ***/


/* Read logcollector config */
int LogCollectorConfig(char * cfgfile);

/* Stary log collector daemon */
void LogCollectorStart();

/* Handle files */
int handle_file(int i);

/* Read syslog file */
void *read_syslog(int pos, int *rc);

/* Read snort full file */
void *read_snortfull(int pos, int *rc);


#ifdef WIN32
/* Windows only */
void win_startel();
void win_readel();
#endif


/*** Global variables ***/

int logr_queue;
logreader *log;


#endif
