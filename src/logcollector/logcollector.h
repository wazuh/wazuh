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
#define ARGV0="ossec-logcollector"
#endif

#define FP_TIMEOUT  2

#include <stdio.h> /* for FILE* */
#include "shared.h"
#include "error_messages/error_messages.h"



/* Logreader config */
typedef struct _logreader
{
    int mtime;
    char type;
    int ign;
        
	char *file;
	char *group;

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
int read_syslog(int pos);

/* Read snort full file */
int read_snortfull(int pos);


/*** Global variables ***/

int logr_queue;
logreader *logr;


#endif
