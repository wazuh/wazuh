/* @(#) $Id$ */

/* Copyright (C) 2004-2006 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef _MONITORD_H
#define _MONITORD_H

#ifndef ARGV0
   #define ARGV0 "ossec-monitord"
#endif
   
typedef struct _monitor_config
{
    short int day_wait;
    short int compress;
    short int sign;
    short int monitor_agents;
    int a_queue;
}monitor_config;


/** Prototypes **/

/* Main monitord */
void Monitord();

/*manage_files */
void manage_files(int cday, int cmon, int cyear);

/* Compress log */
void OS_CompressLog(char *logfile);


/* Global variables */
monitor_config mond;


#endif
