/* @(#) $Id: ./src/monitord/monitord.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
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

#include "config/reports-config.h"



/** Prototypes **/

/* Main monitord */
void Monitord();

/*manage_files */
void manage_files(int cday, int cmon, int cyear);

/* generate reports. */
void generate_reports(int cday, int cmon, int cyear, struct tm *p);

/* monitor_agents */
void monitor_agents();

/* Sign a log */
void OS_SignLog(char *logfile, char *logfile_old, int log_missing);

/* Compress log */
void OS_CompressLog(char *logfile);


/* Global variables */
monitor_config mond;


#endif
