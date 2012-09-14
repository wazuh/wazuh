/* @(#) $Id: ./src/logcollector/logcollector.h, 2012/03/28 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
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


#include "shared.h"
#include "config/localfile-config.h"
#include "config/config.h"




/*** Function prototypes ***/


/* Read logcollector config */
int LogCollectorConfig(char * cfgfile, int accept_remote);

/* Stary log collector daemon */
void LogCollectorStart();

/* Handle files */
int handle_file(int i, int do_fseek, int do_log);

/* Read syslog file */
int read_syslog(int pos, int drop_it);

/* Read snort full file */
int read_snortfull(int pos, int drop_it);

/* Read ossec alert file */
int read_ossecalert(int pos, int drop_it);

/* Read nmap grepable format */
int read_nmapg(int pos, int drop_it);

/* Read mysql log format */
int read_mysql_log(int pos, int drop_it);

/* Read mssql log format */
int read_mssql_log(int pos, int drop_it);

/* Read postgresql log format */
int read_postgresql_log(int pos, int drop_it);

/* read multi line logs. */
int read_multiline(int pos, int drop_it);

/* read mod_security audit logs. */
int read_modsec_audit(int pos, int drop_it);

/* read regex delimited logs. */
int read_regex_init(int i);
int read_regex(int pos, int drop_it);

/* Read DJB multilog format */
/* Initializes multilog. */
int init_djbmultilog(int pos);
int read_djbmultilog(int pos, int drop_it);

/* Read events from output of command */
int read_command(int pos, int drop_it);
int read_fullcommand(int pos, int drop_it);


#ifdef WIN32
/* Windows only */
void win_startel();
void win_readel();
void win_read_vista_sec();
#else
int read_linux_audit_init(int pos);
int read_linux_audit(int pos, int drop_it);
#endif


/*** Global variables ***/


int loop_timeout;
int logr_queue;
int open_file_attempts;
logreader *logff;


#endif
