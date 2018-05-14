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
int LogCollectorConfig(const char *cfgfile);

/* Start log collector daemon */
void LogCollectorStart(void) __attribute__((noreturn));

/* Handle files */
int handle_file(int i, int j, int do_fseek, int do_log);

/* Read syslog file */
void *read_syslog(logreader *lf, int *rc, int drop_it);

/* Read snort full file */
void *read_snortfull(logreader *lf, int *rc, int drop_it);

/* Read ossec alert file */
void *read_ossecalert(logreader *lf, int *rc, int drop_it);

/* Read nmap grepable format */
void *read_nmapg(logreader *lf, int *rc, int drop_it);

/* Read mysql log format */
void *read_mysql_log(logreader *lf, int *rc, int drop_it);

/* Read mysql log format */
void *read_mssql_log(logreader *lf, int *rc, int drop_it);

/* Read postgresql log format */
void *read_postgresql_log(logreader *lf, int *rc, int drop_it);

/* read multi line logs */
void *read_multiline(logreader *lf, int *rc, int drop_it);

/* Read DJB multilog format */
/* Initializes multilog */
int init_djbmultilog(logreader *lf);
void *read_djbmultilog(logreader *lf, int *rc, int drop_it);

/* Read events from output of command */
void *read_command(logreader *lf, int *rc, int drop_it);
void *read_fullcommand(logreader *lf, int *rc, int drop_it);

/* Read auditd events */
void *read_audit(logreader *lf, int *rc, int drop_it);

/* Read json events */
void *read_json(logreader *lf, int *rc, int drop_it);

/* Init queue */
void w_msg_queue_init(size_t size);

/* Push message into the queue */
int w_msg_queue_push(const char * buffer, unsigned long size);

/* Pop message from the queue */
char * w_msg_queue_pop();

#ifdef WIN32
void win_startel();
void win_readel();
void win_read_vista_sec();
void win_start_event_channel(char *evt_log, char future, char *query);
void win_format_event_string(char *string);
#endif

/*** Global variables ***/
extern int loop_timeout;
extern int logr_queue;
extern int open_file_attempts;
extern logreader *logff;
extern logreader_glob *globs;
extern logsocket *logsk;
extern int vcheck_files;
extern int maximum_lines;
extern logsocket default_agent;
extern int maximum_files;
extern int current_files;

typedef enum {
    CONTINUE_IT,
    NEXT_IT,
    LEAVE_IT
} IT_control;

/* Message queue */
w_queue_t * msg_queue;


#endif /* __LOGREADER_H */
