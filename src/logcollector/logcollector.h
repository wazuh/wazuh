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
typedef struct w_msg_queue_t{
    w_queue_t *msg_queue;
    pthread_mutex_t mutex;
    pthread_cond_t available;
} w_msg_queue_t;


/* Hash table of queues */
OSHash * msg_queues_table;

/* Message structure */
typedef struct w_message_t {
    char *file;
    char *buffer;
    char *outformat;
    char queue_mq;
    unsigned int size;
    logsocket **target_socket;
} w_message_t;


/* Init queue hash table */
void w_msg_hash_queues_init();

/* Add entry to queue hash table */
int w_msg_hash_queues_add_entry(const char *key);

/* Push message into the hash queue */
int w_msg_hash_queues_push(const char *str,char *file,char *outformat,unsigned long size,logsocket **target_socket,char queue_mq);

/* Pop message from the hash queue */
w_message_t * w_msg_hash_queues_pop(const char *key);

/* Push message into the queue */
int w_msg_queue_push(w_msg_queue_t * msg,const char * buffer,char *file,char *outformat, unsigned long size,logsocket **target_socket,char queue_mq);

/* Pop message from the queue */
w_message_t * w_msg_queue_pop(w_msg_queue_t * queue);

/* Output processing thread*/
void * w_output_thread(void * args);

/* Prepare pool of output threads */
void w_create_output_threads();


#endif /* __LOGREADER_H */
