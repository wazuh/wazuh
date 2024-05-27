/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LOGREADER_H
#define LOGREADER_H

#ifndef ARGV0
#define ARGV0 "wazuh-logcollector"
#endif

#define N_MIN_INPUT_THREADS 1
#define N_OUPUT_THREADS 1
#define OUTPUT_MIN_QUEUE_SIZE 128
#define WIN32_MAX_FILES 200

///< Size of hash table to save the status file
#define LOCALFILES_TABLE_SIZE 40

///< JSON path wich contains the files position of last read
#ifdef WIN32
#define LOCALFILE_STATUS   "queue\\logcollector\\file_status.json"
#else
#define LOCALFILE_STATUS        "queue/logcollector/file_status.json"
#endif

///< JSON fields for file_status
#define OS_LOGCOLLECTOR_JSON_FILES      "files"
#define OS_LOGCOLLECTOR_JSON_PATH       "path"
#define OS_LOGCOLLECTOR_JSON_HASH       "hash"
#define OS_LOGCOLLECTOR_JSON_OFFSET     "offset"


#include "shared.h"
#include "../config/localfile-config.h"
#include "../config/config.h"
#include "../os_crypto/sha1/sha1_op.h"
#include "macos_log.h"


/*** Function prototypes ***/

/* Read logcollector config */
int LogCollectorConfig(const char *cfgfile);

/* Parse read config into JSON format */
cJSON *getLocalfileConfig(void);
cJSON *getSocketConfig(void);
cJSON *getLogcollectorInternalOptions(void);

/* Start log collector daemon */
void LogCollectorStart(void) __attribute__((noreturn));

/* Handle files */
int handle_file(int i, int j, int do_fseek, int do_log);

/* Reload file: open after close, and restore position */
int reload_file(logreader * lf);

/* Close file and save position */
void close_file(logreader * lf);

/* Read syslog file */
void *read_syslog(logreader *lf, int *rc, int drop_it);

#ifdef WIN32
/* Read ucs2 LE file*/
void *read_ucs2_le(logreader *lf, int *rc, int drop_it);

/* Read ucs2 BE file */
void *read_ucs2_be(logreader *lf, int *rc, int drop_it);
#endif

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

/* Read multi line logs */
void *read_multiline(logreader *lf, int *rc, int drop_it);

/**
 * @brief Check if any logs should be ignored
 *
 * @param ignore_exp List of ignore regex expressions to be checked
 * @param restrict_exp List of restrict regex expressions to be checked
 * @param log_line Log where to search for a match
 * @return 0 if log should be processed, 1 if log should be ignored
 */
int check_ignore_and_restrict(OSList * ignore_exp, OSList * restrict_exp, const char *log_line);

/**
 * @brief Read multi line logs with variable lenght
 *
 * @param lf status and configuration of the log file
 * @param rc output parameter, returns zero
 * @param drop_it if drop_it is different from 0, the logs will be read and discarded
 * @return NULL
 */
void *read_multiline_regex(logreader *lf, int *rc, int drop_it);

#if defined(Darwin) || (defined(__linux__) && defined(WAZUH_UNIT_TESTING))
/**
 * @brief Read macOS log process output
 *
 * @param lf status and configuration of the macOS instance
 * @param rc output parameter, returns zero
 * @param drop_it if drop_it is different from 0, the logs will be read and discarded
 * @return NULL
 */
void *read_macos(logreader *lf, int *rc, int drop_it);
#endif

#ifdef __linux__
/**
 * @brief Read journald logs
 *
 * @param lf status and configuration of the log file
 * @param rc output parameter, returns zero
 * @param drop_it if drop_it is different from 0, the logs will be read and discarded
 * @return NULL
 */
void *read_journald(logreader *lf, int *rc, int drop_it);

/**
 * @brief Check if journald can be read for a specific id
 * 
 * If the journal is not opened, the the function try to open it, returning false if it fails and true if it succeeds.
 * The function sets the id as the owner of the journal.
 * If the journal is opened, the function checks if the id is the owner of the journal,
 * returning true if it is, and false if it is not.
 * @param id the id to be checked
 * @return true if the id is the owner of the journal, false otherwise
 * @note This function is not thread-safe.
 */
bool w_journald_can_read(unsigned long id); 

/**
 * @brief Set the only future events flag to the journal log context
 * @param ofe True if only future events should be read, false otherwise
 */
void w_journald_set_ofe(bool ofe);

/**
 * @brief Set the status of the journal log from a JSON object (timestamp to start reading)
 * 
 * @param global_json JSON object containing the journal log status
 */
void w_journald_set_status_from_JSON(cJSON * global_json);

/**
 * @brief Get the status of the journal log as a JSON object
 * 
 * @return JSON object containing the journal log status
 */
cJSON * w_journald_get_status_as_JSON();

#endif

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
int win_start_event_channel(char *evt_log, char future, char *query, int reconnect_time);
void win_format_event_string(char *string);
#endif

#ifndef WIN32
// Com request thread dispatcher
void * lccom_main(void * arg);
#endif
size_t lccom_dispatch(char * command, char ** output);
size_t lccom_getconfig(const char * section, char ** output);
size_t lccom_getstate(char ** output, bool getNextPage);

/*** Global variables ***/
extern int loop_timeout;
extern int logr_queue;
extern int open_file_attempts;
extern logreader *logff;
extern logreader_glob *globs;
extern socket_forwarder *logsk;
extern int vcheck_files;
extern int maximum_lines;
extern socket_forwarder default_agent;
extern int force_reload;
extern int reload_interval;
extern int reload_delay;
extern int free_excluded_files_interval;
extern int state_interval;

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
extern OSHash * msg_queues_table;

/* Message structure */
typedef struct w_message_t {
    char *file;
    char *buffer;
    char queue_mq;
    unsigned int size;
    logtarget *log_target;
} w_message_t;


/* Input thread range */
typedef struct w_input_range_t{
    int start_i;
    int start_j;
    int end_i;
    int end_j;
} w_input_range_t;

///< Struct to save the position of last line read and the SHA1 hash content
typedef struct file_status {
    int64_t offset;  ///< Position to read
    EVP_MD_CTX *context;    ///< It stores the hashed data calculated so far
    os_sha1 hash;       ///< Content file SHA1 hash
} os_file_status_t;

extern w_input_range_t *w_input_threads_range;

/* Init queue hash table */
void w_msg_hash_queues_init();

/* Add entry to queue hash table */
int w_msg_hash_queues_add_entry(const char *key);

/* Push message into the hash queue */
int w_msg_hash_queues_push(const char *str, char *file, unsigned long size, logtarget * targets, char queue_mq);

/* Push message into the queue */
int w_msg_queue_push(w_msg_queue_t * msg, const char * buffer, char *file, unsigned long size, logtarget * log_target, char queue_mq);

/* Pop message from the queue */
w_message_t * w_msg_queue_pop(w_msg_queue_t * queue);

/* Output processing thread*/
#ifdef WIN32
DWORD WINAPI w_output_thread(void * args);
#else
void * w_output_thread(void * args);
#endif

/* Prepare pool of output threads */
void w_create_output_threads();

/* Input processing thread */
#ifdef WIN32
DWORD WINAPI w_input_thread(__attribute__((unused)) void * t_id);
#else
void * w_input_thread(__attribute__((unused)) void * t_id);
#endif

/* Prepare pool of input threads */
void w_create_input_threads();

/* Set mutexes for each file */
void w_set_file_mutexes();

/* Read stop signal from reader threads */
int can_read();

/**
 * @brief Update the read position in file status hash table
 * @param path the path is the hash key
 * @param pos new read position
 * @param context EVP_MD_CTX context.
 * @return 0 on succes, otherwise -1
 */
int w_update_file_status(const char * path, int64_t pos, EVP_MD_CTX *context);

/**
 * @brief Get EVP_MD_CTX context or initialize it
 * @param lf Structure that contains file information, with `fd` and `file` non-null.
 * @param context EVP_MD_CTX context.
 * @param position end file position.
 * @return true if returns a valid context, false in otherwise.
 */
bool w_get_hash_context(logreader *lf, EVP_MD_CTX **context, int64_t position);

extern int sample_log_length;
extern int lc_debug_level;
extern int accept_remote;
extern int N_INPUT_THREADS;
extern int OUTPUT_QUEUE_SIZE;
#ifndef WIN32
extern rlim_t nofile;
#endif

#if defined(Darwin) || (defined(__linux__) && defined(WAZUH_UNIT_TESTING))
/**
 * @brief This function is called to release macOS log's "show" and/or "stream" resources
 */
void w_macos_release_log_execution(void);

/**
 * @brief This function is called to release macOS log's "show" resources
 */
void w_macos_release_log_show(void);

/**
 * @brief This function is called to release macOS log's "stream" resources
 */
void w_macos_release_log_stream(void);
#endif

#endif /* LOGREADER_H */
