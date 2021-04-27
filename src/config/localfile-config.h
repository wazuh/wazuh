/* Copyright (C) 2015-2021, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CLOGREADER_H
#define CLOGREADER_H

#define EVENTLOG     "eventlog"
#define EVENTCHANNEL "eventchannel"
#define MULTI_LINE_REGEX              "multi-line-regex"
#define MULTI_LINE_REGEX_TIMEOUT      5
#define MULTI_LINE_REGEX_MAX_TIMEOUT  120
#define DATE_MODIFIED   1
#define DEFAULT_EVENTCHANNEL_REC_TIME 5
#define DIFF_DEFAULT_SIZE 10 * 1024 * 1024
#define DIFF_MAX_SIZE (2 * 1024 * 1024 * 1024LL)

#include <pthread.h>

/* For ino_t */
#include <sys/types.h>
#include "labels_op.h"
#include "expression.h"
#include "os_xml/os_xml.h"

extern int maximum_files;
extern int total_files;
extern int current_files;

typedef struct _logsocket {
    char *name;
    char *location;
    int mode;
    char *prefix;
    int socket;
    time_t last_attempt;
} logsocket;

typedef struct _outformat {
    char * target;
    char * format;
} outformat;

typedef struct _logtarget {
    char * format;
    logsocket * log_socket;
} logtarget;

/* Logreader config */
/**
 * @brief Specifies end-of-line replacement type in multiline log (multi-line-regex log format)
 */
typedef enum {
    ML_REPLACE_NO_REPLACE = 0, ///< Not replace
    ML_REPLACE_NONE,           ///< Remove end of line character
    ML_REPLACE_WSPACE,         ///< Replace with a white space character (' ')
    ML_REPLACE_TAB,            ///< Replace with a tab character ('\t')
    ML_REPLACE_MAX             ///< Flow control
} w_multiline_replace_type_t;

/**
 * @brief Specifies the type of multiline matching
 */
typedef enum {
    ML_MATCH_START = 0, ///< Matches a log by its header
    ML_MATCH_ALL,       ///< Matches a log of all your content
    ML_MATCH_END,       ///< Matches a log by its tail
    ML_MATCH_MAX,       ///< Flow control
} w_multiline_match_type_t;

/**
 * @brief Context of a multiline log that was not completely written.
 * 
 * An instance of w_multiline_timeout_ctxt_t allow save the context of a log that have not yet matched with the regex.
 */
typedef struct {
    int lines_count;   ///< number of readed lines from a multiline log
    char * buffer;     ///< backup buffer. Contains readed line so far
    time_t timestamp;  ///< last successful read
} w_multiline_ctxt_t;

/**
 * @brief An instance of w_multiline_config_t represents a multiline log file and its read configuration
 */
typedef struct {
    w_expression_t * regex;                  ///< regex to identify log entries
    w_multiline_match_type_t match_type;     ///< type of multiline matching
    w_multiline_replace_type_t replace_type; ///< replacement type
    /** Max waiting time to receive a new line, once the time has expired, the collected lines are sent */
    unsigned int timeout;
    w_multiline_ctxt_t * ctxt; ///< store current status when multiline log is in process
    int64_t offset_last_read;  ///< absolut file offset of last complete multiline log processed
} w_multiline_config_t;

/* Logreader config */
typedef struct _logreader {
    off_t size;
    int ign;
    dev_t dev;

#ifdef WIN32
    HANDLE h;
    DWORD fd;
#else
    ino_t fd;
#endif

    /* ffile - format file is only used when
     * the file has format string to retrieve
     * the date,
     */
    char *ffile;
    char *file;
    char *logformat;
    w_multiline_config_t * multiline;
    long linecount;
    char *djb_program_name;
    char *command;
    char *alias;
    int reconnect_time;
    char future;
    long diff_max_size;
    char *query;
    int filter_binary;
    int ucs2;
    outformat ** out_format;
    char **target;
    logtarget * log_target;
    int duplicated;
    char *exclude;
    wlabel_t *labels;
    pthread_mutex_t mutex;
    int exists;
    unsigned int age;
    char *age_str;

    void *(*read)(struct _logreader *lf, int *rc, int drop_it);

    FILE *fp;
    fpos_t position; // Pointer offset when closed
} logreader;

typedef struct _logreader_glob {
    char *gpath;
    char *exclude_path;
    int num_files;
    logreader *gfiles;
} logreader_glob;

typedef struct _logreader_config {
    int agent_cfg;
    int accept_remote;
    logreader_glob *globs;
    logreader *config;
    logsocket *socket_list;
} logreader_config;

/* Frees the Logcollector config struct  */
void Free_Localfile(logreader_config * config);

/* Frees a localfile  */
void Free_Logreader(logreader * config);

/* Removes a specific localfile of an array */
int Remove_Localfile(logreader **logf, int i, int gl, int fr, logreader_glob *globf);

/**
 * @brief Get match attribute for multiline regex 
 * @param node node to find match value
 * @retval ML_MATCH_START if match is "start" or if the attribute is not present
 * @retval ML_MATCH_ALL if match is "all"
 * @retval ML_MATCH_END if match is "end"
 */
w_multiline_match_type_t w_get_attr_match(xml_node * node);

/**
 * @brief Get replace attribute for multiline regex 
 * @param node node to find match value
 * @retval ML_REPLACE_NO_REPLACE if replace is "no-replace" or if the attribute is not present
 * @retval ML_REPLACE_WSPACE if replace is "wspace"
 * @retval ML_REPLACE_TAB if replace is "tab"
 * @retval ML_REPLACE_NONE if replace is "none"
 */
w_multiline_replace_type_t w_get_attr_replace(xml_node * node);

/**
 * @brief Get timeout attribute for multiline regex
 * @param node node to find match value
 * @retval MULTI_LINE_REGEX_TIMEOUT if the attribute is invalid or not present
 * @retval timeout value otherwise
 */
unsigned int w_get_attr_timeout(xml_node * node);

/**
 * @brief Get replace type in string format
 * @param replace_type replace type of multiline matching
 * @return const char* replace type
 */
const char * multiline_attr_replace_str(w_multiline_replace_type_t replace_type);

/**
 * @brief Get match type in string format
 * @param match_type  type of multiline matching
 * @return const char* match type
 */
const char * multiline_attr_match_str(w_multiline_match_type_t match_type);


#endif /* CLOGREADER_H */
