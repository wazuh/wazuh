/* Copyright (C) 2015-2019, Wazuh Inc.
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
#define DATE_MODIFIED   1
#define DEFAULT_EVENTCHANNEL_REC_TIME 5

#include <pthread.h>

/* For ino_t */
#include <sys/types.h>
#include "labels_op.h"

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
    long linecount;
    char *djb_program_name;
    char *command;
    char *alias;
    int reconnect_time;
    char future;
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

#endif /* CLOGREADER_H */
