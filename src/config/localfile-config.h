/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __CLOGREADER_H
#define __CLOGREADER_H

#define EVENTLOG     "eventlog"
#define EVENTCHANNEL "eventchannel"
#define DATE_MODIFIED   1

/* For ino_t */
#include <sys/types.h>
#include "labels_op.h"

typedef struct _logsocket {
    char *name;
    char *location;
    int mode;
    char *prefix;
    int socket;
    time_t last_attempt;
} logsocket;

/* Logreader config */
typedef struct _logreader {
    off_t size;
    int ign;

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
    char future;
    char *query;
    char *outformat;
    char **target;
    logsocket **target_socket;
    int duplicated;
    wlabel_t *labels;

    void *(*read)(int i, int *rc, int drop_it);

    FILE *fp;
} logreader;

typedef struct _logreader_config {
    int agent_cfg;
    int accept_remote;
    logreader *config;
    logsocket *socket_list;
} logreader_config;

/* Frees the Localfile struct  */
void Free_Localfile(logreader_config * config);

#endif /* __CLOGREADER_H */
