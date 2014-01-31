/*   $OSSEC, localfile-config.h, v0.3, 2005/11/11, Daniel B. Cid$   */

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
#define VCHECK_FILES    64
#define DATE_MODIFIED   1


/* For ino_t */
#include <sys/types.h>


/* Logreader config */
typedef struct _logreader
{
    unsigned int size;
    int ign;

    #ifdef WIN32
    HANDLE h;
    int fd;
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
    char *djb_program_name;
    char *command;
    char *alias;
    char future;
    char *query;
	
    void (*read)(int i, int *rc, int drop_it);

    FILE *fp;
}logreader;

typedef struct _logreader_config
{
    int agent_cfg;
    int accept_remote;
    logreader *config;
}logreader_config;

#endif
