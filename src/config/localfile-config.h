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

#define EVENTLOG    "eventlog"
#define VCHECK_FILES    64 
#define DATE_MODIFIED   1


/* For ino_t */
#include <sys/types.h>

// Readers that employ internal timers and should be regularly
// called no matter if something was written to file, or not!
#define LOGREADER_FLAG_TIMERS	0x00000001 

/* Logreader config */
typedef struct _logreader
{
    int flags;

    unsigned int size;
    int ign;

    #ifdef WIN32
    HANDLE h;
    int fd;
    #else
    ino_t fd;
    #endif

    FILE *fp;

    /* ffile - format file is only used when 
     * the file has format string to retrieve
     * the date,
     */    
    char *ffile;        
    char *file;
    char *logformat;
	
    int (*read)(int i, int drop_it);

    // Private configuration data of specific log reader
    union
    {
        /* djb_program log reader */
        char *djb_program_name;

        /* multiline log reader */
        int lines;

        /* For read_command and read_fullcommand log readers */
        struct
        {
            // read_command and read_fullcommand log readers
            char *command;
            char *alias;
        };

        /* For Linux audit log reader */
        struct
        {
            // == 0 -> not used, != 0 used. Only one != 0!
            int timeout;
            int window;
        };

        /* Logreader config for regex configuration types */
        struct
        {
            char *start_regex;
            char *end_regex;
        };

        /* Dynamic private data that can be used by each log reader */
    };

    void *private_data;
}logreader;

typedef struct _logreader_config
{
    int agent_cfg;
    int accept_remote;
    logreader *config;
}logreader_config;

#endif
