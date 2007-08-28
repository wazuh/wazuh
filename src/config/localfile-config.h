/*   $OSSEC, localfile-config.h, v0.3, 2005/11/11, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
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


/* Logreader config */
typedef struct _logreader
{
    unsigned int size;
    int ign;
    ino_t fd;
        
    /* ffile - format file is only used when 
     * the file has format string to retrieve
     * the date,
     */    
    char *ffile;        
	char *file;
	char *logformat;

    void (*read)(int i, int *rc, int drop_it);

    FILE *fp;
}logreader;

typedef struct _logreader_config
{
    logreader *config;
}logreader_config;

#endif
