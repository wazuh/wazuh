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

#define MAX_READ_FILE   16

/* Logreader config */
typedef struct _logreader
{
    int mtime;
    char type;
    int ign;
        
	char *file;
	char *logformat;

    void (*read)(int i, int *rc);

    FILE *fp;
}logreader;


#endif
