/*   $OSSEC, logcollector.h, v0.2, 2005/08/26, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef __LOGREADER_H

#define __LOGREADER_H

#include <stdio.h> /* for FILE* */
typedef struct _logreader
{
    int mtime;
    int type;
    int ign;
        
	char *file;
	char *group;

    FILE *fp;
}logreader;

int logr_queue;
logreader *logr;

#define FP_TIMEOUT  2

#endif
