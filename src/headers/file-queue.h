/* @(#) $Id$ */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#ifndef __CFQUEUE_H
#define __CFQUEUE_H

#define MAX_FQUEUE  256
#define FQ_TIMEOUT  5

/* File queue */
typedef struct _file_queue
{
    int last_change;
    int year;
    int day;
    char mon[4];
    FILE *fp;
    char file_name[MAX_FQUEUE +1];
    struct stat f_status;
}file_queue;


/*** Prototypes */
#include "read-alert.h"
int Init_FileQueue(file_queue *fileq, struct tm *p);
alert_data *Read_FileMon(file_queue *fileq, struct tm *p, int timeout);

#endif
