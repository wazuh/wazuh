/* @(#) $Id: ./src/headers/file-queue.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
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
    time_t last_change;
    int year;
    int day;
    int flags;

    char mon[4];
    char file_name[MAX_FQUEUE +1];

    FILE *fp;
    struct stat f_status;
}file_queue;


/*** Prototypes */
#include "read-alert.h"
int Init_FileQueue(file_queue *fileq, const struct tm *p, int flags) __attribute__((nonnull));

alert_data *Read_FileMon(file_queue *fileq, const struct tm *p, int timeout) __attribute__((nonnull));

#endif
