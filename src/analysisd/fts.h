/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __FTS_H
#define __FTS_H

#include "eventinfo.h"

/* FTS queues */
#ifdef TESTRULE
#define FTS_QUEUE "queue/fts/fts-queue"
#define IG_QUEUE  "queue/fts/ig-queue"
#else
#define FTS_QUEUE "/queue/fts/fts-queue"
#define IG_QUEUE  "/queue/fts/ig-queue"
#endif

int FTS_Init(int threads);
void AddtoIGnore(Eventinfo *lf, int pos);
int IGnore(Eventinfo *lf, int pos);
char * FTS(Eventinfo *lf);
FILE **w_get_fp_ignore();
void FTS_Fprintf(char * _line);
void FTS_Flush();

/* Global variables */
extern unsigned int fts_minsize_for_str;
extern int fts_list_size;

#endif /* __FTS_H */
