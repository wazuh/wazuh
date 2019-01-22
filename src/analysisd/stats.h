/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _STAT__H
#define _STAT__H

void LastMsg_Change(const char *log, int t_id);
int LastMsg_Stats(const char *log, int t_id);
int Init_Stats_Directories();

extern char __stats_comment[192];
extern int maxdiff;
extern int mindiff;
extern int percent_diff;

void Update_Hour(void);
int Check_Hour(void);
int Start_Hour(int t_id, int threads_number);
void Start_Time();
#endif /* _STAT__H */
