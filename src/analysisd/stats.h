/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef STAT_H
#define STAT_H

int Init_Stats_Directories();

extern char __stats_comment[192];
extern int maxdiff;
extern int mindiff;
extern int percent_diff;

void Update_Hour(void);
int Check_Hour(void);
int Start_Hour(int t_id, int threads_number);
void Start_Time();
#endif /* STAT_H */
