/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _STAT__H
#define _STAT__H

void LastMsg_Change(const char *log);
int LastMsg_Stats(const char *log);

extern char __stats_comment[192];

void Update_Hour(void);
int Check_Hour(void);
int Start_Hour(void);

#endif /* _STAT__H */

