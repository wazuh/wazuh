/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _MONITORD_H
#define _MONITORD_H

#ifndef ARGV0
#define ARGV0 "ossec-monitord"
#endif

#include "config/reports-config.h"

#define MAX_DAY_WAIT 600

/* Prototypes */
void Monitord(void) __attribute__((noreturn));
void manage_files(int cday, int cmon, int cyear);
void generate_reports(int cday, int cmon, int cyear, const struct tm *p);
void monitor_agents(void);
void OS_SignLog(const char *logfile, const char *logfile_old, int log_missing);
void OS_CompressLog(const char *logfile);
void w_rotate_log(int compress, int keep_log_days, int new_day, int rotate_json, int daily_rotations);

/* Global variables */
extern monitor_config mond;

#endif
