/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _LOGAUDIT__H
#define _LOGAUDIT__H

#include <sys/types.h>

/* Time structures */
int today;
int thishour;

int prev_year;
char prev_month[4];

int __crt_hour;
int __crt_wday;

time_t c_time; /* Current time of event. Used everywhere */

/* Local host name */
char __shost[512];

void *NULL_Decoder;

#define OSSEC_SERVER    "ossec-server"

#endif /* _LOGAUDIT__H */

