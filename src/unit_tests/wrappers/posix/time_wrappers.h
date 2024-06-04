/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef TIME_WRAPPERS_H
#define TIME_WRAPPERS_H

#include <time.h>
#include <sys/time.h>

time_t __wrap_time(time_t *t);
char *__wrap_ctime_r(const time_t *timep, char *buf);

void __wrap_gettimeofday(__attribute__((unused))struct timeval *__restrict __tv, __attribute__((unused)) void *__restrict __tz);

#endif // TIME_WRAPPERS_H
