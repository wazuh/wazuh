/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef TIME_OP_WRAPPERS_H
#define TIME_OP_WRAPPERS_H

#include <time.h>

void __wrap_w_sleep_until(const time_t new_time);

void __wrap_w_time_delay(unsigned long int msec);

char* __wrap_w_get_timestamp(time_t time);

double __wrap_time_diff(__attribute__((unused)) const struct timespec * a, __attribute__((unused)) const struct timespec * b);

extern time_t current_time;

#ifdef WIN32
long long int __wrap_get_windows_file_time_epoch(FILETIME ft);
#endif
void __wrap_gettime(struct timespec *ts);

#endif
