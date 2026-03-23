/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifdef WIN32
#include <windows.h>
#endif
#include "time_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

time_t current_time = 0;

void __wrap_w_sleep_until(const time_t new_time){
    current_time = new_time;
}

void __wrap_w_time_delay(unsigned long int msec){
    current_time += (msec/1000);
}

char* __wrap_w_get_timestamp(time_t time) {
    check_expected(time);

    return mock_type(char*);
}

void __wrap_gettime(struct timespec *ts) {
    ts->tv_sec = mock_type(time_t);
}

double __wrap_time_diff(__attribute__((unused)) const struct timespec * a, __attribute__((unused)) const struct timespec * b) {
    return mock_type(double);
}

#ifdef WIN32
long long __wrap_get_windows_file_time_epoch(FILETIME ftime) {
    check_expected(ftime.dwLowDateTime);
    check_expected(ftime.dwHighDateTime);

    return mock_type(long long);
}
#endif
