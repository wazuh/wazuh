/*
 * Time operations
 * Copyright (C) 2015-2019, Wazuh Inc.
 * October 4, 2017
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32
#include "shared.h"

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

void gettime(struct timespec *ts) {
#ifdef __MACH__
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    ts->tv_sec = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;
#else
    clock_gettime(CLOCK_REALTIME, ts);
#endif
}

// Computes a -= b
void time_sub(struct timespec * a, const struct timespec * b) {
    a->tv_sec -= b->tv_sec;
    a->tv_nsec -= b->tv_nsec;

    if (a->tv_nsec < 0) {
        a->tv_nsec += 1000000000;
        a->tv_sec--;
    }
}

#endif // WIN32

#ifdef WIN32
#include <windows.h>
#define EPOCH_DIFFERENCE 11644473600LL

long long int get_windows_time_epoch() {
    FILETIME ft = {0};
    LARGE_INTEGER li = {0};  

    GetSystemTimeAsFileTime(&ft);
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;

    /* Current machine EPOCH time */
    long long int c_currenttime_epoch = (li.QuadPart / 10000000) - EPOCH_DIFFERENCE;
    return c_currenttime_epoch;
}

long long int get_windows_file_time_epoch(FILETIME ft) {
    LARGE_INTEGER li = {0};  

    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;

    /* Current machine EPOCH time */
    long long int file_time_epoch = (li.QuadPart / 10000000) - EPOCH_DIFFERENCE;
    return file_time_epoch;
}

#endif
