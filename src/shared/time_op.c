/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/**
 * @file time_op.c
 * @brief Time operations
 * @date October 4, 2017
 */

#include "shared.h"

#ifndef WIN32

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

// Get the current calendar time

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

#else

#include <windows.h>
#define EPOCH_DIFFERENCE 11644473600LL

// Get the epoch time

long long int get_windows_time_epoch() {
    FILETIME ft = {0};

    GetSystemTimeAsFileTime(&ft);
    return get_windows_file_time_epoch(ft);
}

// Get the epoch time from a FILETIME object

long long int get_windows_file_time_epoch(FILETIME ft) {
    LARGE_INTEGER li = {0};

    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;

    /* Current machine EPOCH time */
    long long int file_time_epoch = (li.QuadPart / 10000000) - EPOCH_DIFFERENCE;
    return file_time_epoch;
}

void gettime(struct timespec * ts) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);

    LARGE_INTEGER li = {.LowPart = ft.dwLowDateTime, .HighPart = ft.dwHighDateTime};

    // Contains a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC).

    ts->tv_sec = li.QuadPart / 10000000 - EPOCH_DIFFERENCE;
    ts->tv_nsec = (li.QuadPart % 10000000) * 100;
}

#endif

char *w_get_timestamp(time_t time) {
    struct tm localtm;
    char *timestamp;

    localtime_r(&time, &localtm);

    os_calloc(TIME_LENGTH, sizeof(char), timestamp);

    snprintf(timestamp, TIME_LENGTH, "%d/%02d/%02d %02d:%02d:%02d",
            localtm.tm_year + 1900, localtm.tm_mon + 1,
            localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

    return timestamp;
}


void w_sleep_until(const time_t abs_time) {
    while( time(NULL) < abs_time ) {
        w_time_delay(1000);
    }
}

void w_time_delay(unsigned long int ms) {
#ifdef WIN32
    Sleep(ms);
#else
    struct timeval timeout = { ms / 1000, (ms % 1000) * 1000};
    select(0, NULL, NULL, NULL, &timeout);
#endif
}

// Compute time substraction "a - b"

void time_sub(struct timespec * a, const struct timespec * b) {
    a->tv_sec -= b->tv_sec;
    a->tv_nsec -= b->tv_nsec;

    if (a->tv_nsec < 0) {
        a->tv_nsec += 1000000000;
        a->tv_sec--;
    }
}

// Get the time elapsed between a and b (in seconds)

double time_diff(const struct timespec * a, const struct timespec * b) {
    return b->tv_sec - a->tv_sec + (b->tv_nsec - a->tv_nsec) / 1e9;
}

// Function to check if a year is a leap year or not.

bool is_leap_year(int year) {
    bool result = false;

    if ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0) {
        result = true;
    }

    return result;
}
