/*
 * Time operations
 * Copyright (C) 2015-2019, Wazuh Inc.
 * October 4, 2017
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"

#ifndef WIN32
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

#ifdef WIN32
#include <shared.h>
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

int day_to_int(const char *day)
{
#ifndef WIN32
    struct tm timeinfo;
    int wday;

    if (!strptime(day, "%A", &timeinfo))
    {
        return 0;
    }

    wday = timeinfo.tm_wday;
    return wday ? wday : 7;
#else
    int i = 0;
    char *wday = strdup(day);
    const char *(weekdays[]) = {"monday", "tuesday", "wednesday", "thursday",
                      "friday", "saturday", "sunday"};

    str_lowercase(wday);

    while (i < 7)
    {
        if (!strcmp(wday, weekdays[i])) {
            os_free(wday);
            return i+1;
        }
        i++;
    }

    os_free(wday);
    return 0;

#endif
}

char *int_to_day(int day)
{
    struct tm timeinfo;
    char *buffer = NULL;
    os_calloc(80, sizeof(char), buffer);

    timeinfo.tm_wday = day % 7;
    strftime(buffer, 80,"%A", &timeinfo);

    return buffer;
}
