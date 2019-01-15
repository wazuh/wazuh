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
