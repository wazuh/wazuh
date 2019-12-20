/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


/**
 * Shared API to treat scheduled events
 */
#ifndef SCHED_SCAN_H
#define SCHED_SCAN_H

typedef struct _sched_scan_config {
    bool scan_on_start;     /* Force initial scan on startup       */
    int scan_day;           /* Day of the month [1..31]            */
    int scan_wday;          /* Day of the week [0..6]              */
    char* scan_time;        /* Time of day [hh:mm]                 */
    unsigned int interval;  /* Interval betweeen events in seconds */
    time_t time_start;      /* Last scan time                      */
} sched_scan_config;

time_t sched_scan_get_next_time(const sched_scan_config *config);

#endif /* SCHED_SCAN_H */