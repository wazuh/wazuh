/* Copyright (C) 2015-2020, Wazuh Inc.
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
    int scan_day;           /* Day of the month [1..31]                   */
    int scan_wday;          /* Day of the week [0..6]                     */
    char* scan_time;        /* Time of day [hh:mm]                        */
    unsigned int interval;  /* Interval betweeen events in seconds        */
    bool month_interval;    /* Flag to determine if interval is in months */
    time_t time_start;      /* Last scan time                             */
} sched_scan_config;

void sched_scan_init(sched_scan_config *scan_config);
int sched_scan_read(sched_scan_config *scan_config, xml_node **nodes, const char *MODULE_NAME);
time_t sched_scan_get_next_time(sched_scan_config *config, const char *MODULE_TAG, const int run_on_start);
void sched_scan_dump(const sched_scan_config* scan_config, cJSON *cjson_object);
int is_sched_tag(const char* tag);
#endif /* SCHED_SCAN_H */
