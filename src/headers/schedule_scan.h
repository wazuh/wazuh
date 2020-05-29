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
    time_t next_scheduled_scan_time;/* Absolute time next scheduled event will occur */
    time_t time_start;      /* Do not write, used by the modules          */
} sched_scan_config;

/**
 * Receives pointer to sched_scan_config structure returns
 * absolute time for next event 
 * */
#define sched_get_next_scan_time(x) x.next_scheduled_scan_time

void sched_scan_init(sched_scan_config *scan_config);
void sched_scan_free(sched_scan_config *scan_config);

/**
 * @brief Reads an array of xml nodes and overrides scheduling configuration
 * 
 * Expected xml nodes:
 * ´´´
 * <day></day>
 * <wday></wday>
 * <time></time>
 * <interval></interval>
 * ´´´
 * */
int sched_scan_read(sched_scan_config *scan_config, xml_node **nodes, const char *MODULE_NAME);

/**
 * @brief Calculates time until the next scheduled time according based on scheduling configuration
 * 
 * @param config Scheduling configuration
 * Available options are:
 * 1. Specific day of a month 
 * 2. Specific day of a week
 * 3. Every day at a certain time
 * 4. Set up a scan between intervals
 * @param MODULE_TAG String to identify module
 * @param run_on_start forces first time run
 * @return time until next scan in seconds
 *   stores in config->next_scheduled_scan_time the absolute time where next event 
 *   should occur
 * */
time_t sched_scan_get_time_until_next_scan(sched_scan_config *config, const char *MODULE_TAG, const int run_on_start);

/**
 * @brief Function to check the change of daylight to add or subtract an hour
 * 
 * @param next_scan_time next scan time to check the daylight
 * @param current_daylight current daylight
 */
void check_daylight(int current_daylight, int * future_daylight, int * next_scan_time);

void sched_scan_dump(const sched_scan_config* scan_config, cJSON *cjson_object);
int is_sched_tag(const char* tag);
#endif /* SCHED_SCAN_H */
