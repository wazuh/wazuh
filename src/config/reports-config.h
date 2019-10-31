/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef REPORTSCONFIG_H
#define REPORTSCONFIG_H

#include "report_op.h"

/* Structure for the report */
typedef struct _report_config {
    char *title;
    char *args;
    char *relations;
    char *type;
    char **emailto;
    report_filter r_filter;
} report_config;

typedef struct _monitor_config {
    short int day_wait;
    unsigned int compress:1;
    unsigned int sign:1;
    int monitor_agents;
    unsigned int rotate_log:1;
    int delete_old_agents;
    int a_queue;
    int maxage;
    int keep_rotated_files;
    unsigned long min_size_rotate;  // This is the value that we put in the configuration (not converted to bytes). We need it to show the configuration.
    unsigned long size_rotate;      // This is the value that we put in the configuration (not converted to bytes). We need it to show the configuration.
    int daily_rotations;
    int thread_stack_size;

    char *smtpserver;
    char *emailfrom;
    char *emailidsname;

    // Rotation options
    unsigned int enabled:1;
    unsigned int rotation_enabled:1;
    unsigned int compress_rotation:1;
    unsigned int ossec_log_plain:1;
    unsigned int ossec_log_json:1;
    OSList *ossec_rotation_files;
    long int min_size;
    char min_size_units;    // Character that indicates the units of the log file size (Bytes, KBytes, MBytes, GBytes)
    long int max_size;
    char size_units;        // Character that indicates the units of the log file size (Bytes, KBytes, MBytes, GBytes)
    long int interval;
    char interval_units;    // Character that indicates the units of the interval before the log file is rotated (seconds, minutes, hours or days)
    int rotate;
    int log_level;
    rotation_list *log_list_plain;
    rotation_list *log_list_json;

    char **agents;
    report_config **reports;
} monitor_config;

#endif /* REPORTSCONFIG_H */
