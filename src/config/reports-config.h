/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _REPORTSCONFIG_H
#define _REPORTSCONFIG_H

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
    unsigned int monitor_agents:1;
    unsigned int rotate_log:1;
    unsigned int rotate_alerts:1;
    unsigned int rotate_archives:1;
    unsigned int delete_old_agents:1;
    int a_queue;
    int keep_log_days;
    int keep_rotated_files;
    unsigned long size_rotate;
    int daily_rotations;

    char *smtpserver;
    char *emailfrom;
    char *emailidsname;

    // Rotation options
    unsigned int enabled:1;
    unsigned int rotation_enabled:1;
    unsigned int compress_rotation:1;
    char **format;
    long int max_size;
    long int interval;
    int rotate;

    char **agents;
    report_config **reports;
} monitor_config;

#endif /* _REPORTSCONFIG_H */
