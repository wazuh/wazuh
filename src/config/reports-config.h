/* Copyright (C) 2015-2020, Wazuh Inc.
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
    unsigned int monitor_agents:1;
    unsigned int rotate_log:1;
    unsigned int delete_old_agents;
    int a_queue;
    int keep_log_days;
    unsigned long size_rotate;
    int daily_rotations;

    char *smtpserver;
    char *emailfrom;
    char *emailidsname;

    char **agents;
    report_config **reports;
} monitor_config;

#endif /* REPORTSCONFIG_H */
