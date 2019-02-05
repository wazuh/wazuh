/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __REPORT_OP_H
#define __REPORT_OP_H

#define REPORT_RELATED      1
#define REPORT_FILTER       2

#define REPORT_REL_USER          0x001
#define REPORT_REL_SRCIP         0x002
#define REPORT_REL_LEVEL         0x004
#define REPORT_REL_RULE          0x010
#define REPORT_REL_GROUP         0x020
#define REPORT_REL_LOCATION      0x040
#define REPORT_TYPE_DAILY        0x100
#define REPORT_REL_FILE          0x200

typedef struct _report_filter {
    const char *report_name;

    const char *group;
    const char *rule;
    const char *level;
    const char *location;
    const char *user;
    const char *srcip;
    const char *files;
    char *filename;

    OSStore *top_user;
    OSStore *top_srcip;
    OSStore *top_level;
    OSStore *top_rule;
    OSStore *top_group;
    OSStore *top_location;
    OSStore *top_files;

    int related_user;
    int related_file;
    int related_srcip;
    int related_level;
    int related_rule;
    int related_group;
    int related_location;

    int report_type;
    int show_alerts;
    FILE *fp;

} report_filter;

int  os_report_configfilter(const char *filter_by, const char *filter_value,
                            report_filter *r_filter, int arg_type) __attribute__((nonnull(3)));
void os_report_printtop(void *topstore, const char *hname, int print_related) __attribute__((nonnull));
void os_ReportdStart(report_filter *r_filter) __attribute__((nonnull));

#endif

