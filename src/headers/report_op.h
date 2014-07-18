/* @(#) $Id: ./src/headers/report_op.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
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



typedef struct _report_filter
{
    char *report_name;

    char *group;
    char *rule;
    char *level;
    char *location;
    char *user;
    char *srcip;
    char *files;
    char *filename;

    void *top_user;
    void *top_srcip;
    void *top_level;
    void *top_rule;
    void *top_group;
    void *top_location;
    void *top_files;

    int related_user;
    int related_file;
    int related_srcip;
    int related_level;
    int related_rule;
    int related_group;
    int related_location;

    int report_type;
    int show_alerts;
    void *fp;

}report_filter;




int os_report_configfilter(char *filter_by, char *filter_value,
                           report_filter *r_filter, int arg_type);
void os_report_printtop(void *topstore, const char *hname, int print_related);
void os_ReportdStart(report_filter *r_filter);


#endif
