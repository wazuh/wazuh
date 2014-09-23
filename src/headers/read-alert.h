/* @(#) $Id: ./src/headers/read-alert.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#ifndef __CRALERT_H
#define __CRALERT_H

#define CRALERT_MAIL_SET    0x001
#define CRALERT_EXEC_SET    0x002
#define CRALERT_READ_ALL    0x004
#define CRALERT_FP_SET      0x010


/* File queue */
typedef struct _alert_data
{
    int rule;
    int level;
    char *alertid;
    char *date;
    char *location;
    char *comment;
    char *group;
    char *srcip;
    int srcport;
    char *dstip;
    int dstport;
    char *user;
    char *filename;
    char *old_md5;
    char *new_md5;
    char *old_sha1;
    char *new_sha1;
    char **log;
#ifdef GEOIP
    char *geoipdatasrc;
    char *geoipdatadst;
#endif
}alert_data;


alert_data *GetAlertData(int flag, FILE *fp) __attribute__((nonnull));
void FreeAlertData(alert_data *al_data) __attribute__((nonnull));


#endif
