/* @(#) $Id$ */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */



#ifndef __CRALERT_H
#define __CRALERT_H

#define CRALERT_MAIL_SET    1
#define CRALERT_EXEC_SET    2

/* File queue */
typedef struct _alert_data
{
    int rule;
    int level;
    char *date;
    char *location;
    char *comment;
    char *group;
    char *srcip;
    char *user;
    char **log;
}alert_data;


alert_data *GetAlertData(int flag, FILE *fp);
void FreeAlertData(alert_data *al_data);


#endif
