/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _MCCONFIG__H
#define _MCCONFIG__H

#include "shared.h"

#define MAIL_SOURCE_LOGS 0
#define MAIL_SOURCE_JSON 1

/* Mail config structure */
typedef struct _MailConfig {
    int mn;
    int maxperhour;
    int strict_checking;
    int grouping;
    int subject_full;
    int priority;
    char **to;
    char *reply_to;
    char *from;
    char *idsname;
    char *smtpserver;
    char *heloserver;
    int source;

    /* Granular e-mail options */
    unsigned int *gran_level;
    unsigned int **gran_id;
    int *gran_set;
    int *gran_format;
    char **gran_to;

#ifdef LIBGEOIP_ENABLED
    /* Use GeoIP */
    int geoip;
#endif

    OSMatch **gran_location;
    OSMatch **gran_group;
} MailConfig;

/* Email message formats */
#define FULL_FORMAT     2
#define SMS_FORMAT      3
#define FORWARD_NOW     4
#define DONOTGROUP      5

#endif /* _MCCONFIG__H */
