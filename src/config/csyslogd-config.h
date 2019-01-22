/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"

#ifndef _CSYSLOGCONFIG__H
#define _CSYSLOGCONFIG__H

/* Database config structure */
typedef struct _SyslogConfig {
    unsigned int port;
    unsigned int format;
    unsigned int level;
    unsigned int *rule_id;
    unsigned int priority;
    unsigned int use_fqdn;
    int socket;

    char *server;
    OSMatch *group;
    OSMatch *location;
} SyslogConfig;

struct SyslogConfig_holder {
    SyslogConfig **data;
};

/* Syslog formats */
#define DEFAULT_CSYSLOG  0
#define CEF_CSYSLOG      1
#define JSON_CSYSLOG     2
#define SPLUNK_CSYSLOG   3

/* Syslog severities */
#define SLOG_EMERG   0   /* system is unusable */
#define SLOG_ALERT   1   /* action must be taken immediately */
#define SLOG_CRIT    2   /* critical conditions */
#define SLOG_ERR     3   /* error conditions */
#define SLOG_WARNING 4   /* warning conditions */
#define SLOG_NOTICE  5   /* normal but significant condition */
#define SLOG_INFO    6   /* informational */
#define SLOG_DEBUG   7   /* debug-level messages */

#endif /* _CSYSLOGCONFIG__H */
