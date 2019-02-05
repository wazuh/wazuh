/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _MQ__H
#define _MQ__H

#include "config/localfile-config.h"

/* Default queues */
#define LOCALFILE_MQ    '1'
#define SYSLOG_MQ       '2'
#define HOSTINFO_MQ     '3'
#define SECURE_MQ       '4'
#define SYSCHECK_MQ     '8'
#define ROOTCHECK_MQ    '9'
#define EVENT_MQ        '10'


/* Queues for additional log types */
#define MYSQL_MQ         'a'
#define POSTGRESQL_MQ    'b'
#define AUTH_MQ          'c'
#define SYSCOLLECTOR_MQ  'd'
#define CISCAT_MQ        'e'
#define WIN_EVT_MQ       'f'

#define MAX_OPENQ_ATTEMPS 15

extern int sock_fail_time;

int StartMQ(const char *key, short int type) __attribute__((nonnull));

int SendMSG(int queue, const char *message, const char *locmsg, char loc) __attribute__((nonnull));

int SendMSGtoSCK(int queue, const char *message, const char *locmsg, char loc, logtarget * target) __attribute__((nonnull (2, 3, 5)));

#endif
