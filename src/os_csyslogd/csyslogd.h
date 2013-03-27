/* @(#) $Id: ./src/os_csyslogd/csyslogd.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#ifndef _CSYSLOGD_H
#define _CSYSLOGD_H


#include "config/csyslogd-config.h"

#define OS_CSYSLOGD_MAX_TRIES 10

/** Prototypes **/

/* Read syslog config */
void *OS_ReadSyslogConf(int test_config, char *cfgfile,
                        SyslogConfig **sys_config);


/* Send alerts via syslog */
int OS_Alert_SendSyslog(alert_data *al_data, SyslogConfig *syslog_config);


/* Database inserting main function */
void OS_CSyslogD(SyslogConfig **syslog_config);

/* Conditional Field Formatting */
int field_add_int(char *dest, int size, const char *format, const int value );
int field_add_string(char *dest, int size, const char *format, const char *value );
int field_add_truncated(char *dest, int size, const char *format, const char *value,  int fmt_size );


/** Global vars **/

/* System hostname */
char __shost[512];


#endif
