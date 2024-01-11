/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CSYSLOGD_H
#define CSYSLOGD_H

#include "../config/csyslogd-config.h"
#include "cJSON.h"

#define OS_CSYSLOGD_MAX_TRIES 10

/** Prototypes **/

/* Read syslog config */
SyslogConfig **OS_ReadSyslogConf(int test_config, const char *cfgfile);
cJSON *getCsyslogConfig(void);

// Com request thread dispatcher
size_t csyscom_dispatch(const char * command, char ** output);
size_t csyscom_getconfig(const char * section, char ** output);
void * csyscom_main(__attribute__((unused)) void * arg);

/* Send alerts via syslog
 * Returns 1 on success or 0 on error
 */
int OS_Alert_SendSyslog(alert_data *al_data, SyslogConfig *syslog_config);

/* Send alerts via syslog from JSON alert
 * Returns 1 on success or 0 on error
 */
int OS_Alert_SendSyslog_JSON(cJSON *json_data, SyslogConfig *syslog_config);

/* Database inserting main function */
#ifdef WAZUH_UNIT_TESTING
void OS_CSyslogD(SyslogConfig **syslog_config);
#else
void OS_CSyslogD(SyslogConfig **syslog_config) __attribute__((noreturn));
#endif

/* Conditional Field Formatting */
int field_add_int(char *dest, size_t size, const char *format, const int value );
int field_add_string(char *dest, size_t size, const char *format, const char *value );
int field_add_truncated(char *dest, size_t size, const char *format, const char *value,  int fmt_size );

/** Global variables **/

/* System hostname */
extern char __shost[512];
/* System hostname (full length) */
extern char __shost_long[512];

extern SyslogConfig **syslog_config;

#endif /* CSYSLOGD_H */
