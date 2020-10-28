/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef MONITORD_H
#define MONITORD_H

#include "hash_op.h"
#ifndef ARGV0
#define ARGV0 "ossec-monitord"
#endif

#include "config/reports-config.h"
#include "config/global-config.h"

#define MAX_DAY_WAIT 600
#define MONITORD_MSG_HEADER "1:" ARGV0 ":"
#define AG_DISCON_MSG MONITORD_MSG_HEADER OS_AG_DISCON

/* Monitord counters */
typedef struct _mond_counters {
    long agents_disconnection;
    long agents_disconnection_alert;
    long delete_old_agents;
} mond_counters;

/* Prototypes */
void Monitord(void) __attribute__((noreturn));
void manage_files(int cday, int cmon, int cyear);
void generate_reports(int cday, int cmon, int cyear, const struct tm *p);
void monitor_agents(void);
void OS_SignLog(const char *logfile, const char *logfile_old, const char * ext);
void OS_CompressLog(const char *logfile);
void w_rotate_log(int compress, int keep_log_days, int new_day, int rotate_json, int daily_rotations);
int delete_old_agent(const char *agent_id);
int MonitordConfig(const char *cfg, monitor_config *mond, int no_agents, short day_wait);
void monitor_agent_disconnection(char *agent);

/* Counters prototypes */
void MonitorStartCounters(mond_counters *counters);
int MonitorCheckCounters(mond_counters *counters);

/* Parse read config into JSON format */
cJSON *getMonitorInternalOptions(void);
cJSON *getMonitorGlobalOptions(void);
cJSON *getReportsOptions(void);
size_t moncom_dispatch(char * command, char ** output);
size_t moncom_getconfig(const char * section, char ** output);
void * moncom_main(__attribute__((unused)) void * arg);

/* Global variables */
extern monitor_config mond;
extern OSHash* agents_to_alert_hash;


#endif /* MONITORD_H */
