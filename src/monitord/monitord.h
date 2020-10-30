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
/* Time control prototypes */
void monitor_init_time_control();
void monitor_step_time();
void monitor_update_date();
/* Triggers prototypes */
int check_disconnection_trigger();
int check_alert_trigger();
int check_deletion_trigger();
int check_logs_time_trigger();
/* Messages prototypes */
void monitor_queue_connect();
void monitor_send_deletion_msg(char *agent);
void monitor_send_disconnection_msg(char *agent);
/* Actions prototypes */
void monitor_agents_disconnection();
void monitor_agents_alert();
void monitor_agents_deletion();
void monitor_logs(int check_logs_size, char path[PATH_MAX], char path_json[PATH_MAX]);

/* Parse read config into JSON format */
cJSON *getMonitorInternalOptions(void);
cJSON *getMonitorGlobalOptions(void);
cJSON *getReportsOptions(void);
size_t moncom_dispatch(char * command, char ** output);
size_t moncom_getconfig(const char * section, char ** output);
void * moncom_main(__attribute__((unused)) void * arg);

typedef struct _monitor_time_control {
    long disconnect_counter;
    long alert_counter;
    long delete_counter;
    struct tm current_time;
    int today;
    int thismonth;
    int thisyear;
} monitor_time_control;

typedef enum {
    CHECK_LOGS_SIZE_FALSE = 0,
    CHECK_LOGS_SIZE_TRUE
} monitor_check_logs_size;

/* Global variables */
extern monitor_config mond;
extern OSHash* agents_to_alert_hash;


#endif /* MONITORD_H */
