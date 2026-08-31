/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "cJSON.h"
#include "debug_op.h"
#include "hash_op.h"
#include "os_err.h"
#include "shared.h"
#include "monitord.h"
#include "config.h"
#include "string_op.h"
#include "wazuhdb_queries_op.h"
#include "time.h"

/* Global variables */
monitor_config mond;
OSHash* agents_to_alert_hash;
monitor_time_control mond_time_control;
bool worker_node;

/* How long the idle loop parks between wake-ups. Nothing depends on the cadence any more; it exists
 * only so the process stays alive for the getconfig socket and the daemon healthchecks. */
#define MONITORD_IDLE_INTERVAL 60

void Monitord()
{
    /* EVERY PERIODIC RESPONSIBILITY OF THIS DAEMON NOW RUNS IN THE TASK MANAGER, inside
     * wazuh-modulesd: the agent disconnection sweep, the disconnection log line, the retention
     * deletion of long-disconnected agents, and both kinds of log rotation. See
     * docs/ref/modules/task_manager/schedules.md.
     *
     * The loop is gutted here rather than in the change that deletes this daemon, because the two
     * cannot overlap even for one release: two rotators racing on the same rename would lose a log
     * file, and two nodes' worth of disconnection sweeps would fight over the same rows.
     *
     * What is left is a process that starts, answers getconfig and idles. The socket stays because
     * removing it is a breaking API change (`component='monitor'`) that belongs with the daemon's
     * removal, not here. The functions below this one are now unreachable and go with the file.
     */
    /* Wait a few seconds to settle */
    sleep(10);

    /* Log monitord startup message to ossec.log */
    minfo(OS_MG_STARTED);

    // Start com request thread
    w_create_thread(moncom_main, NULL);

    while (1) {
        sleep(MONITORD_IDLE_INTERVAL);
    }
}

cJSON *getMonitorInternalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *monconf = cJSON_CreateObject();

    cJSON_AddNumberToObject(monconf,"day_wait",mond.day_wait);
    cJSON_AddNumberToObject(monconf,"compress",mond.compress);
    cJSON_AddNumberToObject(monconf,"monitor_agents",mond.monitor_agents);
    cJSON_AddNumberToObject(monconf,"keep_log_days",mond.keep_log_days);
    cJSON_AddNumberToObject(monconf,"rotate_log",mond.rotate_log);
    cJSON_AddNumberToObject(monconf,"size_rotate",mond.size_rotate);
    cJSON_AddNumberToObject(monconf,"daily_rotations",mond.daily_rotations);
    cJSON_AddNumberToObject(monconf,"delete_old_agents",mond.delete_old_agents);

    cJSON_AddItemToObject(root,"monitord",monconf);

    return root;
}

cJSON *getMonitorGlobalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *monconf = cJSON_CreateObject();

    cJSON_AddNumberToObject(monconf,"agents_disconnection_time",mond.global.agents_disconnection_time);
    cJSON_AddNumberToObject(monconf,"agents_disconnection_alert_time",mond.global.agents_disconnection_alert_time);

    cJSON_AddItemToObject(root,"monitord",monconf);

    return root;
}

int MonitordConfig(const char *cfg, monitor_config *mond, int no_agents, short day_wait) {
    int modules = 0;

    /* Get config options */
    mond->day_wait = day_wait >= 0 ? day_wait : (short)getDefine_Int_default("monitord", "day_wait", 0, MAX_DAY_WAIT, 10);
    mond->compress = (unsigned int) getDefine_Int_default("monitord", "compress", 0, 1, 1);
    mond->monitor_agents = no_agents ? 0 : (unsigned int) getDefine_Int_default("monitord", "monitor_agents", 0, 1, 1);
    mond->rotate_log = (unsigned int)getDefine_Int_default("monitord", "rotate_log", 0, 1, 1);
    mond->keep_log_days = getDefine_Int_default("monitord", "keep_log_days", 0, 500, 31);
    mond->size_rotate = (unsigned long) getDefine_Int_default("monitord", "size_rotate", 0, 4096, 512) * 1024 * 1024;
    mond->daily_rotations = getDefine_Int_default("monitord", "daily_rotations", 1, 256, 12);
    mond->delete_old_agents = (unsigned int)getDefine_Int_default("monitord", "delete_old_agents", 0, 9600, 0);

    /* Setting default agent's global configuration */
    mond->global.agents_disconnection_time = 900;
    mond->global.agents_disconnection_alert_time = 0;

    if (ReadConfig(CGLOBAL, cfg, &mond->global, NULL) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    return OS_SUCCESS;
}

void monitor_init_time_control() {
    time_t tm;

    mond_time_control.current_time.tm_sec = 0;
    mond_time_control.disconnect_counter = 0;
    mond_time_control.alert_counter = 0;
    mond_time_control.delete_counter = 0;

    tm = time(NULL);
    localtime_r(&tm, &mond_time_control.current_time);

    mond_time_control.today = mond_time_control.current_time.tm_mday;
    mond_time_control.thismonth = mond_time_control.current_time.tm_mon;
    mond_time_control.thisyear = mond_time_control.current_time.tm_year + 1900;
}

void monitor_step_time() {
    time_t tm;
    tm = time(NULL);
    localtime_r(&tm, &mond_time_control.current_time);

    mond_time_control.disconnect_counter++;
    if (mond.monitor_agents != 0) {
        mond_time_control.alert_counter++;
    }
    if(mond.delete_old_agents != 0 && mond.monitor_agents != 0){
        mond_time_control.delete_counter++;
    }
}

void monitor_update_date() {
    mond_time_control.today = mond_time_control.current_time.tm_mday;
    mond_time_control.thismonth = mond_time_control.current_time.tm_mon;
    mond_time_control.thisyear = mond_time_control.current_time.tm_year + 1900;
}

int check_disconnection_trigger() {
    if (mond_time_control.disconnect_counter >= mond.global.agents_disconnection_time) {
        mond_time_control.disconnect_counter = 0;
        return 1;
    }
    return 0;
}

int check_alert_trigger() {
    if (mond.monitor_agents != 0 && mond_time_control.alert_counter >= mond.global.agents_disconnection_alert_time) {
        mond_time_control.alert_counter = 0;
        return 1;
    }
    return 0;
}

int check_deletion_trigger() {
    if (mond.monitor_agents != 0 && mond.delete_old_agents != 0 && mond_time_control.delete_counter >= mond.delete_old_agents * 60 ) {
        mond_time_control.delete_counter = 0;
        return 1;
    }
    return 0;
}

int check_logs_time_trigger() {
    if ( mond_time_control.today != mond_time_control.current_time.tm_mday) {
        return 1;
    }
    return 0;
}
