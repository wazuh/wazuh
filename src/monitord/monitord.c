/* Copyright (C) 2015-2020, Wazuh Inc.
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
#include "config/config.h"
#include "string_op.h"
#include "wazuh_db/wdb.h"
#include "time.h"

/* Global variables */
monitor_config mond;
bool worker_node;
OSHash* agents_to_alert_hash;
monitor_time_control mond_time_control;

void Monitord()
{
    char path[PATH_MAX];
    char path_json[PATH_MAX];

    /* Wait a few seconds to settle */
    sleep(10);

    /* Set internal log path to rotate them */
#ifdef WIN32
    /* ossec.log */
    snprintf(path, PATH_MAX, "%s", LOGFILE);
    /* ossec.json */
    snprintf(path_json, PATH_MAX, "%s", LOGJSONFILE);
#else
    /* /var/ossec/logs/ossec.log */
    snprintf(path, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOGFILE);
    /* /var/ossec/logs/ossec.json */
    snprintf(path_json, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOGJSONFILE);
#endif

    /* Connect to the message queue or exit */
    monitor_queue_connect();
    if (mond.a_queue < 0) {
        merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
    }

    // Start com request thread
    w_create_thread(moncom_main, NULL);

    /* Creating agents disconnected alert table */
    agents_to_alert_hash = OSHash_Create();
    if(!agents_to_alert_hash) {
        merror(MEM_ERROR, errno, strerror(errno));
    }

    /* Get current time and initiate counters */
    monitor_init_time_control();

    /* Main monitor loop */
    while (1) {
        monitor_step_time();

        /* In a local installation, there is no need to check agents */
#ifndef LOCAL
        if (mond.a_queue < 0) {
            /* Connecting to the message queue */
            monitor_queue_connect();
        }
        if(check_disconnection_trigger()){
            monitor_agents_disconnection();
        }
        if(check_alert_trigger()){
            monitor_agents_alert();
        }
        if(check_deletion_trigger()){
            monitor_agents_deletion();
        }
#endif

        if(check_logs_time_trigger()){
            monitor_logs(!CHECK_LOGS_SIZE, path, path_json);
            /* Generating reports */
            generate_reports(mond_time_control.today, mond_time_control.thismonth, mond_time_control.thisyear, &mond_time_control.current_time);
            manage_files(mond_time_control.today, mond_time_control.thismonth, mond_time_control.thisyear);
            monitor_update_date();

        } else{
            monitor_logs(CHECK_LOGS_SIZE, path, path_json);
        }

        sleep(1);
    }
}

cJSON *getMonitorInternalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *monconf = cJSON_CreateObject();

    cJSON_AddNumberToObject(monconf,"day_wait",mond.day_wait);
    cJSON_AddNumberToObject(monconf,"compress",mond.compress);
    cJSON_AddNumberToObject(monconf,"sign",mond.sign);
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

cJSON *getReportsOptions(void) {

    cJSON *root = cJSON_CreateObject();
    unsigned int i;

    if (mond.reports) {
        cJSON *arr = cJSON_CreateArray();
        for (i=0;mond.reports[i];i++) {
            cJSON *rep = cJSON_CreateObject();
            if (mond.reports[i]->title) cJSON_AddStringToObject(rep,"title",mond.reports[i]->title);
            if (mond.reports[i]->r_filter.group) cJSON_AddStringToObject(rep,"group",mond.reports[i]->r_filter.group);
            if (mond.reports[i]->r_filter.rule) cJSON_AddStringToObject(rep,"rule",mond.reports[i]->r_filter.rule);
            if (mond.reports[i]->r_filter.level) cJSON_AddStringToObject(rep,"level",mond.reports[i]->r_filter.level);
            if (mond.reports[i]->r_filter.srcip) cJSON_AddStringToObject(rep,"srcip",mond.reports[i]->r_filter.srcip);
            if (mond.reports[i]->r_filter.user) cJSON_AddStringToObject(rep,"user",mond.reports[i]->r_filter.user);
            if (mond.reports[i]->r_filter.show_alerts) cJSON_AddStringToObject(rep,"showlogs","yes"); else cJSON_AddStringToObject(rep,"showlogs","no");
            if (mond.reports[i]->emailto) {
                unsigned int j = 0;
                cJSON *email = cJSON_CreateArray();
                while (mond.reports[i]->emailto[j]) {
                    cJSON_AddItemToArray(email, cJSON_CreateString(mond.reports[i]->emailto[j]));
                    j++;
                }
                cJSON_AddItemToObject(rep,"email_to",email);
            }
            cJSON_AddItemToArray(arr, rep);
        }
        cJSON_AddItemToObject(root,"reports",arr);
    }

    return root;
}

int MonitordConfig(const char *cfg, monitor_config *mond, int no_agents, short day_wait) {
    int modules = 0;

    /* Get config options */
    mond->day_wait = day_wait >= 0 ? day_wait : (short)getDefine_Int("monitord", "day_wait", 0, MAX_DAY_WAIT);
    mond->compress = (unsigned int) getDefine_Int("monitord", "compress", 0, 1);
    mond->sign = (unsigned int) getDefine_Int("monitord", "sign", 0, 1);
    mond->monitor_agents = no_agents ? 0 : (unsigned int) getDefine_Int("monitord", "monitor_agents", 0, 1);
    mond->rotate_log = (unsigned int)getDefine_Int("monitord", "rotate_log", 0, 1);
    mond->keep_log_days = getDefine_Int("monitord", "keep_log_days", 0, 500);
    mond->size_rotate = (unsigned long) getDefine_Int("monitord", "size_rotate", 0, 4096) * 1024 * 1024;
    mond->daily_rotations = getDefine_Int("monitord", "daily_rotations", 1, 256);
    mond->delete_old_agents = (unsigned int)getDefine_Int("monitord", "delete_old_agents", 0, 9600);

    mond->agents = NULL;
    mond->smtpserver = NULL;
    mond->emailfrom = NULL;
    mond->emailidsname = NULL;

    /* Setting default agent's global configuration */
    mond->global.agents_disconnection_time = 20;
    mond->global.agents_disconnection_alert_time = 100;

    modules |= CREPORTS;

    if (ReadConfig(modules, cfg, mond, NULL) < 0 ||
        ReadConfig(CGLOBAL, cfg, &mond->global, NULL) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    return OS_SUCCESS;
}

void monitor_queue_connect() {
    if ((mond.a_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) > 0) {
        /* Send startup message */
        if (SendMSG(mond.a_queue, OS_AD_STARTED, ARGV0, LOCALFILE_MQ) < 0) {
            mond.a_queue = -1;  // We keep trying to reconnect next time.
            merror(QUEUE_SEND);
        }
    }
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
