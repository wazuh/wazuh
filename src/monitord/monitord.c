/* Copyright (C) 2015-2021, Wazuh Inc.
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
#include "wazuh_db/helpers/wdb_global_helpers.h"
#include "time.h"
#include "math.h"

/* Global variables */
monitor_config mond;
bool worker_node;
OSHash* agents_to_alert_hash;

static void get_min_sleep_time(long *current_sleep_time, long time_setting, long current_counter_time)
{
    long delta = time_setting - current_counter_time;
    *current_sleep_time = MIN(*current_sleep_time, delta > 0 ? delta : 0);
}

void Monitord()
{
    /* Wait a few seconds to settle */
    sleep(10);

    char log_file_path[PATH_MAX];
    char json_log_file_path[PATH_MAX];
    snprintf(log_file_path, PATH_MAX, "%s", LOGFILE);
    snprintf(json_log_file_path, PATH_MAX, "%s", LOGJSONFILE);

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

    //TODO should we move this time to the start of the day(00:00) ?
    time_t day_old_time = time(0);
    long check_disconnection_timer = 0;
    long check_alert_timer = 0;
    long delete_agents_timer = 0;
    long daily_log_rotate_timer = 0;

    time_t loop_time = time(0);

    /* Main monitor loop */
    while (1) {
        long loop_sleep_time = LONG_MAX;
        time_t now = time(0);
        double delta_time = difftime(now, loop_time);
        loop_time = now;

        check_disconnection_timer += delta_time;
        check_alert_timer += delta_time;
        delete_agents_timer += delta_time;
        daily_log_rotate_timer += delta_time;

#ifndef LOCAL
        if (mond.a_queue < 0) {
            monitor_queue_connect();
        }

        if(mond.monitor_agents != 0){

            get_min_sleep_time(&loop_sleep_time, mond.global.agents_disconnection_time, check_disconnection_timer);
            if(check_disconnection_timer >= mond.global.agents_disconnection_time){
                check_disconnection_timer = 0;
                monitor_agents_disconnection();
            }

            if(mond.global.agents_disconnection_alert_time != 0){
                get_min_sleep_time(&loop_sleep_time, mond.global.agents_disconnection_alert_time, check_alert_timer);
            }

            if(check_alert_timer >= mond.global.agents_disconnection_alert_time){
                check_alert_timer = 0;
                monitor_agents_alert();
            }

            if(mond.delete_old_agents != 0){
                get_min_sleep_time(&loop_sleep_time, mond.delete_old_agents, - delete_agents_timer);

                if(delete_agents_timer >= (mond.delete_old_agents * 60u)){
                    delete_agents_timer = 0;
                    monitor_agents_deletion();
                }
            }
        }
#endif

        get_min_sleep_time(&loop_sleep_time, DAY_IN_SECONDS, daily_log_rotate_timer);

        if(daily_log_rotate_timer >= DAY_IN_SECONDS) {
            if (mond.rotate_log) {

                //TODO find why is this delay needed
                sleep(mond.day_wait);

                minfo("Running daily rotation of log files.");
                rotate_log_config_t config = {0};
                config.log_creation_time = day_old_time;
                config.configured_daily_rotations = mond.daily_rotations;
                config.compress = mond.compress;
                config.log_extension = LE_JSON;
                w_rotate_log(&config);

                config.log_extension = LE_LOG;
                w_rotate_log(&config);

                remove_old_logs(mond.keep_log_days);
            }

            generate_reports(day_old_time);
            compress_and_sign_logs(day_old_time);
            day_old_time = now;
            daily_log_rotate_timer = 0;
        }
        else
        {
            if (mond.rotate_log && mond.size_rotate > 0) {
                struct stat buf;
                if (stat(log_file_path, &buf) == 0) {
                    off_t size = buf.st_size;
                    if ((unsigned long) size >= mond.size_rotate) {
                        minfo("Rotating '%s' file: Maximum size reached.", LOGFILE);
                        rotate_log_config_t config = {0};
                        config.log_creation_time = time(0);
                        config.configured_daily_rotations = mond.daily_rotations;
                        config.compress = mond.compress;
                        config.log_extension = LE_LOG;
                        w_rotate_log(&config);
                        remove_old_logs(mond.keep_log_days);
                    }
                }

                if (stat(json_log_file_path, &buf) == 0) {
                    off_t size = buf.st_size;
                    /* If log file reachs maximum size, rotate ossec.json */
                    if ( (unsigned long) size >= mond.size_rotate) {
                        minfo("Rotating '%s' file: Maximum size reached.", LOGJSONFILE);
                        rotate_log_config_t config = {0};
                        config.log_creation_time = time(0);
                        config.configured_daily_rotations = mond.daily_rotations;
                        config.compress = mond.compress;
                        config.log_extension = LE_JSON;
                        w_rotate_log(&config);
                        remove_old_logs(mond.keep_log_days);
                    }
                }
            }
        }

        sleep(loop_sleep_time);
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
    mond->global.agents_disconnection_time = 600;
    mond->global.agents_disconnection_alert_time = 0;

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
