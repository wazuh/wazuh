/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "monitord.h"

/* Global variables */
monitor_config mond;


void Monitord()
{
    time_t tm;
    struct tm *p;
    int counter = 0;

    char path_ossec[PATH_MAX];
    char path_ossec_json[PATH_MAX];

    char path_alerts[PATH_MAX];
    char path_alerts_json[PATH_MAX];

    char path_archives[PATH_MAX];
    char path_archives_json[PATH_MAX];
    struct stat buf;
    off_t size;

    int today = 0;
    int thismonth = 0;
    int thisyear = 0;

    char str[OS_SIZE_1024 + 1];

    /* Wait a few seconds to settle */
    sleep(10);

    memset(str, '\0', OS_SIZE_1024 + 1);

    /* Get current time before starting */
    tm = time(NULL);
    p = localtime(&tm);

    today = p->tm_mday;
    thismonth = p->tm_mon;
    thisyear = p->tm_year + 1900;

    /* Set internal log path to rotate them */
#ifdef WIN32
    // ossec.log
    snprintf(path, PATH_MAX, "%s", LOGFILE);
    // ossec.json
    snprintf(path_json, PATH_MAX, "%s", LOGJSONFILE);
#else
    // /var/ossec/logs/ossec.log
    snprintf(path_ossec, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOGFILE);
    // /var/ossec/logs/ossec.json
    snprintf(path_ossec_json, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOGJSONFILE);

    // /var/ossec/logs/alerts/alerts.log
    snprintf(path_alerts, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, ALERTS_DAILY);
    // /var/ossec/logs/alerts/alerts.json
    snprintf(path_alerts_json, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, ALERTSJSON_DAILY);

    // /var/ossec/logs/archives/archives.log
    snprintf(path_archives, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, EVENTS_DAILY);
    // /var/ossec/logs/archives/archives.json
    snprintf(path_archives_json, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, EVENTSJSON_DAILY);
#endif

    /* Connect to the message queue or exit */
    if ((mond.a_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
        merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
    }

    /* Send startup message */
    snprintf(str, OS_SIZE_1024 - 1, OS_AD_STARTED);
    if (SendMSG(mond.a_queue, str, ARGV0,
                LOCALFILE_MQ) < 0) {
        merror(QUEUE_SEND);
    }

    // Start com request thread
    w_create_thread(moncom_main, NULL);

    /* Main monitor loop */
    while (1) {
        tm = time(NULL);
        p = localtime(&tm);
        counter++;

#ifndef LOCAL
        /* Check for unavailable agents, every two minutes */
        if (mond.monitor_agents && counter >= 120) {
            monitor_agents();
            counter = 0;
        }
#endif

        /* Day changed, deal with log files */
        if (today != p->tm_mday) {
            if (mond.rotate_log || mond.rotate_alerts || mond.rotate_archives) {
                sleep(mond.day_wait);
                /* Daily rotation and compression of ossec.log/ossec.json */
                if(mond.rotate_log) {
                    w_rotate_log(path_ossec, mond.compress, mond.keep_log_days, 1, 0, mond.daily_rotations);
                }
                /* Daily rotation and compression of alerts.log/alerts.json */
                if(mond.rotate_alerts) {
                    w_rotate_log(path_alerts, mond.compress, mond.keep_log_days, 1, 0, mond.daily_rotations);
                }
                /* Daily rotation and compression of archives.log/archives.json */
                if(mond.rotate_archives) {
                    w_rotate_log(path_archives, mond.compress, mond.keep_log_days, 1, 0, mond.daily_rotations);
                }
            }

            /* Generate reports */
            generate_reports(today, thismonth, thisyear, p);
            manage_files(today, thismonth, thisyear);

            today = p->tm_mday;
            thismonth = p->tm_mon;
            thisyear = p->tm_year + 1900;
        } else if (mond.rotate_log && mond.size_rotate > 0) {
            if (stat(path_ossec, &buf) == 0) {
                size = buf.st_size;
                /* If log file reachs maximum size, rotate ossec.log */
                if ( (unsigned long) size >= mond.size_rotate) {
                    w_rotate_log(path_ossec, mond.compress, mond.keep_log_days, 0, 0, mond.daily_rotations);
                }
            }

            if (stat(path_ossec_json, &buf) == 0) {
                size = buf.st_size;
                /* If log file reachs maximum size, rotate ossec.json */
                if ( (unsigned long) size >= mond.size_rotate) {
                    w_rotate_log(path_ossec_json, mond.compress, mond.keep_log_days, 0, 1, mond.daily_rotations);
                }
            }

            if (stat(path_alerts, &buf) == 0) {
                size = buf.st_size;
                /* If log file reachs maximum size, rotate ossec.json */
                if ( (unsigned long) size >= mond.size_rotate) {
                    w_rotate_log(path_alerts, mond.compress, mond.keep_log_days, 0, 0, mond.daily_rotations);
                }
            }
            if (stat(path_alerts_json, &buf) == 0) {
                size = buf.st_size;
                /* If log file reachs maximum size, rotate ossec.log */
                if ( (unsigned long) size >= mond.size_rotate) {
                    w_rotate_log(path_alerts_json, mond.compress, mond.keep_log_days, 0, 1, mond.daily_rotations);
                }
            }

            if (stat(path_archives, &buf) == 0) {
                size = buf.st_size;
                /* If log file reachs maximum size, rotate ossec.json */
                if ( (unsigned long) size >= mond.size_rotate) {
                    w_rotate_log(path_archives, mond.compress, mond.keep_log_days, 0, 0, mond.daily_rotations);
                }
            }
            if (stat(path_archives_json, &buf) == 0) {
                size = buf.st_size;
                /* If log file reachs maximum size, rotate ossec.log */
                if ( (unsigned long) size >= mond.size_rotate) {
                    w_rotate_log(path_archives_json, mond.compress, mond.keep_log_days, 0, 1, mond.daily_rotations);
                }
            }
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
    cJSON_AddNumberToObject(monconf,"keep_rotated_files",mond.keep_rotated_files);
    cJSON_AddNumberToObject(monconf,"rotate_log",mond.rotate_log);
    cJSON_AddNumberToObject(monconf,"size_rotate",mond.size_rotate);
    cJSON_AddNumberToObject(monconf,"daily_rotations",mond.daily_rotations);
    cJSON_AddNumberToObject(monconf,"delete_old_agents",mond.delete_old_agents);

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
