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
static int __ossec_rsec;
struct timespec m_timespec;
const char * MONTHS[] = {
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec"
};
void Monitord()
{
    time_t tm;
    struct tm *p;
    int counter = 0;

    char path_ossec[PATH_MAX];
    char path_ossec_json[PATH_MAX];

    /* Get current time before starting */
    gettime(&m_timespec);
    __ossec_rsec = m_timespec.tv_sec;

    struct stat buf;
    off_t size;

    int today = 0;
    int thismonth = 0;
    int thisyear = 0;

    char *new_path;
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

    mwarn("The following internal options will be deprecated in the next version: compress, rotate_log, keep_log_days, day_wait, size_rotate_read and daily_rotations."
          "Please, use the 'logging' configuration block instead.");

    // Initializes the rotation lists
    mond.log_list_plain = get_rotation_list("logs", ".log");
    mond.log_list_json = get_rotation_list("logs", ".json");
    purge_rotation_list(mond.log_list_plain, mond.rotate);
    purge_rotation_list(mond.log_list_json, mond.rotate);

    /* Main monitor loop */
    while (1) {
        tm = time(NULL);
        p = localtime(&tm);
        gettime(&m_timespec);
        counter++;

#ifndef LOCAL
        /* Check for unavailable agents, every two minutes */
        if (mond.monitor_agents && counter >= 120) {
            monitor_agents();
            counter = 0;
        }
#endif

        if(mond.enabled) {
            /* Day changed, deal with log files */
            if (today != p->tm_mday) {

                sleep(mond.day_wait);
                /* Daily rotation and compression of ossec.log/ossec.json */
                if(mond.ossec_log_plain) {
                    if(mond.log_list_plain && mond.log_list_plain->last) {
                        new_path = w_rotate_log(path_ossec, mond.compress_rotation, mond.keep_log_days, 1, 0, mond.daily_rotations, mond.log_list_plain->last->second_value);
                    } else {
                        new_path = w_rotate_log(path_ossec, mond.compress_rotation, mond.keep_log_days, 1, 0, mond.daily_rotations, -1);
                    }
                    if(new_path) {
                        add_new_rotation_node(mond.log_list_plain, new_path, mond.rotate);
                    }
                    os_free(new_path);
                }
                if(mond.ossec_log_json) {
                    if(mond.log_list_json && mond.log_list_json->last){
                        new_path = w_rotate_log(path_ossec_json, mond.compress_rotation, mond.keep_log_days, 1, 1, mond.daily_rotations, mond.log_list_json->last->second_value);
                    } else {
                        new_path = w_rotate_log(path_ossec_json, mond.compress_rotation, mond.keep_log_days, 1, 1, mond.daily_rotations, -1);
                    }

                    if(new_path) {
                        add_new_rotation_node(mond.log_list_json, new_path, mond.rotate);
                    }
                    os_free(new_path);
                }

                /* Generate reports */
                generate_reports(today, thismonth, thisyear, p);
                manage_files(today, thismonth, thisyear);

                today = p->tm_mday;
                thismonth = p->tm_mon;
                thisyear = p->tm_year + 1900;
            } else if (mond.rotation_enabled) {
                if(mond.max_size > 0) {
                    if ((stat(path_ossec, &buf) == 0) && mond.ossec_log_plain) {
                        size = buf.st_size;
                        /* If log file reachs maximum size, rotate ossec.log */
                        if ( (long) size >= mond.max_size) {
                            if(mond.log_list_plain && mond.log_list_plain->last && today == mond.log_list_plain->last->first_value) {
                                new_path = w_rotate_log(path_ossec, mond.compress_rotation, mond.keep_log_days, 0, 0, mond.daily_rotations, mond.log_list_plain->last->second_value);
                            } else {
                                new_path = w_rotate_log(path_ossec, mond.compress_rotation, mond.keep_log_days, 0, 0, mond.daily_rotations, -1);
                            }
                            if(new_path) {
                                add_new_rotation_node(mond.log_list_plain, new_path, mond.rotate);
                            }
                            os_free(new_path);
                            __ossec_rsec = m_timespec.tv_sec;
                        }
                    }
                    if ((stat(path_ossec_json, &buf) == 0) && mond.ossec_log_json) {
                        size = buf.st_size;
                        /* If log file reachs maximum size, rotate ossec.json */
                        if ( (long) size >= mond.max_size) {
                            if(mond.log_list_json && mond.log_list_json->last && today == mond.log_list_json->last->first_value){
                                new_path = w_rotate_log(path_ossec_json, mond.compress_rotation, mond.keep_log_days, 0, 1, mond.daily_rotations, mond.log_list_json->last->second_value);
                            } else {
                                new_path = w_rotate_log(path_ossec_json, mond.compress_rotation, mond.keep_log_days, 0, 1, mond.daily_rotations, -1);
                            }
                            if(new_path) {
                                add_new_rotation_node(mond.log_list_json, new_path, mond.rotate);
                            }
                            os_free(new_path);
                            __ossec_rsec = m_timespec.tv_sec;
                        }
                    }
                }
                if (mond.rotation_enabled && mond.interval > 0 && m_timespec.tv_sec - __ossec_rsec > mond.interval) {
                    if(mond.ossec_log_plain) {
                        if(mond.log_list_plain && mond.log_list_plain->last && today == mond.log_list_plain->last->first_value) {
                            new_path = w_rotate_log(path_ossec, mond.compress_rotation, mond.keep_log_days, 0, 0, mond.daily_rotations, mond.log_list_plain->last->second_value);
                        } else {
                            new_path = w_rotate_log(path_ossec, mond.compress_rotation, mond.keep_log_days, 0, 0, mond.daily_rotations, -1);
                        }
                        if(new_path) {
                            add_new_rotation_node(mond.log_list_plain, new_path, mond.rotate);
                        }
                        os_free(new_path);
                        __ossec_rsec = m_timespec.tv_sec;
                    }
                    if(mond.ossec_log_json) {
                        if(mond.log_list_json && mond.log_list_json->last && today == mond.log_list_json->last->first_value) {
                            new_path = w_rotate_log(path_ossec_json, mond.compress_rotation, mond.keep_log_days, 0, 1, mond.daily_rotations, mond.log_list_json->last->second_value);
                        } else {
                            new_path = w_rotate_log(path_ossec_json, mond.compress_rotation, mond.keep_log_days, 0, 1, mond.daily_rotations, -1);
                        }
                        if(new_path) {
                            add_new_rotation_node(mond.log_list_json, new_path, mond.rotate);
                        }
                        os_free(new_path);
                        __ossec_rsec = m_timespec.tv_sec;
                    }
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

cJSON *getMonitorLogging(void) {
    char *json_format = "json_format";
    char *plain_format = "plain_format";
    char *compress_rotation = "compress_rotation";
    char *rotation_interval = "rotation_interval";
    char *saved_rotations = "saved_rotations";
    char *max_size = "max_size";
    cJSON *root;
    cJSON *logging;
    char aux[50];


    root = cJSON_CreateObject();
    logging = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "logging", logging);

    if (mond.enabled) {
        cJSON_AddStringToObject(logging, plain_format, mond.ossec_log_plain ? "yes" : "no");
        cJSON_AddStringToObject(logging, json_format, mond.ossec_log_json ? "yes" : "no");
        if (mond.rotation_enabled) {
            cJSON_AddStringToObject(logging, compress_rotation, mond.compress_rotation ? "yes" : "no");
            cJSON_AddNumberToObject(logging, saved_rotations, mond.rotate);
            cJSON_AddNumberToObject(logging, rotation_interval, mond.interval);
            snprintf(aux, 50, "%ld %c", mond.interval_rotate, mond.interval_units);
            cJSON_AddStringToObject(logging, rotation_interval, mond.interval ? aux : "no");
            snprintf(aux, 50, "%ld %c", mond.size_rotate, mond.size_units);
            cJSON_AddStringToObject(logging, max_size, mond.size_rotate ? aux : "no");
        }
    }

    return root;
}