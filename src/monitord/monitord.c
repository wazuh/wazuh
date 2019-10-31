/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "monitord.h"

/* Global variables */
monitor_config mond;

time_t last_rot_log;
time_t last_rot_json;

static void rotate_logs(rotation_list *list, char *path, char *new_path, int *day, int interval, int today, int json,
                        time_t *last_rot, time_t now) {
    int counter;
    struct tm t;
    time_t last_day;
    *day = interval ? *day : today;

    if (list && list->last) {
        if (interval) {
            localtime_r(last_rot, &t);
            if (t.tm_mday != list->last->first_value) {
                counter = list->last->second_value;
            } else {
                t.tm_hour = 0;
                t.tm_min = 0;
                t.tm_sec = 0;
                last_day = mktime(&t);
                /* If there are no rotated logs from the day before */
                counter = now - last_day >= SECONDS_PER_DAY*2 ? -1 : list->last->second_value;
            }
        } else {
            counter = list->last->second_value;
        }
    }

    if (list && list->last && *day == list->last->first_value) {
        new_path = w_rotate_log(path, mond.compress_rotation, mond.maxage, *day != today ? 1 : 0, json,
                                counter, mond.log_list_plain, mond.log_list_json);
    } else {
        new_path = w_rotate_log(path, mond.compress_rotation, mond.maxage, *day != today ? 1 : 0, json,
                                -1, mond.log_list_plain, mond.log_list_json);
    }
    if (new_path) {
        add_new_rotation_node(list, new_path, mond.rotate);
    }
    os_free(new_path);
    *last_rot = now;
    *day = today;
}

/*
 * Check wether the log has grown bigger than 'min_size' or if the rotation time has passed.
 * If the file grows bigger than 'min_size' before the rotation time has passed
 * the rotation will be treated as it's a rotation by schedule.
 * Otherwise the rotation will be treated as it's a rotation by size.
 */
static void check_size_interval(time_t now, time_t rot_time, int size, int *interval, int *set)
{
    if (now <= rot_time && (long) size >= mond.min_size && mond.ossec_log_plain && !*set) {
        *interval = 1;
        *set = 1;
    } else if (now > rot_time && (long) size < mond.min_size && mond.ossec_log_plain && !*set) {
        *interval = 0;
        *set = 1;
    }
}

void Monitord()
{
    time_t tm, n_time, n_time_json;
    struct tm p;
    int counter = 0;
    int interval_log = 0, interval_json = 0;
    int interval_set_log = 0, interval_set_json = 0;

    char path_ossec[PATH_MAX];
    char path_ossec_json[PATH_MAX];

    struct stat buf, buf_json;
    off_t size = 0, size_json = 0;

    int today = 0;
    int today_log = 0;
    int today_json = 0;
    int thismonth = 0;
    int thisyear = 0;

    char *new_path = NULL;
    char str[OS_SIZE_1024 + 1];

    /* Wait a few seconds to settle */
    sleep(10);

    memset(str, '\0', OS_SIZE_1024 + 1);

    /* Get current time before starting */
    tm = time(NULL);
    localtime_r(&tm, &p);

    today = p.tm_mday;
    thismonth = p.tm_mon;
    thisyear = p.tm_year + 1900;
    today_log = today;
    today_json = today;

    /* Calculate when is the next rotation */
    n_time = mond.interval ? calc_next_rotation(tm, mond.interval_units, mond.interval) : 0;
    n_time_json = mond.interval ? n_time : 0;

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
    w_create_thread(moncom_main, NULL, mond.thread_stack_size);

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
        localtime_r(&tm, &p);
        counter++;

#ifndef LOCAL
        /* Check for unavailable agents, every two minutes */
        if (mond.monitor_agents && counter >= 120) {
            monitor_agents();
            counter = 0;
        }
#endif

        if (mond.enabled && mond.rotation_enabled) {
            /* Calculate the logs size only if rotation by size is active */
            if (mond.min_size > 0 || mond.max_size > 0) {
                if (stat(path_ossec, &buf) < 0) {
                    merror("Couldn't stat '%s' file due to '%s'", path_ossec, strerror(errno));
                } else {
                    size = buf.st_size;
                }
                if (stat(path_ossec_json, &buf_json) < 0) {
                    merror("Couldn't stat '%s' file due to '%s'", path_ossec_json, strerror(errno));
                } else {
                    size_json = buf_json.st_size;
                }
            }

            /* Rotation by size (min_size) and interval */
            if (mond.min_size > 0 && mond.interval > 0) {
                /* Rotate ossec.log by size (min_size) and interval */
                check_size_interval(tm, n_time, size, &interval_log, &interval_set_log);
                if (tm > n_time && (long) size >= mond.min_size && mond.ossec_log_plain) {
                    rotate_logs(mond.log_list_plain, path_ossec, new_path, &today_log, interval_log, p.tm_mday, 0, &last_rot_log, tm);
                    n_time = calc_next_rotation(tm, mond.interval_units, mond.interval);
                    interval_set_log = 0;
                }
                /* Rotate ossec.json by size (min_size) and interval */
                check_size_interval(tm, n_time_json, size_json, &interval_json, &interval_set_json);
                if (tm > n_time_json && (long) size_json >= mond.min_size && mond.ossec_log_json) {
                    rotate_logs(mond.log_list_json, path_ossec_json, new_path, &today_json, interval_json, p.tm_mday, 1, &last_rot_json, tm);
                    n_time_json = calc_next_rotation(tm, mond.interval_units, mond.interval);
                    interval_set_json = 0;
                }
            } else {
                /* Rotation by size (max_size) */
                if (mond.max_size > 0) {
                    /* If log file reachs maximum size, rotate ossec.log */
                    if ((long) size >= mond.max_size && mond.ossec_log_plain) {
                        rotate_logs(mond.log_list_plain, path_ossec, new_path, &today_log, 0, p.tm_mday, 0, &last_rot_log, tm);
                    }
                    /* If log file reachs maximum size, rotate ossec.json */
                    if ((long) size_json >= mond.max_size && mond.ossec_log_json) {
                        rotate_logs(mond.log_list_json, path_ossec_json, new_path, &today_json, 0, p.tm_mday, 1, &last_rot_json, tm);
                    }
                }
                /* Rotation by interval */
                if (mond.interval > 0 && tm > n_time) {
                    /* Rotate ossec.log */
                    if (mond.ossec_log_plain) {
                        rotate_logs(mond.log_list_plain, path_ossec, new_path, &today_log, 1, p.tm_mday, 0, &last_rot_log, tm);
                    }
                    /* Rotate ossec.json */
                    if (mond.ossec_log_json) {
                        rotate_logs(mond.log_list_json, path_ossec_json, new_path, &today_json, 1, p.tm_mday, 1, &last_rot_json, tm);
                    }
                    n_time = calc_next_rotation(tm, mond.interval_units, mond.interval);
                }
            }
        }
        if (mond.enabled) {
            if (today != p.tm_mday) {
                /* Generate reports */
                generate_reports(today, thismonth, thisyear, &p);
                today = p.tm_mday;
                thismonth = p.tm_mon;
                thisyear = p.tm_year + 1900;
            }
        }
        sleep(1);
    }
}

cJSON *getMonitorOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *monconf = cJSON_CreateObject();

    cJSON_AddNumberToObject(monconf, "check_agent_status", mond.monitor_agents);
    cJSON_AddNumberToObject(monconf, "delete_old_agents", mond.delete_old_agents);
    cJSON_AddNumberToObject(monconf, "thread_stack_size", mond.thread_stack_size);
    cJSON_AddNumberToObject(monconf, "log_level", mond.log_level);

    cJSON_AddItemToObject(root, "monitord", monconf);

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
    char *rotation_schedule = "schedule";
    char *saved_rotations = "saved_rotations";
    char *maxsize = "maxsize";
    char *maxage = "maxage";
    char *minsize = "minsize";
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
            snprintf(aux, 50, "%d", mond.rotate);
            cJSON_AddStringToObject(logging, saved_rotations, mond.rotate == -1 ? "unlimited" : aux);
            if (mond.interval_units == 'w') {
                char *buffer;
                buffer = int_to_day(mond.interval);
                cJSON_AddStringToObject(logging, rotation_schedule, buffer);
                os_free(buffer);
            } else {
                snprintf(aux, 50, "%ld%c", mond.interval, mond.interval_units);
                cJSON_AddStringToObject(logging, rotation_schedule, mond.interval ? aux : "no");
            }
            snprintf(aux, 50, "%ld%c", mond.size_rotate, mond.size_units);
            cJSON_AddStringToObject(logging, maxsize, mond.size_rotate ? aux : "no");
            snprintf(aux, 50, "%ld%c", mond.min_size_rotate, mond.min_size_units);
            cJSON_AddStringToObject(logging, minsize, mond.min_size_rotate ? aux : "no");
            cJSON_AddNumberToObject(logging, maxage, mond.maxage);
        }
    }

    return root;
}