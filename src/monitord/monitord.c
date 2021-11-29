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

/* Global variables */
monitor_config mond;

time_t last_rot_log;
time_t last_rot_json;

bool worker_node;
OSHash* agents_to_alert_hash;
monitor_time_control mond_time_control;

static void rotate_logs(rotation_list *list, char *path, char *new_path, int *day, int interval, int json,
                        time_t *last_rot, time_t now) {
    int counter;
    struct tm t;
    time_t last_day;
    *day = interval ? *day : mond_time_control.today;

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
        new_path = w_rotate_log(path, mond.compress_rotation, mond.maxage, *day != mond_time_control.today ? 1 : 0, json,
                                counter, mond.log_list_plain, mond.log_list_json);
    } else {
        new_path = w_rotate_log(path, mond.compress_rotation, mond.maxage, *day != mond_time_control.today ? 1 : 0, json,
                                -1, mond.log_list_plain, mond.log_list_json);
    }
    if (new_path) {
        add_new_rotation_node(list, new_path, mond.rotate);
    }
    os_free(new_path);
    *last_rot = now;
    *day = mond_time_control.today;
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
    time_t tm = 0, n_time = 0, n_time_json = 0;
    int interval_log = 0, interval_json = 0;
    int interval_set_log = 0, interval_set_json = 0;

    char path[PATH_MAX];
    char path_json[PATH_MAX];

    struct stat buf, buf_json;
    off_t size = 0, size_json = 0;

    int today_log = 0;
    int today_json = 0;

    char *new_path = NULL;

    /* Wait a few seconds to settle */
    sleep(10);

    /* Calculate when is the next rotation */
    n_time = mond.interval ? calc_next_rotation(tm, mond.interval_units, mond.interval) : 0;
    n_time_json = mond.interval ? n_time : 0;

    /* Set internal log path to rotate them */
    /* ossec.log */
    snprintf(path, PATH_MAX, "%s", LOGFILE);
    /* ossec.json */
    snprintf(path_json, PATH_MAX, "%s", LOGJSONFILE);

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
    today_log = mond_time_control.today;
    today_json = mond_time_control.today;

    // TODO: Review and reallocate this warning
    mwarn("The following internal options will be deprecated in the next version: compress, rotate_log, keep_log_days, day_wait, size_rotate_read and daily_rotations."
          "Please, use the 'logging' configuration block instead.");

    // Initializes the rotation lists
    mond.log_list_plain = get_rotation_list("logs", ".log");
    mond.log_list_json = get_rotation_list("logs", ".json");
    purge_rotation_list(mond.log_list_plain, mond.rotate);
    purge_rotation_list(mond.log_list_json, mond.rotate);

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

        // TODO: Review this logic agains changes in https://github.com/wazuh/wazuh/pull/6396
        if (mond.enabled && mond.rotation_enabled) {
            /* Calculate the logs size only if rotation by size is active */
            if (mond.min_size > 0 || mond.max_size > 0) {
                if (stat(path, &buf) < 0) {
                    merror("Couldn't stat '%s' file due to '%s'", path, strerror(errno));
                } else {
                    size = buf.st_size;
                }
                if (stat(path_json, &buf_json) < 0) {
                    merror("Couldn't stat '%s' file due to '%s'", path_json, strerror(errno));
                } else {
                    size_json = buf_json.st_size;
                }
            }

            /* Rotation by size (min_size) and interval */
            if (mond.min_size > 0 && mond.interval > 0) {
                /* Rotate ossec.log by size (min_size) and interval */
                check_size_interval(tm, n_time, size, &interval_log, &interval_set_log);
                if (tm > n_time && (long) size >= mond.min_size && mond.ossec_log_plain) {
                    rotate_logs(mond.log_list_plain, path, new_path, &today_log, interval_log, 0, &last_rot_log, tm);
                    n_time = calc_next_rotation(tm, mond.interval_units, mond.interval);
                    interval_set_log = 0;
                }
                /* Rotate ossec.json by size (min_size) and interval */
                check_size_interval(tm, n_time_json, size_json, &interval_json, &interval_set_json);
                if (tm > n_time_json && (long) size_json >= mond.min_size && mond.ossec_log_json) {
                    rotate_logs(mond.log_list_json, path_json, new_path, &today_json, interval_json, 1, &last_rot_json, tm);
                    n_time_json = calc_next_rotation(tm, mond.interval_units, mond.interval);
                    interval_set_json = 0;
                }
            } else {
                /* Rotation by size (max_size) */
                if (mond.max_size > 0) {
                    /* If log file reachs maximum size, rotate ossec.log */
                    if ((long) size >= mond.max_size && mond.ossec_log_plain) {
                        rotate_logs(mond.log_list_plain, path, new_path, &today_log, 0, 0, &last_rot_log, tm);
                    }
                    /* If log file reachs maximum size, rotate ossec.json */
                    if ((long) size_json >= mond.max_size && mond.ossec_log_json) {
                        rotate_logs(mond.log_list_json, path_json, new_path, &today_json, 0, 1, &last_rot_json, tm);
                    }
                }
                /* Rotation by interval */
                if (mond.interval > 0 && tm > n_time) {
                    /* Rotate ossec.log */
                    if (mond.ossec_log_plain) {
                        rotate_logs(mond.log_list_plain, path, new_path, &today_log, 1, 0, &last_rot_log, tm);
                    }
                    /* Rotate ossec.json */
                    if (mond.ossec_log_json) {
                        rotate_logs(mond.log_list_json, path_json, new_path, &today_json, 1, 1, &last_rot_json, tm);
                    }
                    n_time = calc_next_rotation(tm, mond.interval_units, mond.interval);
                }
            }
        }
        if (mond.enabled) {
            if(check_logs_time_trigger()){
                /* Generate reports */
                generate_reports(mond_time_control.today, mond_time_control.thismonth, mond_time_control.thisyear, &mond_time_control.current_time);
                monitor_update_date();
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
    cJSON_AddNumberToObject(monconf, "log_level", mond.log_level);

    cJSON_AddItemToObject(root, "monitord", monconf);

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
