/* Copyright (C) 2015-2019, Wazuh Inc.
 * June 13, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "monitord/monitord.h"

#ifdef WIN32
#define localtime_r(x, y) localtime_s(y, x)
#endif

monitor_config mond;
time_t last_rot_log;
time_t last_rot_json;

static void init_conf()
{
    mond.enabled = 0;
    mond.max_size = 0;
    mond.interval = 0;
    mond.rotate = -1;
    mond.rotation_enabled = 1;
    mond.compress_rotation = 1;
    mond.ossec_log_plain = 0;
    mond.ossec_log_json = 0;
    mond.size_rotate = 0;
    mond.interval_rotate = 0;
    mond.interval_units = 's';
    mond.size_units = 'B';
    mond.maxage = 31;
    mond.day_wait = 10;
    mond.log_level = 0;

    return;
}

static void read_internal()
{
    int aux;

    if ((aux = getDefine_Int("monitord", "rotate_log", 0, 1)) != INT_OPT_NDEF)
        mond.rotation_enabled = aux;
    if ((aux = getDefine_Int("monitord", "size_rotate", 0, 4096)) != INT_OPT_NDEF) {
        mond.max_size = (unsigned long) aux * 1024 * 1024;
        mond.size_rotate = (unsigned long) aux;
        mond.size_units = 'M';              // Internal options has only MBytes available
    }
    if ((aux = getDefine_Int("monitord", "compress", 0, 1)) != INT_OPT_NDEF)
        mond.compress_rotation = aux;
    if ((aux = getDefine_Int("monitord", "day_wait", 0, MAX_DAY_WAIT)) != INT_OPT_NDEF)
        mond.day_wait = (short) aux;
    if ((aux = getDefine_Int("monitord", "keep_log_days", 0, 500)) != INT_OPT_NDEF)
        mond.maxage = aux;
    if ((aux = getDefine_Int("monitord", "debug", 0, 2)) != INT_OPT_NDEF)
        mond.log_level = aux;

    return;
}

static void rotate_logs(rotation_list *list, char *path, char *new_path, int day, int interval, int today, int json, time_t last_rot, time_t now) {
    int counter;
    struct tm t;
    time_t last_day;

    if (list && list->last) {
        if (interval) {
            localtime_r(&last_rot, &t);
            if (t.tm_mday != list->last->first_value) {
                counter = list->last->second_value;
            } else {
                t.tm_hour = 0;
                t.tm_min = 0;
                t.tm_sec = 0;
                last_day = mktime(&t);
                /* If there are no rotated logs from the day before */
                counter = now - last_day >= 172800 ? -1 : list->last->second_value;
            }
        } else {
            counter = list->last->second_value;
        }
    }

    if (list && list->last && day == list->last->first_value) {
        new_path = w_rotate_log(path, mond.compress_rotation, mond.maxage, day != today ? 1 : 0, json, mond.daily_rotations,
                                counter, mond.log_list_plain, mond.log_list_json);
    } else {
        new_path = w_rotate_log(path, mond.compress_rotation, mond.maxage, day != today ? 1 : 0, json, mond.daily_rotations,
                                -1, mond.log_list_plain, mond.log_list_json);
    }
    if (new_path) {
        add_new_rotation_node(list, new_path, mond.rotate);
    }
    os_free(new_path);
}

// Thread to rotate internal log
void * w_rotate_log_thread(__attribute__((unused)) void * arg) {
    char path[PATH_MAX];
    char path_json[PATH_MAX];
    struct stat buf, buf_json;
    off_t size, size_json;
    time_t n_time, n_time_json, now = time(NULL);
    struct tm tm, rot;
    int today_log, today_json;
    char *new_path = NULL;

    localtime_r(&now, &tm);
    today_log = tm.tm_mday;
    today_json = today_log;

#ifdef WIN32
    // ossec.log
    snprintf(path, PATH_MAX, "%s", LOGFILE);
    // ossec.json
    snprintf(path_json, PATH_MAX, "%s", LOGJSONFILE);
#else
    // /var/ossec/logs/ossec.log
    snprintf(path, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOGFILE);
    // /var/ossec/logs/ossec.json
    snprintf(path_json, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOGJSONFILE);
#endif

    init_conf();

    const char *cfg = (isChroot() ? OSSECCONF : DEFAULTCPATH);
    int c;
    c = 0;
    c |= CROTMONITORD;
    if (ReadConfig(c, cfg, &mond, NULL) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    read_internal();

    // If module is disabled, exit
    if (mond.rotation_enabled) {
        mdebug1("Log rotating thread started.");
    } else {
        mdebug1("Log rotating disabled. Exiting.");
        pthread_exit(NULL);
    }

    mwarn("The following internal options will be deprecated in the next version: compress, keep_log_days, day_wait, size_rotate_read and daily_rotations."
          "Please, use the 'logging' configuration block instead.");

    /* Calculate when is the next rotation */
    n_time = mond.interval ? calc_next_rotation(now, &rot, mond.interval_units, mond.interval) : 0;
    n_time_json = mond.interval ? n_time : 0;

    // Initializes the rotation lists
    mond.log_list_plain = get_rotation_list("logs", ".log");
    mond.log_list_json = get_rotation_list("logs", ".json");
    purge_rotation_list(mond.log_list_plain, mond.rotate);
    purge_rotation_list(mond.log_list_json, mond.rotate);

    while (1) {
        if (mond.enabled && mond.rotation_enabled){

            now = time(NULL);
            localtime_r(&now, &tm);

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

            if (mond.min_size > 0 && mond.interval > 0) {
                /* Rotate ossec.log by size (min_size) and interval */
                if (mond.interval > 0 && now > n_time && (long) size >= mond.min_size && mond.ossec_log_plain) {
                    rotate_logs(mond.log_list_plain, path, new_path, today_log, 0, tm.tm_mday, 0, 0, now);
                    n_time = calc_next_rotation(now, &rot, mond.interval_units, mond.interval);
                    today_log = today_log != tm.tm_mday ? tm.tm_mday : today_log;
                }
                /* Rotate ossec.json by size (min_size) and interval */
                if (mond.interval > 0 && now > n_time_json && (long) size_json >= mond.min_size && mond.ossec_log_json) {
                    rotate_logs(mond.log_list_json, path_json, new_path, today_json, 0, tm.tm_mday, 1, 0, now);
                    n_time_json = calc_next_rotation(now, &rot, mond.interval_units, mond.interval);
                    today_json = today_json != tm.tm_mday ? tm.tm_mday : today_json;
                }
            } else {
                /* Rotation by size (max_size) */
                if (mond.max_size > 0) {
                    /* If log file reachs maximum size, rotate ossec.log */
                    if ( (long) size >= mond.max_size && mond.ossec_log_plain) {
                        today_log = today_log != tm.tm_mday ? tm.tm_mday : today_log;
                        rotate_logs(mond.log_list_plain, path, new_path, today_log, 0, tm.tm_mday, 0, 0, now);
                        last_rot_log = now;
                    }
                    /* If log file reachs maximum size, rotate ossec.json */
                    if ( (long) size >= mond.max_size && mond.ossec_log_json) {
                        today_json = today_json != tm.tm_mday ? tm.tm_mday : today_json;
                        rotate_logs(mond.log_list_json, path_json, new_path, today_json, 0, tm.tm_mday, 1, 0, now);
                        last_rot_json = now;
                    }
                }
                if (mond.rotation_enabled && mond.interval > 0 && now > n_time) {
                    /* Rotate ossec.log */
                    if (mond.ossec_log_plain) {
                        rotate_logs(mond.log_list_plain, path, new_path, today_log, 1, tm.tm_mday, 0, last_rot_log, now);
                        last_rot_log = now;
                    }
                    /* Rotate ossec.json */
                    if (mond.ossec_log_json) {
                        rotate_logs(mond.log_list_json, path_json, new_path, today_json, 1, tm.tm_mday, 1, last_rot_json, now);
                        last_rot_json = now;
                    }
                    today_log = today_log != tm.tm_mday ? tm.tm_mday : today_log;
                    today_json = today_json != tm.tm_mday ? tm.tm_mday : today_json;
                    n_time = calc_next_rotation(now, &rot, mond.interval_units, mond.interval);
                }
            }
        }
        sleep(1);
    }
}
