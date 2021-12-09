/* Copyright (C) 2015-2021, Wazuh Inc.
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

int log_compress;
int keep_log_days;
int day_wait;
int daily_rotations;
int size_rotate_read;

// Thread to rotate internal log
void * w_rotate_log_thread(__attribute__((unused)) void * arg) {
    char path[PATH_MAX];
    char path_json[PATH_MAX];
    struct stat buf;
    off_t size;
    time_t now = time(NULL);
    struct tm tm = { .tm_sec = 0 };
    int today;
    log_compress = getDefine_Int("monitord", "compress", 0, 1);
    keep_log_days = getDefine_Int("monitord", "keep_log_days", 0, 500);
    day_wait = getDefine_Int("monitord", "day_wait", 0, 600);
    size_rotate_read = getDefine_Int("monitord", "size_rotate", 0, 4096);
    unsigned long size_rotate = (unsigned long) size_rotate_read * 1024 * 1024;
    daily_rotations = getDefine_Int("monitord", "daily_rotations", 1, 256);

    mdebug1("Log rotating thread started.");

    localtime_r(&now, &tm);
    today = tm.tm_mday;

    snprintf(path, PATH_MAX, "%s", LOGFILE);
    snprintf(path_json, PATH_MAX, "%s", LOGJSONFILE);

    while (1) {
        now = time(NULL);
        localtime_r(&now, &tm);

        rotate_log_config_t config = {0};
        config.configured_daily_rotations = daily_rotations;
        config.compress = log_compress;

        if (today != tm.tm_mday) {
            sleep(day_wait);
            /* Daily rotation and compression of ossec.log/ossec.json */
            config.log_creation_time = time(0) - DAY_IN_SECONDS;
            config.log_extension = LE_LOG;
            w_rotate_log(&config);

            config.log_extension = LE_JSON;
            w_rotate_log(&config);

            remove_old_logs(keep_log_days);
            today = tm.tm_mday;
        }

        if (size_rotate > 0) {
            if (stat(path, &buf) == 0) {
                size = buf.st_size;
                /* If log file reachs maximum size, rotate ossec.log */
                config.log_extension = LE_LOG;
                config.log_creation_time = time(0);

                if ( (unsigned long) size >= size_rotate) {
                    w_rotate_log(&config);
                    remove_old_logs(keep_log_days);
                }
            }

            if (stat(path_json, &buf) == 0) {
                size = buf.st_size;
                /* If log file reachs maximum size, rotate ossec.json */
                config.log_extension = LE_JSON;
                config.log_creation_time = time(0);
                if ( (unsigned long) size >= size_rotate) {
                    w_rotate_log(&config);
                    remove_old_logs(keep_log_days);
                }
            }
        }else
            mdebug1("Disabled rotation of internal logs by size.");

        sleep(1);
    }
}
