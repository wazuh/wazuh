/* Copyright (C) 2015-2019, Wazuh Inc.
 * June 13, 2017.
 *
 * This program is a free software; you can redistribute it
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
    struct tm tm;
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

    while (1) {
        now = time(NULL);
        localtime_r(&now, &tm);

        if (today != tm.tm_mday) {
            sleep(day_wait);
            /* Daily rotation and compression of ossec.log/ossec.json */
            w_rotate_log(log_compress, keep_log_days, 1, 0, daily_rotations);
            today = tm.tm_mday;
        }

        if (size_rotate > 0) {
            if (stat(path, &buf) == 0) {
                size = buf.st_size;
                /* If log file reachs maximum size, rotate ossec.log */
                if ( (unsigned long) size >= size_rotate) {
                    w_rotate_log(log_compress, keep_log_days, 0, 0, daily_rotations);
                }
            }

            if (stat(path_json, &buf) == 0) {
                size = buf.st_size;
                /* If log file reachs maximum size, rotate ossec.json */
                if ( (unsigned long) size >= size_rotate) {
                    w_rotate_log(log_compress, keep_log_days, 0, 1, daily_rotations);
                }
            }
        }else
            mdebug1("Disabled rotation of internal logs by size.");

        sleep(1);
    }
}
