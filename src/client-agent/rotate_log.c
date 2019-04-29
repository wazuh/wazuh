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
    char *new_path;
    int __ossec_rsec;
    time_t m_timespec;

    mwarn("The following internal options will be deprecated in the next version: compress, keep_log_days, day_wait, size_rotate_read and daily_rotations."
          "Please, use the 'logging' configuration block instead.");

    // Deprecated
    log_compress = getDefine_Int("monitord", "compress", 0, 1);

    // Deprecated
    keep_log_days = getDefine_Int("monitord", "keep_log_days", 0, 500);

    // Deprecated
    day_wait = getDefine_Int("monitord", "day_wait", 0, 600);

    // Deprecated
    size_rotate_read = getDefine_Int("monitord", "size_rotate", 0, 4096);
    unsigned long size_rotate = (unsigned long) size_rotate_read * 1024 * 1024;

    // Deprecated
    daily_rotations = getDefine_Int("monitord", "daily_rotations", 1, 256);

    mdebug1("Log rotating thread started.");

    localtime_r(&now, &tm);
    today = tm.tm_mday;

    /* Get current time before starting */
    time(&m_timespec);
    __ossec_rsec = m_timespec;

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


    monitor_config mond;
    const char *cfg = (isChroot() ? OSSECCONF : DEFAULTCPATH);
    int c;
    c = 0;
    c |= CROTMONITORD;
    if (ReadConfig(c, cfg, &mond, NULL) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    // If the deletion of old logs isn't disabled
    if(mond.rotate != -1) {
        mond.log_list_plain = get_rotation_list("logs", ".log");
        mond.log_list_json = get_rotation_list("logs", ".json");
        purge_rotation_list(mond.log_list_plain, mond.rotate);
        purge_rotation_list(mond.log_list_json, mond.rotate);
    }

    while (1) {
        now = time(NULL);
        localtime_r(&now, &tm);
        time(&m_timespec);

        if (today != tm.tm_mday) {
            sleep(day_wait);
            /* Daily rotation and compression of ossec.log/ossec.json */
            if(mond.rotation_enabled) {
                if(mond.ossec_log_plain) {
                    if(mond.log_list_plain->last) {
                        new_path = w_rotate_log(path, mond.compress_rotation, mond.keep_log_days, 1, 0, mond.daily_rotations, mond.log_list_plain->last->second_value);
                    } else {
                        new_path = w_rotate_log(path, mond.compress_rotation, mond.keep_log_days, 1, 0, mond.daily_rotations, 0);
                    }
                    if(new_path && mond.rotate != -1) {
                        add_new_rotation_node(mond.log_list_plain, new_path, mond.rotate);
                    }
                    os_free(new_path);
                }
                if(mond.ossec_log_json) {
                    if(mond.log_list_json->last) {
                        new_path = w_rotate_log(path_json, mond.compress_rotation, mond.keep_log_days, 1, 1, mond.daily_rotations, mond.log_list_json->last->second_value);
                    } else {
                        new_path = w_rotate_log(path_json, mond.compress_rotation, mond.keep_log_days, 1, 1, mond.daily_rotations, 0);
                    }
                    if(new_path && mond.rotate != -1) {
                        add_new_rotation_node(mond.log_list_json, new_path, mond.rotate);
                    }
                    os_free(new_path);
                }
            }
            today = tm.tm_mday;
        } else if (mond.rotation_enabled) {
            if(mond.max_size > 0 || size_rotate > 0) {
                if ((stat(path, &buf) == 0) && mond.ossec_log_plain) {
                    size = buf.st_size;
                    /* If log file reachs maximum size, rotate ossec.log */
                    if ( (long) size >= mond.max_size) {
                        if(mond.log_list_plain->last) {
                            new_path = w_rotate_log(path, mond.compress_rotation, mond.keep_log_days, 0, 0, mond.daily_rotations, mond.log_list_plain->last->second_value);
                        } else {
                            new_path = w_rotate_log(path, mond.compress_rotation, mond.keep_log_days, 0, 0, mond.daily_rotations, 0);
                        }
                        if(new_path && mond.rotate != -1) {
                            add_new_rotation_node(mond.log_list_plain, new_path, mond.rotate);
                        }
                        os_free(new_path);
                        __ossec_rsec = m_timespec;
                    }
                }
                if ((stat(path_json, &buf) == 0) && mond.ossec_log_json) {
                    size = buf.st_size;
                    /* If log file reachs maximum size, rotate ossec.json */
                    if ( (long) size >= mond.max_size) {
                        if(mond.log_list_json->last) {
                            new_path = w_rotate_log(path_json, mond.compress_rotation, mond.keep_log_days, 0, 1, mond.daily_rotations, mond.log_list_json->last->second_value);
                        } else{
                            new_path = w_rotate_log(path_json, mond.compress_rotation, mond.keep_log_days, 0, 1, mond.daily_rotations, 0);
                        }
                        if(new_path && mond.rotate != -1) {
                            add_new_rotation_node(mond.log_list_json, new_path, mond.rotate);
                        }
                        os_free(new_path);
                        __ossec_rsec = m_timespec;
                    }
                }
            }
            if (mond.rotation_enabled && mond.interval > 0 && m_timespec - __ossec_rsec > mond.interval) {
                if(mond.ossec_log_plain) {
                    if(mond.log_list_plain->last) {
                        new_path = w_rotate_log(path_json, mond.compress_rotation, mond.keep_log_days, 0, 0, mond.daily_rotations, mond.log_list_plain->last->second_value);
                    } else {
                        new_path = w_rotate_log(path_json, mond.compress_rotation, mond.keep_log_days, 0, 0, mond.daily_rotations, 0);
                    }
                    if(new_path && mond.rotate != -1) {
                        add_new_rotation_node(mond.log_list_plain, new_path, mond.rotate);
                    }
                    os_free(new_path);
                    __ossec_rsec = m_timespec;
                }
                if(mond.ossec_log_json) {
                    if(mond.log_list_json->last) {
                        new_path = w_rotate_log(path_json, mond.compress_rotation, mond.keep_log_days, 0, 1, mond.daily_rotations, mond.log_list_json->last->second_value);
                    } else {
                        new_path = w_rotate_log(path_json, mond.compress_rotation, mond.keep_log_days, 0, 1, mond.daily_rotations, 0);
                    }
                    if(new_path && mond.rotate != -1) {
                        add_new_rotation_node(mond.log_list_json, new_path, mond.rotate);
                    }
                    os_free(new_path);
                    __ossec_rsec = m_timespec;
                }
            }
        }

        sleep(1);
    }
}
