/* Copyright (C) 2015-2021, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Get the log directory/file based on the day/month/year */

#include "getloglocation.h"
#include "config.h"
#include "monitord/monitord.h"

/* Global definitions */
FILE *_eflog;
FILE *_aflog;
FILE *_fflog;
FILE *_jflog;
FILE *_ejflog;

/* Global variables */
static int __ecounter;
static int __acounter;
static int __fcounter;
static int __jcounter;
static int __ejcounter;
static char __elogfile[OS_FLSIZE + 1];
static char __alogfile[OS_FLSIZE + 1];
static char __flogfile[OS_FLSIZE + 1];
static char __jlogfile[OS_FLSIZE + 1];
static char __ejlogfile[OS_FLSIZE + 1];

/* Last time of each log rotation */
time_t last_archive_log = 0;
time_t last_archive_json = 0;
time_t last_alerts_log = 0;
time_t last_alerts_json = 0;

struct timespec local_timespec;

// Open a valid log or die. No return on error.
FILE * openlog(FILE * fp, char path[OS_FLSIZE + 1], const char * logdir, int year, const char * month, const char * tag, int day, const char * ext, const char * lname, int * counter, int rotate, __attribute__((unused)) rotation_list *list);

void OS_InitLog()
{
    OS_InitFwLog();

    __ecounter = 0;
    __acounter = 0;
    __fcounter = 0;
    __jcounter = 0;
    __ejcounter = 0;

    /* Alerts and events log file */
    memset(__alogfile, '\0', OS_FLSIZE + 1);
    memset(__elogfile, '\0', OS_FLSIZE + 1);
    memset(__flogfile, '\0', OS_FLSIZE + 1);
    memset(__jlogfile, '\0', OS_FLSIZE + 1);
    memset(__ejlogfile, '\0', OS_FLSIZE + 1);

    _eflog = NULL;
    _aflog = NULL;
    _fflog = NULL;
    _jflog = NULL;
    _ejflog = NULL;

    gettime(&local_timespec);

    /* Set the umask */
    umask(0027);
}

FILE * locate_log(rotation_list *list, int day, int year, char *mon, char *log_file, int counter, FILE *log,
                int compress, const char *folder, const char *daily, const char *tag, const char *ext, int rotate)
{
    char *prev_log;
    char c_log[OS_FLSIZE + 3];

    if (list && list->last && list->last->first_value == day) {
        counter = list->last->second_value;
    } else {
        counter = 0;
    }
    os_strdup(log_file, prev_log);
    memset(c_log, '\0', OS_FLSIZE + 1);
    snprintf(c_log, OS_FLSIZE+3, "%s.gz", prev_log);
    log = openlog(log, log_file, folder, year, mon, tag, day, ext, daily, &counter, 0, list);
    if (compress) {
        if (!IsFile(prev_log)) {
            w_compress_gzfile(prev_log, c_log, 1);
            /* Remove uncompressed file */
            if (unlink(prev_log) == -1) {
                merror("Unable to delete '%s' due to '%s'", prev_log, strerror(errno));
            }
        }
    }
    os_free(prev_log);
    add_new_rotation_node(list, log_file, rotate);

    return log;
}

int OS_GetLogLocation(int day,int year,char *mon)
{
    /* Check what directories to create
     * Check if the year directory is there
     * If not, create it. Same for the month directory.
     */

    /* For the events in plain format */
    if (Config.logall || (Config.archives_enabled && Config.archives_log_plain)) {
        _eflog = locate_log(Config.log_archives_plain, day, year, mon, __elogfile, __ecounter, _eflog,
                   Config.archives_compress_rotation, EVENTS, EVENTS_DAILY, "archive", "log", Config.archives_rotate);
    }

    /* For the events in JSON format*/
    if (Config.logall_json || (Config.archives_enabled && Config.archives_log_json)) {
        _ejflog = locate_log(Config.log_archives_json, day, year, mon, __ejlogfile, __ejcounter, _ejflog,
                   Config.archives_compress_rotation, EVENTS, EVENTSJSON_DAILY, "archive", "json", Config.archives_rotate);
    }

    /* For the alerts in plain format */
    if (Config.alerts_log || (Config.alerts_enabled && Config.alerts_log_plain)) {
        _aflog = locate_log(Config.log_alerts_plain, day, year, mon, __alogfile, __acounter, _aflog,
                   Config.alerts_compress_rotation, ALERTS, ALERTS_DAILY, "alerts", "log", Config.alerts_rotate);
    }

    /* For the alerts in JSON format */
    if (Config.jsonout_output || (Config.alerts_enabled && Config.alerts_log_json)) {
        _jflog = locate_log(Config.log_alerts_json, day, year, mon, __jlogfile, __jcounter, _jflog,
                   Config.alerts_compress_rotation, ALERTS, ALERTSJSON_DAILY, "alerts", "json", Config.alerts_rotate);
    }

    /* For the firewall events */
    _fflog = openlog(_fflog, __flogfile, FWLOGS, year, mon, "firewall", day, "log", FWLOGS_DAILY, &__fcounter, 0, NULL);

    return (0);
}

// Open a valid log or die. No return on error.

FILE * openlog(FILE * fp, char * path, const char * logdir, int year, const char * month, const char * tag, int day, const char * ext, const char * lname, int * counter, int rotate, rotation_list *list) {

    char prev_path[OS_FLSIZE + 1];
    snprintf(prev_path, OS_FLSIZE + 1, "%s", path);

    if (fp) {
        fclose(fp);
    }

    snprintf(path, OS_FLSIZE + 1, "%s/%d/", logdir, year);

    if (IsDir(path) == -1 && mkdir(path, 0770)) {
        merror_exit(MKDIR_ERROR, path, errno, strerror(errno));
    }

    snprintf(path, OS_FLSIZE + 1, "%s/%d/%s", logdir, year, month);

    if (IsDir(path) == -1 && mkdir(path, 0770)) {
        merror_exit(MKDIR_ERROR, path, errno, strerror(errno));
    }

    if (rotate == 2) {
        snprintf(path, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d.%s", logdir, year, month, tag, day, ext);
        if (rename_ex(prev_path, path)) {
            merror_exit(RENAME_ERROR, prev_path, path, errno, strerror(errno));
        }

        /* Update the rotation node */
        os_free(list->last->string_value);
        os_strdup(path, list->last->string_value);
        list->last->first_value = day;
        list->last->second_value = 0;

        if (fp = fopen(path, "a"), !fp) {
            merror_exit("Error opening logfile: '%s': (%d) %s", path, errno, strerror(errno));
        }

        return fp;
    }

    // Create the logfile name
    if (!rotate) {
        if(*counter == 0) {
            snprintf(path, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d.%s", logdir, year, month, tag, day, ext);
        } else {
            snprintf(prev_path, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d-%.3d.%s", logdir, year, month, tag, day, (*counter), ext);
            if (IsFile(prev_path)){
                snprintf(path, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d-%.3d.%s", logdir, year, month, tag, day, ++(*counter), ext);
            } else {
                snprintf(path, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d-%.3d.%s", logdir, year, month, tag, day, (*counter), ext);
            }
        }
    } else {
        snprintf(path, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d-%.3d.%s", logdir, year, month, tag, day, ++(*counter), ext);
    }

    if (fp = fopen(path, "a"), !fp) {
        merror_exit("Error opening logfile: '%s': (%d) %s", path, errno, strerror(errno));
    }

    // Create a symlink
    unlink(lname);

    if (link(path, lname) == -1) {
        merror_exit(LINK_ERROR, path, lname, errno, strerror(errno));
    }

    return fp;
}

FILE * rotate_logs(rotation_list *list, char *log_file, int today, int counter, FILE *_flog, const char *month,
                 int year, const char *folder, const char *log_daily, int compress, const char *ext, const char *tag,
                 time_t *last_rot, int maxage, rotation_list *other_list, int rotate_op) {
    char compress_file[OS_FLSIZE + 1] = {0};
    char path[PATH_MAX] = {0};
    char *previous_log = NULL;
    int last_counter, rotate, remove_tag = 0, json = 0;
    char *logfile;
    struct tm last_day;

    if (strcmp(tag, "alerts") == 0) {
        snprintf(path, PATH_MAX, "%s", LOGALERTS);
        remove_tag = 0;
    } else if (strcmp(tag, "archive") == 0) {
        snprintf(path, PATH_MAX, "%s", LOGARCHIVES);
        remove_tag = 1;
    }

    if (strcmp(ext, "json") == 0) {
        json = 1;
    } else if (strcmp(ext, "log") == 0) {
        json = 0;
    }

    localtime_r(last_rot, &last_day);
    os_strdup(log_file, logfile);

    if (list && list->last) {
        os_strdup(list->last->string_value, previous_log);
    } else {
        os_strdup(log_file, previous_log);
    }
    if (list && list->last && list->last->first_value == today) {
        counter = list->last->second_value;
        rotate = 1;
    } else {
        counter = 0;
        rotate = 0;
    }
    _flog = openlog(_flog, log_file, folder, year, month, tag, today, ext, log_daily, &counter, rotate, list);

    /* Log signing */
    if (list && list->last) {
        if (list->last->first_value == last_day.tm_mday) {
            last_counter = list->last->prev ? list->last->prev->second_value : -1;
        } else {
            last_counter = list->last->second_value;
        }
        if (list->last->prev && list->last->prev->first_value != last_day.tm_mday) {
            *last_rot = *last_rot - SECONDS_PER_DAY;
        }
    } else {
        last_counter = -1;
    }
    sign_log(folder, logfile, last_rot, last_counter, tag, ext);
    *last_rot = time(NULL);

    /* Log compression */
    memset(compress_file, '\0', OS_FLSIZE + 1);
    snprintf(compress_file, OS_FLSIZE, "%s.gz", previous_log);
    if (compress) {
        if (!IsFile(previous_log)) {
            w_compress_gzfile(previous_log, compress_file, 1);
        }
    }

    os_free(previous_log);
    os_free(logfile);

    /* Remove old logs if necessary */
    remove_old_logs(path, maxage, remove_tag ? "archives" : "alerts", json ? other_list : list, json ? list : other_list);
    /* Add the new rotation node */
    add_new_rotation_node(list, log_file, rotate_op);

    return _flog;
}

void OS_RotateLogs(int day, int year, char *mon) {

    gettime(&local_timespec);

    // If more than interval time has passed and the interval rotation is set for any log
    if ((Config.alerts_interval || Config.archives_interval)) {
        // If the rotation for alerts is enabled
        if (Config.alerts_rotation_enabled && Config.alerts_interval > 0) {
            // Rotate alerts.log
            if (Config.alerts_log_plain && current_time > alerts_time) {
                if (Config.alerts_min_size ? (_aflog && !fseek(_aflog, 0, SEEK_END) && ftell(_aflog) > Config.alerts_min_size) : 1) {
                    _aflog = rotate_logs(Config.log_alerts_plain, __alogfile, day, __acounter, _aflog, mon, year,
                                ALERTS, ALERTS_DAILY, Config.alerts_compress_rotation, "log", "alerts", &last_alerts_log,
                                Config.alerts_maxage, Config.log_alerts_json, Config.alerts_rotate);
                    alerts_time = calc_next_rotation(current_time, Config.alerts_interval_units, Config.alerts_interval);
                }
            }
            // Rotate alerts.json
            if (Config.alerts_log_json && current_time > alerts_time_json) {
                if (Config.alerts_min_size ? (_jflog && !fseek(_jflog, 0, SEEK_END) && ftell(_jflog) > Config.alerts_min_size) : 1) {
                    _jflog = rotate_logs(Config.log_alerts_json, __jlogfile, day, __jcounter, _jflog, mon, year,
                                ALERTS, ALERTSJSON_DAILY, Config.alerts_compress_rotation, "json", "alerts", &last_alerts_json,
                                Config.alerts_maxage, Config.log_alerts_plain, Config.alerts_rotate);
                    alerts_time_json = calc_next_rotation(current_time, Config.alerts_interval_units, Config.alerts_interval);
                }
            }
        }
        // If the rotation for archives is enabled
        if (Config.archives_rotation_enabled && Config.archives_interval > 0) {
            // Rotation for archives.log
            if (Config.archives_log_plain && current_time > archive_time) {
                if (Config.archives_min_size ? (_eflog && !fseek(_eflog, 0, SEEK_END) && ftell(_eflog) > Config.archives_min_size) : 1) {
                    _eflog = rotate_logs(Config.log_archives_plain, __elogfile, day, __ecounter, _eflog, mon, year,
                                EVENTS, EVENTS_DAILY, Config.archives_compress_rotation, "log", "archive", &last_archive_log,
                                Config.archives_maxage, Config.log_archives_json, Config.archives_rotate);
                    archive_time = calc_next_rotation(current_time, Config.archives_interval_units, Config.archives_interval);
                }
            }
            // Rotation for archives.json
            if (Config.archives_log_json && current_time > archive_time_json) {
                if (Config.archives_min_size ? (_ejflog && !fseek(_ejflog, 0, SEEK_END) && ftell(_ejflog) > Config.archives_min_size) : 1) {
                    _ejflog = rotate_logs(Config.log_archives_json, __ejlogfile, day, __ejcounter, _ejflog, mon, year,
                                EVENTS, EVENTSJSON_DAILY, Config.archives_compress_rotation, "json", "archive", &last_archive_json,
                                Config.archives_maxage, Config.log_archives_plain, Config.archives_rotate);
                    archive_time_json = calc_next_rotation(current_time, Config.archives_interval_units, Config.archives_interval);
                }
            }
        }
    }

    // If the rotation for alerts is enabled and max_size is set
    if (Config.alerts_rotation_enabled && Config.alerts_max_size > 0) {
        // Rotate alerts.log only if the size of the file is bigger than max_size
        if (Config.alerts_log_plain) {
            if (_aflog && !fseek(_aflog, 0, SEEK_END) && ftell(_aflog) > Config.alerts_max_size) {
                _aflog = rotate_logs(Config.log_alerts_plain, __alogfile, day, __acounter, _aflog, mon, year,
                            ALERTS, ALERTS_DAILY, Config.alerts_compress_rotation, "log", "alerts", &last_alerts_log,
                            Config.alerts_maxage, Config.log_alerts_json, Config.alerts_rotate);
            }
        }
        // Rotate alerts.json only if the size of the file is bigger than max_size
        if (Config.alerts_log_json) {
            if (_jflog && !fseek(_jflog, 0, SEEK_END) && ftell(_jflog) > Config.alerts_max_size) {
                _jflog = rotate_logs(Config.log_alerts_json, __jlogfile, day, __jcounter, _jflog, mon, year,
                            ALERTS, ALERTSJSON_DAILY, Config.alerts_compress_rotation, "json", "alerts", &last_alerts_json,
                            Config.alerts_maxage, Config.log_alerts_plain, Config.alerts_rotate);
            }
        }
    }

    // If the rotation for archives is enabled and maz_size is set
    if (Config.archives_rotation_enabled && Config.archives_max_size > 0) {
        // Rotate archives.log only if the size of the file is bigger than max_size
        if (Config.archives_log_plain) {
            if (_eflog && !fseek(_eflog, 0, SEEK_END) && ftell(_eflog) > Config.archives_max_size) {
                _eflog = rotate_logs(Config.log_archives_plain, __elogfile, day, __ecounter, _eflog, mon, year,
                            EVENTS, EVENTS_DAILY, Config.archives_compress_rotation, "log", "archive", &last_archive_log,
                            Config.archives_maxage, Config.log_archives_json, Config.archives_rotate);
            }
        }
        // Rotate archives.json only if the size of the file is bigger than max_size
        if (Config.archives_log_json) {
            if (_ejflog && !fseek(_ejflog, 0, SEEK_END) && ftell(_ejflog) > Config.archives_max_size) {
                _ejflog = rotate_logs(Config.log_archives_json, __ejlogfile, day, __ejcounter, _ejflog, mon, year,
                            EVENTS, EVENTSJSON_DAILY, Config.archives_compress_rotation, "json", "archive", &last_archive_json,
                            Config.archives_maxage, Config.log_archives_plain, Config.archives_rotate);
            }
        }
    }

    // If there hasn't been a rotation the day before, change the name of the log
    if (Config.alerts_rotation_enabled) {
        if (Config.alerts_log_plain && Config.log_alerts_plain && Config.log_alerts_plain->last && Config.log_alerts_plain->last->first_value != day && current_time != alerts_time) {
            _aflog = openlog(_aflog, __alogfile, ALERTS, year, mon, "alerts", day, "log", ALERTS_DAILY, &__acounter, 2, Config.log_alerts_plain);
        }
        if (Config.alerts_log_json && Config.log_alerts_json && Config.log_alerts_json->last && Config.log_alerts_json->last->first_value != day && current_time != alerts_time_json) {
            _jflog = openlog(_jflog, __jlogfile, ALERTS, year, mon, "alerts", day, "json", ALERTSJSON_DAILY, &__jcounter, 2, Config.log_alerts_json);
        }
    }
    if (Config.archives_rotation_enabled) {
        if (Config.archives_log_plain && Config.log_archives_plain && Config.log_archives_plain->last && Config.log_archives_plain->last->first_value != day && current_time != archive_time) {
            _eflog = openlog(_eflog, __elogfile, EVENTS, year, mon, "archive", day, "log", EVENTS_DAILY, &__ecounter, 2, Config.log_archives_plain);
        }
        if (Config.archives_log_json  && Config.log_archives_json && Config.log_archives_json->last && Config.log_archives_json->last->first_value != day && current_time != archive_time_json) {
            _ejflog = openlog(_ejflog, __ejlogfile, EVENTS, year, mon, "archive", day, "json", EVENTSJSON_DAILY, &__ejcounter, 2, Config.log_archives_json);
        }
    }
}
