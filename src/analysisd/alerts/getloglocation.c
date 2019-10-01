/* Copyright (C) 2015-2019, Wazuh Inc.
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
static int __crt_day;
static int __alerts_rsec;
static int __archives_rsec;
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

struct timespec local_timespec;

// Open a valid log or die. No return on error.
static FILE * openlog(FILE * fp, char path[OS_FLSIZE + 1], const char * logdir, int year, const char * month, const char * tag, int day, const char * ext, const char * lname, int * counter, int rotate, __attribute__((unused)) rotation_list *list);

void OS_InitLog()
{
    OS_InitFwLog();

    __crt_day = 0;
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

int OS_GetLogLocation(int day,int year,char *mon)
{
    /* Check what directories to create
     * Check if the year directory is there
     * If not, create it. Same for the month directory.
     */

    char *prev_elogfile;
    char *prev_alogfile;
    char *prev_jlogfile;
    char *prev_ejlogfile;
    char c_elogfile[OS_FLSIZE + 3];
    char c_alogfile[OS_FLSIZE + 3];
    char c_jlogfile[OS_FLSIZE + 3];
    char c_ejlogfile[OS_FLSIZE + 3];

    /* For the events in plain format */
    if (Config.logall || (Config.archives_enabled && Config.archives_log_plain)) {
        if (Config.log_archives_plain && Config.log_archives_plain->last && Config.log_archives_plain->last->first_value == day) {
            __ecounter = Config.log_archives_plain->last->second_value;
        } else {
            __ecounter = 0;
        }
        os_strdup(__elogfile, prev_elogfile);
        memset(c_elogfile, '\0', OS_FLSIZE + 1);
        snprintf(c_elogfile, OS_FLSIZE+3, "%s.gz", prev_elogfile);
        _eflog = openlog(_eflog, __elogfile, EVENTS, year, mon, "archive", day, "log", EVENTS_DAILY, &__ecounter, FALSE, Config.log_archives_plain);
        if(Config.archives_compress_rotation) {
            if(!IsFile(prev_elogfile)) {
                w_compress_gzfile(prev_elogfile, c_elogfile);
                /* Remove uncompressed file */
                if(unlink(prev_elogfile) == -1) {
                    merror("Unable to delete '%s' due to '%s'", prev_elogfile, strerror(errno));
                }
            }
        }
        os_free(prev_elogfile);
        add_new_rotation_node(Config.log_archives_plain, __elogfile, Config.archives_rotate);
    }

    /* For the events in JSON format*/
    if (Config.logall_json || (Config.archives_enabled && Config.archives_log_json)) {
        if (Config.log_archives_json && Config.log_archives_json->last && Config.log_archives_json->last->first_value == day) {
            __ejcounter = Config.log_archives_json->last->second_value;
        } else {
            __ejcounter = 0;
        }
        os_strdup(__ejlogfile, prev_ejlogfile);
        memset(c_ejlogfile, '\0', OS_FLSIZE + 1);
        snprintf(c_ejlogfile, OS_FLSIZE+3, "%s.gz", prev_ejlogfile);
        _ejflog = openlog(_ejflog, __ejlogfile, EVENTS, year, mon, "archive", day, "json", EVENTSJSON_DAILY, &__ejcounter, FALSE, Config.log_archives_json);
        if(Config.archives_compress_rotation) {
            if(!IsFile(prev_ejlogfile)) {
                w_compress_gzfile(prev_ejlogfile, c_ejlogfile);
                /* Remove uncompressed file */
                if(unlink(prev_ejlogfile) == -1) {
                    merror("Unable to delete '%s' due to '%s'", prev_ejlogfile, strerror(errno));
                }
            }
        }
        os_free(prev_ejlogfile);
        add_new_rotation_node(Config.log_archives_json, __ejlogfile, Config.archives_rotate);
    }

    /* For the alerts in plain format */
    if (Config.alerts_log || (Config.alerts_enabled && Config.alerts_log_plain)) {
        if (Config.log_alerts_plain && Config.log_alerts_plain->last && Config.log_alerts_plain->last->first_value == day) {
            __acounter = Config.log_alerts_plain->last->second_value;
        } else {
            __acounter = 0;
        }
        os_strdup(__alogfile, prev_alogfile);
        memset(c_alogfile, '\0', OS_FLSIZE + 1);
        snprintf(c_alogfile, OS_FLSIZE+3, "%s.gz", prev_alogfile);
        _aflog = openlog(_aflog, __alogfile, ALERTS, year, mon, "alerts", day, "log", ALERTS_DAILY, &__acounter, FALSE, Config.log_alerts_plain);
        if(Config.alerts_compress_rotation) {
            if(!IsFile(prev_alogfile)) {
                w_compress_gzfile(prev_alogfile, c_alogfile);
                /* Remove uncompressed file */
                if(unlink(prev_alogfile) == -1) {
                    merror("Unable to delete '%s' due to '%s'", prev_alogfile, strerror(errno));
                }
            }
        }
        os_free(prev_alogfile);
        add_new_rotation_node(Config.log_alerts_plain, __alogfile, Config.alerts_rotate);
    }

    /* For the alerts in JSON format */
    if (Config.jsonout_output || (Config.alerts_enabled && Config.alerts_log_json)) {
        if (Config.log_alerts_json && Config.log_alerts_json->last && Config.log_alerts_json->last->first_value == day) {
            __jcounter = Config.log_alerts_json->last->second_value;
        } else {
            __jcounter = 0;
        }
        os_strdup(__jlogfile, prev_jlogfile);
        memset(c_jlogfile, '\0', OS_FLSIZE + 1);
        snprintf(c_jlogfile, OS_FLSIZE+3, "%s.gz", prev_jlogfile);
        _jflog = openlog(_jflog, __jlogfile, ALERTS, year, mon, "alerts", day, "json", ALERTSJSON_DAILY, &__jcounter, FALSE, Config.log_alerts_json);
        if(Config.alerts_compress_rotation) {
            if(!IsFile(prev_jlogfile)) {
                w_compress_gzfile(prev_jlogfile, c_jlogfile);
                /* Remove uncompressed file */
                if(unlink(prev_jlogfile) == -1) {
                    merror("Unable to delete '%s' due to '%s'", prev_jlogfile, strerror(errno));
                }
            }
        }
        os_free(prev_jlogfile);
        add_new_rotation_node(Config.log_alerts_json, __jlogfile, Config.alerts_rotate);

    }

    /* For the firewall events */
    _fflog = openlog(_fflog, __flogfile, FWLOGS, year, mon, "firewall", day, "log", FWLOGS_DAILY, &__fcounter, FALSE, NULL);

    /* Setting the new day */
    __crt_day = day;
    __alerts_rsec = c_timespec.tv_sec;
    __archives_rsec = c_timespec.tv_sec;

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
        rename(prev_path, path);

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
            if(IsFile(prev_path)){
                snprintf(path, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d-%.3d.%s", logdir, year, month, tag, day, ++(*counter), ext);
            } else {
                snprintf(path, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d-%.3d.%s", logdir, year, month, tag, day, (*counter), ext);
            }
        }
    } else {
        snprintf(prev_path, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d-%.3d.%s", logdir, year, month, tag, day, (*counter), ext);
        if(IsFile(prev_path) || rotate){
            snprintf(path, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d-%.3d.%s", logdir, year, month, tag, day, ++(*counter), ext);
        }
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

static void rotate_logs(rotation_list *list, char *log_file, int day, int counter, int rotate, FILE *_flog, const char *month,
                 int year, const char *folder, const char *log_daily, int compress, const char *ext, const char *tag) {
    char compress_file[OS_FLSIZE + 1];
    char *previous_log = NULL;

    if (list->last) {
        os_strdup(list->last->string_value, previous_log);
    } else {
        os_strdup(log_file, previous_log);
    }
    if (list && list->last && list->last->first_value == day) {
        counter = list->last->second_value;
        rotate = 1;
    } else {
        counter = 0;
        rotate = 0;
    }
    openlog(_flog, log_file, folder, year, month, tag, day, ext, log_daily, &counter, rotate, list);
    memset(compress_file, '\0', OS_FLSIZE + 1);
    snprintf(compress_file, OS_FLSIZE, "%s.gz", previous_log);
    if (compress) {
        if (!IsFile(previous_log)) {
            w_compress_gzfile(previous_log, compress_file);
            /* Remove uncompressed file */
            if (unlink(previous_log) == -1) {
                merror("Unable to delete '%s' due to '%s'", previous_log, strerror(errno));
            }
        }
    }
    os_free(previous_log);
}

void OS_RotateLogs(int day, int year, char *mon) {

    char path_alerts[PATH_MAX];
    char path_archives[PATH_MAX];
    struct tm rot;
    int rotate = 0;

    snprintf(path_alerts, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOGALERTS);
    snprintf(path_archives, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOGARCHIVES);

    gettime(&local_timespec);

    // If more than interval time has passed and the interval rotation is set for any log
    if ((Config.alerts_interval || Config.archives_interval)) {
        // If the rotation for alerts is enabled
        if (Config.alerts_rotation_enabled && Config.alerts_interval > 0) {
            // Rotate alerts.log
            if (Config.alerts_min_size ? (_aflog && !fseek(_aflog, 0, SEEK_END) && ftell(_aflog) > Config.alerts_min_size) : 1) {
                if (Config.alerts_log_plain && current_time > alerts_time) {
                    rotate_logs(Config.log_alerts_plain, __alogfile, day, __acounter, rotate, _aflog, mon, year,
                                ALERTS, ALERTS_DAILY, Config.alerts_compress_rotation, "log", "alerts");
                    remove_old_logs(path_alerts, Config.alerts_maxage, "alerts", Config.log_alerts_plain, Config.log_alerts_json);
                    add_new_rotation_node(Config.log_alerts_plain, __alogfile, Config.alerts_rotate);
                    alerts_time = calc_next_rotation(current_time, &rot, Config.alerts_interval_units, Config.alerts_interval);
                }
            }
            // Rotate alerts.json
            if (Config.alerts_min_size ? (_jflog && !fseek(_jflog, 0, SEEK_END) && ftell(_jflog) > Config.alerts_min_size) : 1) {
                if (Config.alerts_log_json && current_time > alerts_time_json) {
                    rotate_logs(Config.log_alerts_json, __jlogfile, day, __jcounter, rotate, _jflog, mon, year,
                                ALERTS, ALERTSJSON_DAILY, Config.alerts_compress_rotation, "json", "alerts");
                    remove_old_logs(path_alerts, Config.alerts_maxage, "alerts", Config.log_alerts_plain, Config.log_alerts_json);
                    add_new_rotation_node(Config.log_alerts_json, __jlogfile, Config.alerts_rotate);
                    alerts_time_json = calc_next_rotation(current_time, &rot, Config.alerts_interval_units, Config.alerts_interval);
                }
            }
            __alerts_rsec = local_timespec.tv_sec;
        }
        // If the rotation for archives is enabled
        if (Config.archives_rotation_enabled && Config.archives_interval >= 0) {
            // Rotation for archives.log
            if (Config.archives_min_size ? (_eflog && !fseek(_eflog, 0, SEEK_END) && ftell(_eflog) > Config.archives_min_size) : 1) {
                if (Config.archives_log_plain && current_time > archive_time) {
                    rotate_logs(Config.log_archives_plain, __elogfile, day, __ecounter, rotate, _eflog, mon, year,
                                EVENTS, EVENTS_DAILY, Config.archives_compress_rotation, "log", "archive");
                    remove_old_logs(path_archives, Config.archives_maxage, "archives", Config.log_archives_plain, Config.log_archives_json);
                    add_new_rotation_node(Config.log_archives_plain, __elogfile, Config.archives_rotate);
                    archive_time = calc_next_rotation(current_time, &rot, Config.archives_interval_units, Config.archives_interval);
                }
            }
            // Rotation for archives.json
            if (Config.archives_min_size ? (_ejflog && !fseek(_ejflog, 0, SEEK_END) && ftell(_ejflog) > Config.archives_min_size) : 1) {
                if (Config.archives_log_json && current_time > archive_time_json) {
                    rotate_logs(Config.log_archives_json, __ejlogfile, day, __ejcounter, rotate, _ejflog, mon, year,
                                EVENTS, EVENTSJSON_DAILY, Config.archives_compress_rotation, "json", "archive");
                    remove_old_logs(path_archives, Config.archives_maxage, "archive", Config.log_archives_plain, Config.log_archives_json);
                    add_new_rotation_node(Config.log_archives_json, __ejlogfile, Config.archives_rotate);
                    archive_time_json = calc_next_rotation(current_time, &rot, Config.archives_interval_units, Config.archives_interval);
                }
            }
            __archives_rsec = local_timespec.tv_sec;
        }
    }

    // If the rotation for alerts is enabled and max_size is set
    if (Config.alerts_rotation_enabled && Config.alerts_max_size > 0) {
        // Rotate alerts.log only if the size of the file is bigger than max_size
        if (Config.alerts_log_plain) {
            if (_aflog && !fseek(_aflog, 0, SEEK_END) && ftell(_aflog) > Config.alerts_max_size) {
                rotate_logs(Config.log_alerts_plain, __alogfile, day, __acounter, rotate, _aflog, mon, year,
                            ALERTS, ALERTS_DAILY, Config.alerts_compress_rotation, "log", "alerts");
                remove_old_logs(path_alerts, Config.alerts_maxage, "alerts", Config.log_alerts_plain, Config.log_alerts_json);
                add_new_rotation_node(Config.log_alerts_plain, __alogfile, Config.alerts_rotate);
                __alerts_rsec = local_timespec.tv_sec;
            }
        }
        // Rotate alerts.json only if the size of the file is bigger than max_size
        if (Config.alerts_log_json) {
            if (_jflog && !fseek(_jflog, 0, SEEK_END) && ftell(_jflog) > Config.alerts_max_size) {
                rotate_logs(Config.log_alerts_json, __jlogfile, day, __jcounter, rotate, _jflog, mon, year,
                            ALERTS, ALERTSJSON_DAILY, Config.alerts_compress_rotation, "json", "alerts");
                remove_old_logs(path_alerts, Config.alerts_maxage, "alerts", Config.log_alerts_plain, Config.log_alerts_json);
                add_new_rotation_node(Config.log_alerts_json, __jlogfile, Config.alerts_rotate);
                __alerts_rsec = local_timespec.tv_sec;
            }
        }
    }

    // If the rotation for archives is enabled and maz_size is set
    if (Config.archives_rotation_enabled && Config.archives_max_size > 0) {
        // Rotate archives.log only if the size of the file is bigger than max_size
        if (Config.archives_log_plain) {
            if (_eflog && !fseek(_eflog, 0, SEEK_END) && ftell(_eflog) > Config.archives_max_size) {
                rotate_logs(Config.log_archives_plain, __elogfile, day, __ecounter, rotate, _eflog, mon, year,
                            EVENTS, EVENTS_DAILY, Config.archives_compress_rotation, "log", "archive");
                remove_old_logs(path_archives, Config.archives_maxage, "archive", Config.log_archives_plain, Config.log_archives_json);
                add_new_rotation_node(Config.log_archives_plain, __elogfile, Config.archives_rotate);
                __archives_rsec = local_timespec.tv_sec;
            }
        }
        // Rotate archives.json only if the size of the file is bigger than max_size
        if (Config.archives_log_json) {
            if (_ejflog && !fseek(_ejflog, 0, SEEK_END) && ftell(_ejflog) > Config.archives_max_size) {
                rotate_logs(Config.log_archives_json, __ejlogfile, day, __ejcounter, rotate, _ejflog, mon, year,
                            EVENTS, EVENTSJSON_DAILY, Config.archives_compress_rotation, "json", "archive");
                remove_old_logs(path_archives, Config.archives_maxage, "archive", Config.log_archives_plain, Config.log_archives_json);
                add_new_rotation_node(Config.log_archives_json, __ejlogfile, Config.archives_rotate);
                __archives_rsec = local_timespec.tv_sec;
            }
        }
    }

    // If there hasn't been a rotation the day before, change the name of the log
    if (Config.alerts_rotation_enabled) {
        if (Config.alerts_log_plain && Config.log_alerts_plain->last && Config.log_alerts_plain->last->first_value != day && current_time != alerts_time) {
            _aflog = openlog(_aflog, __alogfile, ALERTS, year, mon, "alerts", day, "log", ALERTS_DAILY, &__acounter, 2, Config.log_alerts_plain);
        }
        if (Config.alerts_log_json && Config.log_alerts_json->last && Config.log_alerts_json->last->first_value != day && current_time != alerts_time_json) {
            _jflog = openlog(_jflog, __jlogfile, ALERTS, year, mon, "alerts", day, "json", ALERTSJSON_DAILY, &__jcounter, 2, Config.log_alerts_json);
        }
    }
    if (Config.archives_rotation_enabled) {
        if (Config.archives_log_plain && Config.log_archives_plain->last && Config.log_archives_plain->last->first_value != day && current_time != archive_time) {
            _eflog = openlog(_eflog, __elogfile, EVENTS, year, mon, "archive", day, "log", EVENTS_DAILY, &__ecounter, 2, Config.log_archives_plain);
        }
        if (Config.archives_log_json && Config.log_archives_json->last && Config.log_archives_json->last->first_value != day && current_time != archive_time_json) {
            _ejflog = openlog(_ejflog, __ejlogfile, EVENTS, year, mon, "archive", day, "json", EVENTSJSON_DAILY, &__ejcounter, 2, Config.log_archives_json);
        }
    }
}
