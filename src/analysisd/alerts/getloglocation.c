/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Get the log directory/file based on the day/month/year */

#include "getloglocation.h"
#include "config.h"

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
static FILE * openlog(FILE * fp, char path[OS_FLSIZE + 1], const char * logdir, int year, const char * month, const char * tag, int day, const char * ext, const char * lname, int * counter, int rotate);

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

    /* For the events */
    _eflog = openlog(_eflog, __elogfile, EVENTS, year, mon, "archive", day, "log", EVENTS_DAILY, &__ecounter, FALSE);

    /* For the events in JSON */
    if (Config.logall_json) {
        _ejflog = openlog(_ejflog, __ejlogfile, EVENTS, year, mon, "archive", day, "json", EVENTSJSON_DAILY, &__ejcounter, FALSE);
    }

    /* For the alerts logs */
    _aflog = openlog(_aflog, __alogfile, ALERTS, year, mon, "alerts", day, "log", ALERTS_DAILY, &__acounter, FALSE);

    if (Config.jsonout_output) {
        _jflog = openlog(_jflog, __jlogfile, ALERTS, year, mon, "alerts", day, "json", ALERTSJSON_DAILY, &__jcounter, FALSE);
    }

    /* For the firewall events */
    _fflog = openlog(_fflog, __flogfile, FWLOGS, year, mon, "firewall", day, "log", FWLOGS_DAILY, &__fcounter, FALSE);

    /* Setting the new day */
    __crt_day = day;
    __alerts_rsec = c_timespec.tv_sec;
    __archives_rsec = c_timespec.tv_sec;

    return (0);
}

// Open a valid log or die. No return on error.

FILE * openlog(FILE * fp, char * path, const char * logdir, int year, const char * month, const char * tag, int day, const char * ext, const char * lname, int * counter, int rotate) {
    char next[OS_FLSIZE + 1];
    char next_gz[OS_FLSIZE + 1];

    if (fp) {
        if (ftell(fp) == 0) {
            unlink(path);
        }

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

    // Create the logfile name

    if (rotate) {
        snprintf(path, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d-%.3d.%s", logdir, year, month, tag, day, ++(*counter), ext);
    } else {
        snprintf(path, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d.%s", logdir, year, month, tag, day, ext);

        // While this file is bigger than maximum or there is a next file
        for (*counter = 0; snprintf(next, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d-%.3d.%s", logdir, year, month, tag, day, *counter + 1, ext), snprintf(next_gz, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d-%.3d.%s.gz", logdir, year, month, tag, day, *counter + 1, ext), !IsFile(next) || !IsFile(next_gz) || (Config.max_output_size && FileSize(path) > Config.max_output_size); (*counter)++) {
            strncpy(path, next, OS_FLSIZE);
            path[OS_FLSIZE] = '\0';
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

void OS_RotateLogs(int day,int year,char *mon) {

    char c_alogfile[OS_FLSIZE + 1];
    char c_jlogfile[OS_FLSIZE + 1];
    char c_ejflogfile[OS_FLSIZE + 1];
    char c_elogfile[OS_FLSIZE + 1];
    char *previous_log = NULL;

    gettime(&local_timespec);

    // If more than interval time has passed and the interval rotation is set for any log
    if((Config.alerts_interval || Config.archives_interval)) {
        // If the rotation for alerts is enabled
        if(Config.alerts_rotation_enabled && Config.archives_interval > 0 && local_timespec.tv_sec - __alerts_rsec > Config.alerts_interval) {
            // Rotate alerts.log
            if (_aflog && !fseek(_aflog, 0, SEEK_END) && ftell(_aflog) > 0) {
                memset(c_alogfile, '\0', OS_FLSIZE + 1);
                snprintf(c_alogfile, OS_FLSIZE, "%s.gz", __alogfile);
                os_strdup(__alogfile, previous_log);
                _aflog = openlog(_aflog, __alogfile, ALERTS, year, mon, "alerts", day, "log", ALERTS_DAILY, &__acounter, TRUE);
                if(Config.alerts_compress_rotation) {
                    w_compress_gzfile(previous_log, c_alogfile);
                    /* Remove uncompressed file */
                    if(unlink(previous_log) == -1) {
                        merror("Unable to delete '%s' due to '%s'", previous_log, strerror(errno));
                    }
                }
                os_free(previous_log);
            }
            // Rotate alerts.json
            if (_jflog && !fseek(_jflog, 0, SEEK_END) && ftell(_jflog) > 0) {
                memset(c_jlogfile, '\0', OS_FLSIZE + 1);
                snprintf(c_jlogfile, OS_FLSIZE, "%s.gz", __jlogfile);
                os_strdup(__jlogfile, previous_log);
                _jflog = openlog(_jflog, __jlogfile, ALERTS, year, mon, "alerts", day, "json", ALERTSJSON_DAILY, &__jcounter, TRUE);
                if(Config.alerts_compress_rotation) {
                    w_compress_gzfile(previous_log, c_jlogfile);
                    /* Remove uncompressed file */
                    if(unlink(previous_log) == -1) {
                        merror("Unable to delete '%s' due to '%s'", previous_log, strerror(errno));
                    }
                }
                os_free(previous_log);
            }
            __alerts_rsec = local_timespec.tv_sec;
        }
        // If the rotation for archives is enabled
        if(Config.archives_rotation_enabled && Config.archives_interval > 0 && local_timespec.tv_sec - __archives_rsec > Config.archives_interval) {
            // Rotation for archives.log
            if (_eflog && !fseek(_eflog, 0, SEEK_END) && ftell(_eflog) > 0) {
                memset(c_elogfile, '\0', OS_FLSIZE + 1);
                snprintf(c_elogfile, OS_FLSIZE, "%s.gz", __elogfile);
                os_strdup(__elogfile, previous_log);
                _eflog = openlog(_eflog, __elogfile, EVENTS, year, mon, "archive", day, "log", EVENTS_DAILY, &__ecounter, TRUE);
                if(Config.archives_compress_rotation) {
                    w_compress_gzfile(previous_log, c_elogfile);
                    /* Remove uncompressed file */
                    if(unlink(previous_log) == -1) {
                        merror("Unable to delete '%s' due to '%s'", previous_log, strerror(errno));
                    }
                }
                os_free(previous_log);
            }
            // Rotation for archives.json
            if (_ejflog && !fseek(_ejflog, 0, SEEK_END) && ftell(_ejflog) > 0) {
                memset(c_ejflogfile, '\0', OS_FLSIZE + 1);
                snprintf(c_ejflogfile, OS_FLSIZE, "%s.gz", __ejlogfile);
                os_strdup(__ejlogfile, previous_log);
                _ejflog = openlog(_ejflog, __ejlogfile, EVENTS, year, mon, "archive", day, "json", EVENTSJSON_DAILY, &__ejcounter, TRUE);
                if(Config.archives_compress_rotation) {
                    w_compress_gzfile(previous_log, c_ejflogfile);
                    /* Remove uncompressed file */
                    if(unlink(previous_log) == -1) {
                        merror("Unable to delete '%s' due to '%s'", previous_log, strerror(errno));
                    }
                }
                os_free(previous_log);
            }
            __archives_rsec = local_timespec.tv_sec;
        }
    }

    // If any file is bigger than max_size and the size rotation is set for any log
    if((Config.alerts_max_size > 0) || (Config.archives_max_size > 0)) {
        // If the rotation for alerts is enabled
        if(Config.alerts_rotation_enabled) {
            // Rotate alerts.log
            if (_aflog && !fseek(_aflog, 0, SEEK_END) && ftell(_aflog) > Config.alerts_max_size) {
                memset(c_alogfile, '\0', OS_FLSIZE + 1);
                snprintf(c_alogfile, OS_FLSIZE, "%s.gz", __alogfile);
                os_strdup(__alogfile, previous_log);
                // Rotate only if the size of the file is bigger than max_size
                // TODO
                _aflog = openlog(_aflog, __alogfile, ALERTS, year, mon, "alerts", day, "log", ALERTS_DAILY, &__acounter, TRUE);
                if(Config.alerts_compress_rotation) {
                    w_compress_gzfile(previous_log, c_alogfile);
                    /* Remove uncompressed file */
                    if(unlink(previous_log) == -1) {
                        merror("Unable to delete '%s' due to '%s'", previous_log, strerror(errno));
                    }
                }
                os_free(previous_log);
                __alerts_rsec = local_timespec.tv_sec;
            }
            // Rotate alerts.json
            if (_jflog && !fseek(_jflog, 0, SEEK_END) && ftell(_jflog) > Config.alerts_max_size) {
                memset(c_jlogfile, '\0', OS_FLSIZE + 1);
                snprintf(c_jlogfile, OS_FLSIZE, "%s.gz", __jlogfile);
                os_strdup(__jlogfile, previous_log);
                // Rotate only if the size of the file is bigger than max_size
                // TODO
                _jflog = openlog(_jflog, __jlogfile, ALERTS, year, mon, "alerts", day, "json", ALERTSJSON_DAILY, &__jcounter, TRUE);
                if(Config.alerts_compress_rotation) {
                    w_compress_gzfile(previous_log, c_jlogfile);
                    /* Remove uncompressed file */
                    if(unlink(previous_log) == -1) {
                        merror("Unable to delete '%s' due to '%s'", previous_log, strerror(errno));
                    }
                }
                os_free(previous_log);
                __alerts_rsec = local_timespec.tv_sec;
            }
        }
        // If the rotation for archives is enabled
        if(Config.archives_rotation_enabled) {
            // Rotate archives.log
            if (_eflog && !fseek(_eflog, 0, SEEK_END) && ftell(_eflog) > 0) {
                memset(c_elogfile, '\0', OS_FLSIZE + 1);
                snprintf(c_elogfile, OS_FLSIZE, "%s.gz", __elogfile);
                os_strdup(__elogfile, previous_log);
                _eflog = openlog(_eflog, __elogfile, EVENTS, year, mon, "archive", day, "log", EVENTS_DAILY, &__ecounter, TRUE);
                if(Config.archives_compress_rotation) {
                    w_compress_gzfile(previous_log, c_elogfile);
                    /* Remove uncompressed file */
                    if(unlink(previous_log) == -1) {
                        merror("Unable to delete '%s' due to '%s'", previous_log, strerror(errno));
                    }
                }
                os_free(previous_log);
                __archives_rsec = local_timespec.tv_sec;
            }
            // Rotate archives.json
            if (_ejflog && !fseek(_ejflog, 0, SEEK_END) && ftell(_ejflog) > 0) {
                memset(c_ejflogfile, '\0', OS_FLSIZE + 1);
                snprintf(c_ejflogfile, OS_FLSIZE, "%s.gz", __ejlogfile);
                os_strdup(__ejlogfile, previous_log);
                _ejflog = openlog(_ejflog, __ejlogfile, EVENTS, year, mon, "archive", day, "json", EVENTSJSON_DAILY, &__ejcounter, TRUE);
                if(Config.archives_compress_rotation) {
                    w_compress_gzfile(previous_log, c_ejflogfile);
                    /* Remove uncompressed file */
                    if(unlink(previous_log) == -1) {
                        merror("Unable to delete '%s' due to '%s'", previous_log, strerror(errno));
                    }
                }
                os_free(previous_log);
                __archives_rsec = local_timespec.tv_sec;
            }
        }
    }
}
