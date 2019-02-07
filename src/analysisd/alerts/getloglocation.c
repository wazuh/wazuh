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
static int __crt_rsec;
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
    __crt_rsec = c_timespec.tv_sec;

    return (0);
}

// Open a valid log or die. No return on error.

FILE * openlog(FILE * fp, char * path, const char * logdir, int year, const char * month, const char * tag, int day, const char * ext, const char * lname, int * counter, int rotate) {
    char next[OS_FLSIZE + 1];

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
        for (*counter = 0; snprintf(next, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d-%.3d.%s", logdir, year, month, tag, day, *counter + 1, ext), !IsFile(next) || (Config.max_output_size && FileSize(path) > Config.max_output_size); (*counter)++) {
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

    if (Config.rotate_interval && c_time - __crt_rsec > Config.rotate_interval) {
        // If timespan exceeded the rotation time and the file isn't empty
        if (_eflog && ftell(_eflog) > 0) {
            _eflog = openlog(_eflog, __elogfile, EVENTS, year, mon, "archive", day, "log", EVENTS_DAILY, &__ecounter, TRUE);
        }

        if (_ejflog && ftell(_ejflog) > 0) {
            _ejflog = openlog(_ejflog, __ejlogfile, EVENTS, year, mon, "archive", day, "json", EVENTSJSON_DAILY, &__ejcounter, TRUE);
        }

        if (_aflog && ftell(_aflog) > 0) {
            _aflog = openlog(_aflog, __alogfile, ALERTS, year, mon, "alerts", day, "log", ALERTS_DAILY, &__acounter, TRUE);
        }

        if (_jflog && ftell(_jflog) > 0) {
            _jflog = openlog(_jflog, __jlogfile, ALERTS, year, mon, "alerts", day, "json", ALERTSJSON_DAILY, &__jcounter, TRUE);
        }

        if (_fflog && ftell(_fflog) > 0) {
            _fflog = openlog(_fflog, __flogfile, FWLOGS, year, mon, "firewall", day, "log", FWLOGS_DAILY, &__fcounter, TRUE);
        }

        __crt_rsec = c_time;
    } else if (Config.max_output_size && c_time - __crt_rsec > Config.min_rotate_interval) {
        // Or if timespan from last rotation is enough and the file is too big

        if (_eflog && ftell(_eflog) > Config.max_output_size) {
            _eflog = openlog(_eflog, __elogfile, EVENTS, year, mon, "archive", day, "log", EVENTS_DAILY, &__ecounter, TRUE);
            __crt_rsec = c_time;
        }

        if (_ejflog && ftell(_ejflog) > Config.max_output_size) {
            _ejflog = openlog(_ejflog, __ejlogfile, EVENTS, year, mon, "archive", day, "json", EVENTSJSON_DAILY, &__ejcounter, TRUE);
            __crt_rsec = c_time;
        }

        if (_aflog && ftell(_aflog) > Config.max_output_size) {
            _aflog = openlog(_aflog, __alogfile, ALERTS, year, mon, "alerts", day, "log", ALERTS_DAILY, &__acounter, TRUE);
            __crt_rsec = c_time;
        }

        if (_jflog && ftell(_jflog) > Config.max_output_size) {
            _jflog = openlog(_jflog, __jlogfile, ALERTS, year, mon, "alerts", day, "json", ALERTSJSON_DAILY, &__jcounter, TRUE);
            __crt_rsec = c_time;
        }

        if (_fflog && ftell(_fflog) > Config.max_output_size) {
            _fflog = openlog(_fflog, __flogfile, FWLOGS, year, mon, "firewall", day, "log", FWLOGS_DAILY, &__fcounter, TRUE);
            __crt_rsec = c_time;
        }
    }
}
