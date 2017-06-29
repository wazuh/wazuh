/* Copyright (C) 2009 Trend Micro Inc.
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
static int  __crt_day;
static char __elogfile[OS_FLSIZE + 1];
static char __alogfile[OS_FLSIZE + 1];
static char __flogfile[OS_FLSIZE + 1];
static char __jlogfile[OS_FLSIZE + 1];
static char __ejlogfile[OS_FLSIZE + 1];

void OS_InitLog()
{
    OS_InitFwLog();

    __crt_day = 0;

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

int OS_GetLogLocation(const Eventinfo *lf)
{
    /* Check what directories to create
     * Check if the year directory is there
     * If not, create it. Same for the month directory.
     */
    

    /* For the events */
    if (_eflog) {
        if (ftell(_eflog) == 0) {
            unlink(__elogfile);
        }
        fclose(_eflog);
        _eflog = NULL;
    }

    snprintf(__elogfile, OS_FLSIZE, "%s/%d/", EVENTS, lf->year);
    if (IsDir(__elogfile) == -1)
        if (mkdir(__elogfile, 0770) == -1) {
            merror_exit(MKDIR_ERROR, __elogfile, errno, strerror(errno));
        }

    snprintf(__elogfile, OS_FLSIZE, "%s/%d/%s", EVENTS, lf->year, lf->mon);

    if (IsDir(__elogfile) == -1)
        if (mkdir(__elogfile, 0770) == -1) {
            merror_exit(MKDIR_ERROR, __elogfile, errno, strerror(errno));
        }

    /* Create the logfile name */
    snprintf(__elogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             EVENTS,
             lf->year,
             lf->mon,
             "archive",
             lf->day);

    _eflog = fopen(__elogfile, "a");
    if (!_eflog) {
        merror_exit("Error opening logfile: '%s'", __elogfile);
    }

    /* Create a symlink */
    unlink(EVENTS_DAILY);

    if (link(__elogfile, EVENTS_DAILY) == -1) {
        merror_exit(LINK_ERROR, __elogfile, EVENTS_DAILY, errno, strerror(errno));
    }
    /* For the events in JSON */
    if (Config.logall_json) {
        if (_ejflog) {
            if (ftell(_ejflog) == 0) {
                unlink(__ejlogfile);
            }
            fclose(_ejflog);
            _ejflog = NULL;
        }

        snprintf(__ejlogfile, OS_FLSIZE, "%s/%d/", EVENTS, lf->year);
        if (IsDir(__ejlogfile) == -1)
            if (mkdir(__ejlogfile, 0770) == -1) {
                merror_exit(MKDIR_ERROR, __ejlogfile, errno, strerror(errno));
        }

        snprintf(__ejlogfile, OS_FLSIZE, "%s/%d/%s", EVENTS, lf->year, lf->mon);

        if (IsDir(__ejlogfile) == -1)
            if (mkdir(__ejlogfile, 0770) == -1) {
                merror_exit(MKDIR_ERROR, __ejlogfile, errno, strerror(errno));
        }

        /* Create the json archives logfile name */
        snprintf(__ejlogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.json",
                 EVENTS,
                 lf->year,
                 lf->mon,
                 "archive",
                 lf->day);

        _ejflog = fopen(__ejlogfile, "a");

        if (!_ejflog) {
            merror_exit("Error opening logfile: '%s'", __ejlogfile);
        }

        /* Create a symlink */
        unlink(EVENTSJSON_DAILY);

        if (link(__ejlogfile, EVENTSJSON_DAILY) == -1) {
            merror_exit(LINK_ERROR, __ejlogfile, EVENTSJSON_DAILY, errno, strerror(errno));
        }
    }
    
    /* For the alerts logs */
    if (_aflog) {
        if (ftell(_aflog) == 0) {
            unlink(__alogfile);
        }
        fclose(_aflog);
        _aflog = NULL;
    }

    snprintf(__alogfile, OS_FLSIZE, "%s/%d/", ALERTS, lf->year);
    if (IsDir(__alogfile) == -1)
        if (mkdir(__alogfile, 0770) == -1) {
            merror_exit(MKDIR_ERROR, __alogfile, errno, strerror(errno));
        }

    snprintf(__alogfile, OS_FLSIZE, "%s/%d/%s", ALERTS, lf->year, lf->mon);

    if (IsDir(__alogfile) == -1)
        if (mkdir(__alogfile, 0770) == -1) {
            merror_exit(MKDIR_ERROR, __alogfile, errno, strerror(errno));
        }

    /* Create the logfile name */
    snprintf(__alogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             ALERTS,
             lf->year,
             lf->mon,
             "alerts",
             lf->day);

    _aflog = fopen(__alogfile, "a");

    if (!_aflog) {
        merror_exit("Error opening logfile: '%s'", __alogfile);
    }

    /* Create a symlink */
    unlink(ALERTS_DAILY);

    if (link(__alogfile, ALERTS_DAILY) == -1) {
        merror_exit(LINK_ERROR, __alogfile, ALERTS_DAILY, errno, strerror(errno));
    }

    if (Config.jsonout_output) {
        if (_jflog) {
            if (ftell(_jflog) == 0) {
                unlink(__jlogfile);
            }
            fclose(_jflog);
            _jflog = NULL;
        }

        snprintf(__jlogfile, OS_FLSIZE, "%s/%d/", ALERTS, lf->year);
        if (IsDir(__jlogfile) == -1)
            if (mkdir(__jlogfile, 0770) == -1) {
                merror_exit(MKDIR_ERROR, __jlogfile, errno, strerror(errno));
            }

        snprintf(__jlogfile, OS_FLSIZE, "%s/%d/%s", ALERTS, lf->year, lf->mon);

        if (IsDir(__jlogfile) == -1)
            if (mkdir(__jlogfile, 0770) == -1) {
                merror_exit(MKDIR_ERROR, __jlogfile, errno, strerror(errno));
            }

        /* Create the json logfile name */
        snprintf(__jlogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.json",
                 ALERTS,
                 lf->year,
                 lf->mon,
                 "alerts",
                 lf->day);

        _jflog = fopen(__jlogfile, "a");

        if (!_jflog) {
            merror_exit("Error opening logfile: '%s'", __jlogfile);
        }

        /* Create a symlink */
        unlink(ALERTSJSON_DAILY);

        if (link(__jlogfile, ALERTSJSON_DAILY) == -1) {
            merror_exit(LINK_ERROR, __jlogfile, ALERTSJSON_DAILY, errno, strerror(errno));
        }
    } 

    /* For the firewall events */
    if (_fflog) {
        if (ftell(_fflog) == 0) {
            unlink(__flogfile);
        }
        fclose(_fflog);
        _fflog = NULL;
    }

    snprintf(__flogfile, OS_FLSIZE, "%s/%d/", FWLOGS, lf->year);
    if (IsDir(__flogfile) == -1)
        if (mkdir(__flogfile, 0770) == -1) {
            merror_exit(MKDIR_ERROR, __flogfile, errno, strerror(errno));
        }

    snprintf(__flogfile, OS_FLSIZE, "%s/%d/%s", FWLOGS, lf->year, lf->mon);

    if (IsDir(__flogfile) == -1)
        if (mkdir(__flogfile, 0770) == -1) {
            merror_exit(MKDIR_ERROR, __flogfile, errno, strerror(errno));
        }

    /* Create the logfile name */
    snprintf(__flogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             FWLOGS,
             lf->year,
             lf->mon,
             "firewall",
             lf->day);

    _fflog = fopen(__flogfile, "a");

    if (!_fflog) {
        merror_exit("Error opening logfile: '%s'", __flogfile);
    }

    /* Create a symlink */
    unlink(FWLOGS_DAILY);

    if (link(__flogfile, FWLOGS_DAILY) == -1) {
        merror_exit(LINK_ERROR, __flogfile, FWLOGS_DAILY, errno, strerror(errno));
    }

    /* Setting the new day */
    __crt_day = lf->day;

    return (0);
}

