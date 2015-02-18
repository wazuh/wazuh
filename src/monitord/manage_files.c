/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "monitord.h"

static const char *(months[]) = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
                                };


void manage_files(int cday, int cmon, int cyear)
{
    time_t tm_old;
    struct tm *pp_old;

#ifndef SOLARIS
    struct tm p_old;
#endif

    char elogfile[OS_FLSIZE + 1];
    char elogfile_old[OS_FLSIZE + 1];

    char alogfile[OS_FLSIZE + 1];
    char alogfile_old[OS_FLSIZE + 1];

    char ajlogfile[OS_FLSIZE + 1];
    char ajlogfile_old[OS_FLSIZE + 1];

    char flogfile[OS_FLSIZE + 1];
    char flogfile_old[OS_FLSIZE + 1];

    /* Get time from the day before (for log signing) */
    tm_old = time(NULL);
    tm_old -= 93500;
#ifndef SOLARIS
    pp_old = localtime_r(&tm_old, &p_old);
#else
    pp_old = localtime(&tm_old);
#endif

    memset(elogfile, '\0', OS_FLSIZE + 1);
    memset(elogfile_old, '\0', OS_FLSIZE + 1);
    memset(alogfile, '\0', OS_FLSIZE + 1);
    memset(alogfile_old, '\0', OS_FLSIZE + 1);
    memset(ajlogfile, '\0', OS_FLSIZE + 1);
    memset(ajlogfile_old, '\0', OS_FLSIZE + 1);
    memset(flogfile, '\0', OS_FLSIZE + 1);
    memset(flogfile_old, '\0', OS_FLSIZE + 1);

    /* When the day changes, we wait up to day_wait before compressing the file */
    sleep(mond.day_wait);

    /* Event logfile */
    snprintf(elogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             EVENTS,
             cyear,
             months[cmon],
             "archive",
             cday);
    /* Event log file old */
    snprintf(elogfile_old, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             EVENTS,
             pp_old->tm_year + 1900,
             months[pp_old->tm_mon],
             "archive",
             pp_old->tm_mday);
    OS_SignLog(elogfile, elogfile_old, 0);
    OS_CompressLog(elogfile);

    /* alert logfile  */
    snprintf(alogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             ALERTS,
             cyear,
             months[cmon],
             "alerts",
             cday);
    /* alert logfile old  */
    snprintf(alogfile_old, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             ALERTS,
             pp_old->tm_year + 1900,
             months[pp_old->tm_mon],
             "alerts",
             pp_old->tm_mday);
    OS_SignLog(alogfile, alogfile_old, 1);
    OS_CompressLog(alogfile);

    /* alert logfile  */
    snprintf(ajlogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.json",
             ALERTS,
             cyear,
             months[cmon],
             "alerts",
             cday);
    /* alert logfile old  */
    snprintf(ajlogfile_old, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.json",
             ALERTS,
             pp_old->tm_year + 1900,
             months[pp_old->tm_mon],
             "alerts",
             pp_old->tm_mday);

    int exists = 0;
    FILE *fopnetest;

    if ((fopnetest = fopen(ajlogfile, "r"))) {
        exists = 1;
        fclose(fopnetest);
    }

    if ((fopnetest = fopen(ajlogfile_old, "r"))) {
        exists = 1;
        fclose(fopnetest);
    }

    if (exists) {
        /* Only if there is a file to operate on. */
        OS_SignLog(ajlogfile, ajlogfile_old, 1);
        OS_CompressLog(ajlogfile);
    }

    /* firewall events */
    snprintf(flogfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             FWLOGS,
             cyear,
             months[cmon],
             "firewall",
             cday);
    /* firewall events old */
    snprintf(flogfile_old, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d.log",
             FWLOGS,
             pp_old->tm_year + 1900,
             months[pp_old->tm_mon],
             "firewall",
             pp_old->tm_mday);
    OS_SignLog(flogfile, flogfile_old, 0);
    OS_CompressLog(flogfile);

    return;
}

