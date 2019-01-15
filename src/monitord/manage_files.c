/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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

static void manage_log(const char * logdir, int cday, int cmon, int cyear, const struct tm * pp_old, const char * tag, const char * ext);

void manage_files(int cday, int cmon, int cyear)
{
    time_t tm_old;
    struct tm *pp_old;

#ifndef SOLARIS
    struct tm p_old;
#endif

    /* Get time from the day before (for log signing) */
    tm_old = time(NULL);
    tm_old -= 93500;
#ifndef SOLARIS
    pp_old = localtime_r(&tm_old, &p_old);
#else
    pp_old = localtime(&tm_old);
#endif

    manage_log(EVENTS, cday, cmon, cyear, pp_old, "archive", "log");
    manage_log(EVENTS, cday, cmon, cyear, pp_old, "archive", "json");
    manage_log(ALERTS, cday, cmon, cyear, pp_old, "alerts", "log");
    manage_log(ALERTS, cday, cmon, cyear, pp_old, "alerts", "json");
    manage_log(FWLOGS, cday, cmon, cyear, pp_old, "firewall", "log");
}

void manage_log(const char * logdir, int cday, int cmon, int cyear, const struct tm * pp_old, const char * tag, const char * ext) {
    int i;
    char logfile[OS_FLSIZE + 1];
    char logfile_r[OS_FLSIZE + 1];
    char logfile_old[OS_FLSIZE + 1];

    snprintf(logfile, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d", logdir, cyear, months[cmon], tag, cday);
    snprintf(logfile_old, OS_FLSIZE + 1, "%s/%d/%s/ossec-%s-%02d", logdir, pp_old->tm_year + 1900, months[pp_old->tm_mon], tag, pp_old->tm_mday);

    OS_SignLog(logfile, logfile_old, ext);

    if (mond.compress) {
        snprintf(logfile_r, OS_FLSIZE + 1, "%s.%s", logfile, ext);
        OS_CompressLog(logfile_r);

        for (i = 1; snprintf(logfile_r, OS_FLSIZE + 1, "%s-%.3d.%s", logfile, i, ext), !IsFile(logfile_r) && FileSize(logfile_r) > 0; i++) {
            OS_CompressLog(logfile_r);
        }
    }
}
