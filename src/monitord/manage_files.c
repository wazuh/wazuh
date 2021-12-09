/* Copyright (C) 2015-2021, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "monitord.h"

static void manage_log(const char * logdir, const struct tm* current_time, const struct tm * day_old_time, const char * tag, const char * ext)
{
    char logfile[OS_FLSIZE];
    char logfile_old[OS_FLSIZE];

    snprintf(logfile, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d", logdir, current_time->tm_year, get_short_month_name(current_time->tm_mon), tag, current_time->tm_mday);
    snprintf(logfile_old, OS_FLSIZE, "%s/%d/%s/ossec-%s-%02d", logdir, day_old_time->tm_year + 1900, get_short_month_name(day_old_time->tm_mon), tag, day_old_time->tm_mday);

    OS_SignLog(logfile, logfile_old, ext);

    if (mond.compress) {
        int additional_logs = 0;
        do
        {
            char log_file_path[OS_FLSIZE];
            if(additional_logs++)
            {
                os_snprintf(log_file_path, OS_FLSIZE, "%s.%s", logfile, ext);
            }
            else
            {
                os_snprintf(log_file_path, OS_FLSIZE, "%s-%.3d.%s", logfile, additional_logs, ext);
            }

            if(0 != IsFile(log_file_path))
            {
                break;
            }

            OS_CompressLog(log_file_path);

        }while(1);
    }
}

void compress_and_sign_logs(time_t starting_time)
{
    struct tm translated_yesterday;
    localtime_r(&starting_time, &translated_yesterday);

    struct tm translated_now;
    time_t now = time(0);
    localtime_r(&now, &translated_now);

    manage_log(EVENTS, &translated_now, &translated_yesterday, "archive", "log");
    manage_log(EVENTS, &translated_now, &translated_yesterday, "archive", "json");
    manage_log(ALERTS, &translated_now, &translated_yesterday, "alerts", "log");
    manage_log(ALERTS, &translated_now, &translated_yesterday, "alerts", "json");
    manage_log(FWLOGS, &translated_now, &translated_yesterday, "firewall", "log");
}
