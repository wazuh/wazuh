/* Copyright (C) 2015-2021, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "monitord.h"
#include "os_maild/maild.h"

void generate_reports(time_t starting_time)
{
    if (mond.reports == 0 || !mond.smtpserver) {
        return;
    }

    int reports_in_flight = 0;
    for(report_config* current_report = *mond.reports; current_report; current_report++)
    {
        if (*current_report->emailto == NULL) {
            minfo("Report <%s> does not have a mailto set. Skipping...", current_report->title);
            continue;
        }

        /* We create a new process to run the report and send the email.
         * To avoid crashing monitord if something goes wrong.
         */
        pid_t pid = fork();

        if (pid < 0) {
            merror("Fork failed. cause: %d - %s", errno, strerror(errno));
            continue;
        } else if (pid == 0) {

            char report_path[OS_FLSIZE] = {0};
            snprintf(report_path, OS_FLSIZE, "/logs/.report-%d.log", (int)getpid());

            minfo("Starting daily reporting for '%s'", current_report->title);

            FILE* report_file = fopen(report_path, "w+");
            if (report_file == 0) {
                merror("Unable to open temporary reports file.");
                continue;
            }

            current_report->r_filter.fp = report_file;

            int additional_logs_sufix = 0;
            char log_path[OS_FLSIZE] = {0};

            struct tm translated_time = {0};
            localtime_r(&starting_time, &translated_time);

            time_t now = time(0);
            struct tm translated_now = {0};
            localtime_r(&now, &translated_now);

            do{
                snprintf(log_path, OS_FLSIZE,
                        additional_logs_sufix == 0 ? "%s/%d/%s/ossec-alerts-%02d.log" :
                        "%s/%d/%s/ossec-alerts-%02d-%.3d.log",
                        ALERTS,
                        translated_time.tm_year + 1900,
                        get_short_month_name(translated_time.tm_mon),
                        translated_time.tm_mday,
                        additional_logs_sufix);

                additional_logs_sufix++;

                if(IsFile(log_path) != 0)
                {
                    /* No more logs to process */
                    break;
                }

                os_strdup(log_path, current_report->r_filter.filename);

                os_ReportdStart(&current_report->r_filter);
                fflush(current_report->r_filter.fp);

                if (ftell(current_report->r_filter.fp) < 10) {
                    minfo("Report '%s' empty.", current_report->title);
                } else if (OS_SendCustomEmail(current_report->emailto,
                            current_report->title,
                            mond.smtpserver,
                            mond.emailfrom,
                            NULL,
                            mond.emailidsname,
                            current_report->r_filter.fp,
                            &translated_now)
                        != 0) {
                    mwarn("Unable to send report email.");
                }

                free(current_report->r_filter.filename);
                current_report->r_filter.filename = NULL;

            }while(1);

            fclose(current_report->r_filter.fp);
            unlink(report_path);

            exit(0);
        } else {
            /* Sleep between each report. Time is not important in here. */
            sleep(20);
            reports_in_flight++;
        }
    }


    int retries = 0;
    while (reports_in_flight) {
        int wp = waitpid((pid_t) - 1, NULL, WNOHANG);

        if (wp < 0) {

            merror(WAITPID_ERROR, errno, strerror(errno));

        } else if (wp == 0) {
            /* If there is still any report left, sleep 5 and try again */
            sleep(5);
            retries++;

            if (retries > 2) {
                mwarn("Report taking too long to complete. Waiting for it to finish...");

                sleep(10);

                if (retries > 10) {
                    mwarn("Report took too long. Moving on...");
                    break;
                }
            }
        } else {
            reports_in_flight--;
        }
    }
}
