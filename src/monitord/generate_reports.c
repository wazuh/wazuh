/* @(#) $Id: ./src/monitord/generate_reports.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2010 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "monitord.h"
int OS_SendCustomEmail(char **to, char *subject, char *smtpserver, char *from, char *idsname, FILE *fp, struct tm *p);
char *(monthss[])={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug",
                  "Sep","Oct","Nov","Dec"};


void generate_reports(int cday, int cmon, int cyear,struct tm *p)
{
    int s = 0;

    if(!mond.smtpserver)
    {
        return;
    }

    if(mond.reports)
    {
        int twait = 0;
        int childcount = 0;
        while(mond.reports[s])
        {
            pid_t pid;
            if(mond.reports[s]->emailto == NULL)
            {
                s++;
                continue;
            }

            /* We create a new process to run the report and send the email.
             * To avoid crashing monitord if something goes wrong.
             */
            pid = fork();
            if(pid < 0)
            {
                merror("%s: ERROR: Fork failed. cause: %d - %s", ARGV0, errno, strerror(errno));
                s++;
                continue;
            }
            else if(pid == 0)
            {
                char fname[256];
                char aname[256];
                fname[255] = '\0';
                aname[255] = '\0';
                snprintf(fname, 255, "/logs/.report-%d.log", getpid());

                merror("%s: INFO: Starting daily reporting for '%s'", ARGV0, mond.reports[s]->title);
                mond.reports[s]->r_filter.fp = fopen(fname, "w+");
                if(!mond.reports[s]->r_filter.fp)
                {
                    merror("%s: ERROR: Unable to open temporary reports file.", ARGV0);
                    s++;
                    continue;
                }


                /* Opening the log file. */
                snprintf(aname, 255, "%s/%d/%s/ossec-%s-%02d.log",
                         ALERTS, cyear, monthss[cmon], "alerts", cday);
                os_strdup(aname, mond.reports[s]->r_filter.filename);


                /* Starting report */
                os_ReportdStart(&mond.reports[s]->r_filter);
                fflush(mond.reports[s]->r_filter.fp);

                if(ftell(mond.reports[s]->r_filter.fp) < 10)
                {
                    merror("%s: INFO: Report '%s' empty.", ARGV0, mond.reports[s]->title);
                }
                else if(OS_SendCustomEmail(mond.reports[s]->emailto, mond.reports[s]->title,
                        mond.smtpserver, mond.emailfrom, mond.emailidsname, mond.reports[s]->r_filter.fp, p) != 0)
                {
                    merror("%s: WARN: Unable to send report email.", ARGV0);
                }
                fclose(mond.reports[s]->r_filter.fp);
                unlink(fname);
                free(mond.reports[s]->r_filter.filename);
                mond.reports[s]->r_filter.filename = NULL;

                exit(0);
            }
            else
            {
                /* Sleep between each report. Time is not important in here. */
                sleep(20);
                childcount++;
            }

            s++;
        }


        while (childcount)
        {
            int wp;
            wp = waitpid((pid_t) -1, NULL, WNOHANG);
            if (wp < 0)
            {
                merror(WAITPID_ERROR, ARGV0);
            }
            else if(wp == 0)
            {
                /* If there is still any report left, sleep 5 and try again.*/
                sleep(5);
                twait++;

                if(twait > 2)
                {
                    merror("%s: WARN: Report taking too long to complete. Waiting for it to finish...", ARGV0);
                    sleep(10);
                    if(twait > 10)
                    {
                        merror("%s: WARN: Report took too long. Moving on...", ARGV0);
                        break;
                    }
                }
            }
            else
            {
                childcount--;
            }
        }
    }
    return;
}

/* EOF */
