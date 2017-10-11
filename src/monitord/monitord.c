/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "monitord.h"

/* Global variables */
monitor_config mond;


void Monitord()
{
    time_t tm;
    struct tm *p;
    int counter = 0;

    char path[PATH_MAX];
    char path_json[PATH_MAX];
    struct stat buf;
    off_t size;

    int today = 0;
    int thismonth = 0;
    int thisyear = 0;

    char str[OS_SIZE_1024 + 1];

    /* Wait a few seconds to settle */
    sleep(10);

    memset(str, '\0', OS_SIZE_1024 + 1);

    /* Get current time before starting */
    tm = time(NULL);
    p = localtime(&tm);

    today = p->tm_mday;
    thismonth = p->tm_mon;
    thisyear = p->tm_year + 1900;

    /* Set internal log path to rotate them */
#ifdef WIN32
    // ossec.log
    snprintf(path, PATH_MAX, "%s", LOGFILE);
    // ossec.json
    snprintf(path_json, PATH_MAX, "%s", LOGJSONFILE);
#else
    // /var/ossec/logs/ossec.log
    snprintf(path, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOGFILE);
    // /var/ossec/logs/ossec.json
    snprintf(path_json, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOGJSONFILE);
#endif

    /* Connect to the message queue or exit */
    if ((mond.a_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
        merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
    }

    /* Send startup message */
    snprintf(str, OS_SIZE_1024 - 1, OS_AD_STARTED);
    if (SendMSG(mond.a_queue, str, ARGV0,
                LOCALFILE_MQ) < 0) {
        merror(QUEUE_SEND);
    }

    /* Main monitor loop */
    while (1) {
        tm = time(NULL);
        p = localtime(&tm);
        counter++;

#ifndef LOCAL
        /* Check for unavailable agents, every two minutes */
        if (mond.monitor_agents && counter >= 120) {
            monitor_agents();
            counter = 0;
        }
#endif

        /* Day changed, deal with log files */
        if (today != p->tm_mday) {
            if (mond.rotate_log) {
                sleep(mond.day_wait);
                /* Daily rotation and compression of ossec.log/ossec.json */
                w_rotate_log(mond.compress, mond.keep_log_days, 1, 0, mond.daily_rotations);
            }

            /* Generate reports */
            generate_reports(today, thismonth, thisyear, p);
            manage_files(today, thismonth, thisyear);

            today = p->tm_mday;
            thismonth = p->tm_mon;
            thisyear = p->tm_year + 1900;
        } else if (mond.rotate_log && mond.size_rotate > 0) {
            if (stat(path, &buf) == 0) {
                size = buf.st_size;
                /* If log file reachs maximum size, rotate ossec.log */
                if ( (unsigned long) size >= mond.size_rotate) {
                    w_rotate_log(mond.compress, mond.keep_log_days, 0, 0, mond.daily_rotations);
                }
            }

            if (stat(path_json, &buf) == 0) {
                size = buf.st_size;
                /* If log file reachs maximum size, rotate ossec.json */
                if ( (unsigned long) size >= mond.size_rotate) {
                    w_rotate_log(mond.compress, mond.keep_log_days, 0, 1, mond.daily_rotations);
                }
            }
        }

        sleep(1);
    }
}
