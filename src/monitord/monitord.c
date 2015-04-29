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

    /* Connect to the message queue or exit */
    if ((mond.a_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
        ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
    }

    /* Send startup message */
    snprintf(str, OS_SIZE_1024 - 1, OS_AD_STARTED);
    if (SendMSG(mond.a_queue, str, ARGV0,
                LOCALFILE_MQ) < 0) {
        merror(QUEUE_SEND, ARGV0);
    }

    /* Main monitor loop */
    while (1) {
        tm = time(NULL);
        p = localtime(&tm);

        /* Check for unavailable agents */
        if (mond.monitor_agents) {
            monitor_agents();
        }

        /* Day changed, deal with log files */
        if (today != p->tm_mday) {
            /* Generate reports */
            generate_reports(today, thismonth, thisyear, p);

            manage_files(today, thismonth, thisyear);

            today = p->tm_mday;
            thismonth = p->tm_mon;
            thisyear = p->tm_year + 1900;
        }

        /* We only check every two minutes */
        sleep(120);
    }
}

