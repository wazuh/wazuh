/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Read MySQL logs */

#include "shared.h"
#include "logcollector.h"

/* Starting last time */
static char __mysql_last_time[18] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};


void *read_mysql_log(logreader *lf, int *rc, int drop_it) {
    size_t str_len = 0;
    int need_clear = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    char buffer[OS_MAXSTR + 1];
    int lines = 0;

    str[OS_MAXSTR] = '\0';
    *rc = 0;

    /* Get new entry */
    while (fgets(str, OS_MAXSTR - OS_LOG_HEADER, lf->fp) != NULL && (!maximum_lines || lines < maximum_lines)) {

        lines++;
        /* Get buffer size */
        str_len = strlen(str);

        /* Get the last occurrence of \n */
        if ((p = strrchr(str, '\n')) != NULL) {
            *p = '\0';

            /* If need clear is set, we just get the line and ignore it */
            if (need_clear) {
                need_clear = 0;
                continue;
            }
        } else {
            need_clear = 1;
        }

#ifdef WIN32
        if ((p = strrchr(str, '\r')) != NULL) {
            *p = '\0';
        }

        /* Look for empty string (only on windows) */
        if (str_len <= 2) {
            continue;
        }


        /* Windows can have comment on their logs */
        if (str[0] == '#') {
            continue;
        }
#endif

        /* MySQL messages have the following format:
         * 070823 21:01:30 xx
         */
        if ((str_len > 18) &&
                (str[6] == ' ') &&
                (str[9] == ':') &&
                (str[12] == ':') &&
                isdigit((int)str[0]) &&
                isdigit((int)str[1]) &&
                isdigit((int)str[2]) &&
                isdigit((int)str[3]) &&
                isdigit((int)str[4]) &&
                isdigit((int)str[5]) &&
                isdigit((int)str[7]) &&
                isdigit((int)str[8])) {
            /* Save last time */
            strncpy(__mysql_last_time, str, 16);
            __mysql_last_time[15] = '\0';


            /* Remove spaces and tabs */
            p = str + 15;
            while (*p == ' ' || *p == '\t') {
                p++;
            }

            /* Valid MySQL message */
            snprintf(buffer, OS_MAXSTR, "MySQL log: %s %s",
                     __mysql_last_time, p);
        }

        /* Multiple events at the same second share the same timestamp:
         * 0909 2020 2020 2020 20
         */
        else if ((str_len > 10) && (__mysql_last_time[0] != '\0') &&
                 (str[0] == 0x09) &&
                 (str[1] == 0x09) &&
                 (str[2] == 0x20) &&
                 (str[3] == 0x20) &&
                 (str[4] == 0x20) &&
                 (str[5] == 0x20) &&
                 (str[6] == 0x20) &&
                 (str[7] == 0x20)) {
            p = str + 2;

            /* Remove extra spaces and tabs */
            while (*p == ' ' || *p == '\t') {
                p++;
            }

            /* Valid MySQL message */
            snprintf(buffer, OS_MAXSTR, "MySQL log: %s %s",
                     __mysql_last_time, p);
        } else {
            continue;
        }

        mdebug2("Reading mysql messages: '%s'", buffer);

        /* Send message to queue */
        if (drop_it == 0) {
            w_msg_hash_queues_push(buffer, lf->file, strlen(buffer) + 1, lf->log_target, MYSQL_MQ);
        }

        continue;
    }

    mdebug2("Read %d lines from %s", lines, lf->file);
    return (NULL);
}
