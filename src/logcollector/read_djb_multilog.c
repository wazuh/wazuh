/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Read DJB multilog */

#include "shared.h"
#include "logcollector.h"


/* To translante between month (int) to month (char) */
static const char *(djb_month[]) = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
                                   };
static char djb_host[512 + 1];


/* Initialize multilog */
int init_djbmultilog(int pos)
{
    char *djbp_name = NULL;
    char *tmp_str = NULL;

    logff[pos].djb_program_name = NULL;

    /* Initialize hostname */
    memset(djb_host, '\0', 512 + 1);

#ifndef WIN32
    if (gethostname(djb_host, 512 - 1) != 0) {
        strncpy(djb_host, "unknown", 512 - 1);
    } else {
        char *_ltmp;

        /* Remove domain part if available */
        _ltmp = strchr(djb_host, '.');
        if (_ltmp) {
            *_ltmp = '\0';
        }
    }
#else
    strncpy(djb_host, "win32", 512 - 1);
#endif

    /* Multilog must be in the following format: /path/program_name/current */
    tmp_str = strrchr(logff[pos].file, '/');
    if (!tmp_str) {
        return (0);
    }

    /* Must end with /current and must not be in the beginning of the string */
    if ((strcmp(tmp_str, "/current") != 0) || (tmp_str == logff[pos].file)) {
        return (0);
    }

    tmp_str[0] = '\0';

    /* Get final name */
    djbp_name = strrchr(logff[pos].file, '/');
    if (djbp_name == logff[pos].file) {
        tmp_str[0] = '/';
        return (0);
    }

    os_strdup(djbp_name + 1, logff[pos].djb_program_name);
    tmp_str[0] = '/';

    verbose("%s: INFO: Using program name '%s' for DJB multilog file: '%s'.",
            ARGV0, logff[pos].djb_program_name, logff[pos].file);

    return (1);
}

void *read_djbmultilog(int pos, int *rc, int drop_it)
{
    size_t str_len = 0;
    int need_clear = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    char buffer[OS_MAXSTR + 1];

    str[OS_MAXSTR] = '\0';
    *rc = 0;

    /* Must have a valid program name */
    if (!logff[pos].djb_program_name) {
        return (NULL);
    }

    /* Get new entry */
    while (fgets(str, OS_MAXSTR - OS_LOG_HEADER, logff[pos].fp) != NULL) {
        /* Get buffer size */
        str_len = strlen(str);

        /* Getting the last occurence of \n */
        if ((p = strrchr(str, '\n')) != NULL) {
            *p = '\0';

            /* If need_clear is set, we just get the line and ignore it */
            if (need_clear) {
                need_clear = 0;
                continue;
            }
        } else {
            need_clear = 1;
        }

        /* Multilog messages have the following format:
         * @40000000463246020c2ca16c xx...
         */
        if ((str_len > 26) &&
                (str[0] == '@') &&
                isalnum((int)str[1]) &&
                isalnum((int)str[2]) &&
                isalnum((int)str[3]) &&
                isalnum((int)str[24]) &&
                (str[25] == ' ')) {
            /* Remove spaces and tabs */
            p = str + 26;
            while (*p == ' ' || *p == '\t') {
                p++;
            }

            /* If message has a valid syslog header, send as is */
            if ((str_len > 44) &&
                    (p[3] == ' ') &&
                    (p[6] == ' ') &&
                    (p[9] == ':') &&
                    (p[12] == ':') &&
                    (p[15] == ' ')) {
                p += 16;
                strncpy(buffer, p, OS_MAXSTR);
            } else {
                /* We will add a proper syslog header */
                time_t djbtime;
                struct tm *pt;

                djbtime = time(NULL);
                pt = localtime(&djbtime);

                /* Syslog time: Apr 27 14:50:32  */
                snprintf(buffer, OS_MAXSTR, "%s %02d %02d:%02d:%02d %s %s: %s",
                         djb_month[pt->tm_mon],
                         pt->tm_mday,
                         pt->tm_hour,
                         pt->tm_min,
                         pt->tm_sec,
                         djb_host,
                         logff[pos].djb_program_name,
                         p);
            }
        }

        else {
            debug2("%s: DEBUG: Invalid DJB log: '%s'", ARGV0, str);
            continue;
        }

        debug2("%s: DEBUG: Reading DJB multilog message: '%s'", ARGV0, buffer);

        /* Send message to queue */
        if (drop_it == 0) {
            if (SendMSG(logr_queue, buffer, logff[pos].file, MYSQL_MQ) < 0) {
                merror(QUEUE_SEND, ARGV0);
                if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                    ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
                }
            }
        }

        continue;
    }

    return (NULL);
}

