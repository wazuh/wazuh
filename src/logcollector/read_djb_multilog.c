/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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


/* To translate between month (int) to month (char) */
static const char *(djb_month[]) = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
                                   };
static char djb_host[512 + 1];


/* Initialize multilog */
int init_djbmultilog(logreader *lf) {
    char *djbp_name = NULL;
    char *tmp_str = NULL;

    lf->djb_program_name = NULL;

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
    tmp_str = strrchr(lf->file, '/');
    if (!tmp_str) {
        return (0);
    }

    /* Must end with /current and must not be in the beginning of the string */
    if ((strcmp(tmp_str, "/current") != 0) || (tmp_str == lf->file)) {
        return (0);
    }

    tmp_str[0] = '\0';

    /* Get final name */
    djbp_name = strrchr(lf->file, '/');
    if (djbp_name == lf->file) {
        tmp_str[0] = '/';
        return (0);
    }

    os_strdup(djbp_name + 1, lf->djb_program_name);
    tmp_str[0] = '/';

    minfo("Using program name '%s' for DJB multilog file: '%s'.",
            lf->djb_program_name, lf->file);

    return (1);
}

void *read_djbmultilog(logreader *lf, int *rc, int drop_it) {
    size_t str_len = 0;
    int need_clear = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    char buffer[OS_MAXSTR + 1];
    int lines = 0;
    str[OS_MAXSTR] = '\0';
    *rc = 0;

    /* Must have a valid program name */
    if (!lf->djb_program_name) {
        return (NULL);
    }

    /* Get new entry */
    while (fgets(str, OS_MAXSTR - OS_LOG_HEADER, lf->fp) != NULL && (!maximum_lines || lines < maximum_lines)) {

        lines++;
        /* Get buffer size */
        str_len = strlen(str);

        /* Getting the last occurrence of \n */
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
                         lf->djb_program_name,
                         p);
            }
        }

        else {
            mdebug2("Invalid DJB log: '%s'", str);
            continue;
        }

        mdebug2("Reading DJB multilog message: '%s'", buffer);

        /* Send message to queue */
        if (drop_it == 0) {
            w_msg_hash_queues_push(buffer, lf->file, strlen(buffer) + 1, lf->log_target, MYSQL_MQ);
        }

        continue;
    }

    mdebug2("Read %d lines from %s", lines, lf->file);
    return (NULL);
}
