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
#include "logcollector.h"


/* Read snort_full files */
void *read_snortfull(logreader *lf, int *rc, int drop_it) {
    int f_msg_size = OS_MAXSTR;
    const char *one = "one";
    const char *two = "two";
    const char *p = NULL;
    char *q;
    char str[OS_MAXSTR + 1];
    char f_msg[OS_MAXSTR + 1];
    int lines = 0;

    *rc = 0;
    str[OS_MAXSTR] = '\0';
    f_msg[OS_MAXSTR] = '\0';

    while (fgets(str, OS_MAXSTR, lf->fp) != NULL && (!maximum_lines || lines < maximum_lines)) {

        lines++;
        /* Remove \n at the end of the string */
        if ((q = strrchr(str, '\n')) != NULL) {
            *q = '\0';
        } else {
            goto file_error;
        }

        /* First part of the message */
        if (p == NULL) {
            if (strncmp(str, "[**] [", 6) == 0) {
                strncpy(f_msg, str, OS_MAXSTR);
                f_msg_size -= strlen(str) + 1;
                p = one;
            }
        } else {
            if (p == one) {
                /* Second line has the [Classification: */
                if (strncmp(str, "[Classification: ", 16) == 0) {
                    strncat(f_msg, str, f_msg_size);
                    f_msg_size -= strlen(str) + 1;
                    p = two;
                } else if (strncmp(str, "[Priority: ", 10) == 0) {
                    strncat(f_msg, "[Classification: Preprocessor] "
                            "[Priority: 3] ", f_msg_size);
                    f_msg_size -= strlen(str) + 1;
                    p = two;
                }

                /* If it is a preprocessor message, it will not have
                 * the classification.
                 */
                else if ((str[2] == '/') && (str[5] == '-') && (q = strchr(str, ' '))) {
                    strncat(f_msg, "[Classification: Preprocessor] "
                            "[Priority: 3] ", f_msg_size);
                    strncat(f_msg, ++q, f_msg_size - 40);

                    /* Clean for next event */
                    p = NULL;

                    /* Send the message */
                    if (drop_it == 0) {
                        w_msg_hash_queues_push(str, lf->file, strlen(f_msg), lf->log_target, LOCALFILE_MQ);
                    }

                    f_msg[0] = '\0';
                    f_msg_size = OS_MAXSTR;
                    str[0] = '\0';
                } else {
                    goto file_error;
                }
            } else if (p == two) {
                /* Third line has the 01/13-15 (date) */
                if ((str[2] == '/') && (str[5] == '-') && (q = strchr(str, ' '))) {
                    strncat(f_msg, ++q, f_msg_size);
                    f_msg_size -= strlen(q) + 1;
                    p = NULL;

                    /* Send the message */
                    if (drop_it == 0) {
                        w_msg_hash_queues_push(str, lf->file, strlen(str) + 1, lf->log_target, LOCALFILE_MQ);
                    }

                    f_msg[0] = '\0';
                    f_msg_size = OS_MAXSTR;
                    str[0] = '\0';
                } else {
                    goto file_error;
                }

            }
        }

        continue;

file_error:

        merror("Bad formated snort full file.");
        *rc = -1;
        return (NULL);

    }

    mdebug2("Read %d lines from %s", lines, lf->file);
    return (NULL);
}
