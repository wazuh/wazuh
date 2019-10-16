/* Copyright (C) 2019, Semper Victus LLC
 * Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Read indentend multi line logs */

#include "shared.h"
#include "logcollector.h"


/* Read multi line indented log files */
void *read_multiline_indented(logreader *lf, int *rc, int drop_it) {
    size_t str_len = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    char buffer[OS_MAXSTR + 1];
    int lines = 0;

    /* Zero buffer and str */
    buffer[0] = '\0';
    buffer[OS_MAXSTR] = '\0';
    str[OS_MAXSTR] = '\0';
    *rc = 0;

    /* Get new entry */
    while (fgets(str, OS_MAXSTR - OS_LOG_HEADER, lf->fp) != NULL && (!maximum_lines || lines < maximum_lines)) {

        lines++;
        /* Get buffer size */
        str_len = strlen(str);

        /* Check str_len size. Very useless, but just to make sure.. */
        if (str_len >= sizeof(buffer) - 2) {
            str_len = sizeof(buffer) - 10;
        }

        /* Get the last occurrence of \n */
        if ((p = strrchr(str, '\n')) != NULL) {
            *p = '\0';
        }

#ifdef WIN32
        if ((p = strrchr(str, '\r')) != NULL) {
            *p = '\0';
        }
#endif
        /* Look for empty string */
        if ((str_len <= 1) || (str[0] == '\r')) {
            /* Send existing data if any in buffer */
            if (buffer[0] != '\0') {
                w_msg_hash_queues_push(buffer, lf->file, strlen(buffer) + 1, lf->log_target, LOCALFILE_MQ);
                buffer[0] = '\0';
                lines = 0;
            }
            continue;
        }

        /* Look for lines starting with indents */
        if ((str_len > 2) && (buffer[0] != '\0') &&
                 ((str[0] == ' ') || (str[0] == '\t'))) {
            /* Size of the buffer */
            size_t buffer_len = strlen(buffer);

            p = str + 1;

            /* Remove extra spaces and tabs */
            while (*p == ' ' || *p == '\t') {
                p++;
            }

            /* Add additional message to the saved buffer */
            if (sizeof(buffer) - buffer_len > str_len + 256) {
                /* Here we make sure that the size of the buffer
                 * minus what was used (strlen) is greater than
                 * the length of the received message.
                 */
                buffer[buffer_len] = ' ';
                buffer[buffer_len + 1] = '\0';
                strncat(buffer, str, str_len + 3);
            }
        /* Look for lines not starting with indents */
        } else if ((str[0] != ' ') || (str[0] != '\t')) {
            /* Flush previous messages */
            if (buffer[0] != '\0') {
                w_msg_hash_queues_push(buffer, lf->file, strlen(buffer) + 1, lf->log_target, LOCALFILE_MQ);
                buffer[0] = '\0';
                lines = 0;
            }
            strncpy(buffer, str, str_len + 2);
            continue;
       /* Error handling for buffer[0] being '\0' when indents are present */
       } else {
           // messages or retries
       }

    }

    /* Send whatever is stored */
    if (buffer[0] != '\0') {
        w_msg_hash_queues_push(buffer, lf->file, strlen(buffer) + 1, lf->log_target, LOCALFILE_MQ);
    }

    mdebug2("Read %d lines from %s", lines, lf->file);
    return (NULL);
}
