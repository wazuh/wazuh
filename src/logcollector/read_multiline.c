/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2010 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"


/* Read multiline logs */
void *read_multiline(logreader *lf, int *rc, int drop_it) {
    int __ms = 0;
    int __ms_reported = 0;
    int linesgot = 0;
    size_t buffer_size = 0;
    char str[OS_MAXSTR + 1];
    char buffer[OS_MAXSTR + 1];
    fpos_t fp_pos;
    int lines = 0;
    long offset;
    long rbytes;

    buffer[0] = '\0';
    buffer[OS_MAXSTR] = '\0';
    str[OS_MAXSTR] = '\0';
    *rc = 0;

    /* Get initial file location */
    fgetpos(lf->fp, &fp_pos);

    for (offset = w_ftell(lf->fp); fgets(str, OS_MAXSTR - OS_LOG_HEADER, lf->fp) != NULL && (!maximum_lines || lines < maximum_lines); offset += rbytes) {
        rbytes = w_ftell(lf->fp) - offset;
        lines++;
        linesgot++;

        /* Get the last occurrence of \n */
        if (str[rbytes - 1] == '\n') {
            str[rbytes - 1] = '\0';

            if ((long)strlen(str) != rbytes - 1)
            {
                mdebug2("Line in '%s' contains some zero-bytes (valid=%ld / total=%ld). Dropping line.", lf->file, (long)strlen(str), rbytes - 1);
                continue;
            }
        }

        /* If we didn't get the new line, because the
         * size is large, send what we got so far.
         */
        else if (rbytes == OS_MAXSTR - OS_LOG_HEADER - 1) {
            /* Message size > maximum allowed */
            __ms = 1;
        } else if (feof(lf->fp)) {
            /* Message not complete. Return. */
            mdebug2("Message not complete from '%s'. Trying again: '%.*s'%s", lf->file, sample_log_length, str, rbytes > sample_log_length ? "..." : "");
            fsetpos(lf->fp, &fp_pos);
            break;
        }

#ifdef WIN32
        char * p;

        if ((p = strrchr(str, '\r')) != NULL) {
            *p = '\0';
        }
#endif


        /* Add to buffer */
        buffer_size = strlen(buffer);
        if (buffer[0] != '\0') {
            buffer[buffer_size] = ' ';
            buffer_size++;
        }

        strncpy(buffer + buffer_size, str, OS_MAXSTR - buffer_size - 2);

        if (linesgot < lf->linecount) {
            continue;
        }
        linesgot = 0;

        /* Send message to queue */
        if (drop_it == 0) {
            mdebug2("Reading message: '%.*s'%s", sample_log_length, buffer, strlen(buffer) > (size_t)sample_log_length ? "..." : "");
            w_msg_hash_queues_push(buffer, lf->file, strlen(buffer) + 1, lf->log_target, LOCALFILE_MQ);
        }

        buffer[0] = '\0';


        /* Incorrect message size */
        if (__ms) {
            if (!__ms_reported) {
                merror("Large message size from file '%s' (length = %ld): '%.*s'...", lf->file, rbytes, sample_log_length, str);
                __ms_reported = 1;
            } else {
                mdebug2("Large message size from file '%s' (length = %ld): '%.*s'...", lf->file, rbytes, sample_log_length, str);
            }

            for (offset += rbytes; fgets(str, OS_MAXSTR - 2, lf->fp) != NULL; offset += rbytes) {
                rbytes = w_ftell(lf->fp) - offset;

                /* Get the last occurrence of \n */
                if (str[rbytes - 1] == '\n') {
                    break;
                }
            }
            __ms = 0;
        }

        fgetpos(lf->fp, &fp_pos);
        continue;
    }

    mdebug2("Read %d lines from %s", lines, lf->file);
    return (NULL);
}
