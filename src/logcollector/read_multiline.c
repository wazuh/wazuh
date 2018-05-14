/* Copyright (C) 2010 Trend Micro Inc.
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
    int linecount;
    int linesgot = 0;
    size_t buffer_size = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    char buffer[OS_MAXSTR + 1];
    fpos_t fp_pos;
    int lines = 0;

    buffer[0] = '\0';
    buffer[OS_MAXSTR] = '\0';
    str[OS_MAXSTR] = '\0';
    *rc = 0;

    linecount = atoi(lf->logformat);

    /* Get initial file location */
    fgetpos(lf->fp, &fp_pos);

    while (fgets(str, OS_MAXSTR - OS_LOG_HEADER, lf->fp) != NULL && (!maximum_lines || lines < maximum_lines)) {

        lines++;
        linesgot++;

        /* Get the last occurrence of \n */
        if ((p = strrchr(str, '\n')) != NULL) {
            *p = '\0';
        }

        /* If we didn't get the new line, because the
         * size is large, send what we got so far.
         */
        else if (strlen(str) >= (OS_MAXSTR - OS_LOG_HEADER - 2)) {
            /* Message size > maximum allowed */
            __ms = 1;
        } else {
            /* Message not complete. Return. */
            mdebug1("Message not complete. Trying again: '%s'", str);
            fsetpos(lf->fp, &fp_pos);
            break;
        }

#ifdef WIN32
        if ((p = strrchr(str, '\r')) != NULL) {
            *p = '\0';
        }
#endif

        mdebug2("Reading message: '%s'", str);

        /* Add to buffer */
        buffer_size = strlen(buffer);
        if (buffer[0] != '\0') {
            buffer[buffer_size] = ' ';
            buffer_size++;
        }

        strncpy(buffer + buffer_size, str, OS_MAXSTR - buffer_size - 2);

        if (linesgot < linecount) {
            continue;
        }

        /* Send message to queue */
        if (drop_it == 0) {
            if (SendMSGtoSCK(logr_queue, buffer, lf->file,
                        LOCALFILE_MQ, lf->target_socket, lf->outformat) < 0) {
                merror(QUEUE_SEND);
                if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                    merror_exit(QUEUE_FATAL, DEFAULTQPATH);
                }
            }
        }

        buffer[0] = '\0';


        /* Incorrect message size */
        if (__ms) {
            merror("Large message size: '%s'", str);
            while (fgets(str, OS_MAXSTR - 2, lf->fp) != NULL) {
                /* Get the last occurrence of \n */
                if ((p = strrchr(str, '\n')) != NULL) {
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
