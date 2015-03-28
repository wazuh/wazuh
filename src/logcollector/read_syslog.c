/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Read the syslog */

#include "shared.h"
#include "logcollector.h"


/* Read syslog files */
void *read_syslog(int pos, int *rc, int drop_it)
{
    int __ms = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    fpos_t fp_pos;

    str[OS_MAXSTR] = '\0';
    *rc = 0;

    /* Get initial file location */
    fgetpos(logff[pos].fp, &fp_pos);

    while (fgets(str, OS_MAXSTR - OS_LOG_HEADER, logff[pos].fp) != NULL) {
        /* Get the last occurence of \n */
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
            debug1("%s: Message not complete. Trying again: '%s'", ARGV0, str);
            fsetpos(logff[pos].fp, &fp_pos);
            break;
        }

#ifdef WIN32
        if ((p = strrchr(str, '\r')) != NULL) {
            *p = '\0';
        }

        /* Look for empty string (only on Windows) */
        if (strlen(str) <= 2) {
            fgetpos(logff[pos].fp, &fp_pos);
            continue;
        }

        /* Windows can have comment on their logs */
        if (str[0] == '#') {
            fgetpos(logff[pos].fp, &fp_pos);
            continue;
        }
#endif

        debug2("%s: DEBUG: Reading syslog message: '%s'", ARGV0, str);

        /* Send message to queue */
        if (drop_it == 0) {
            if (SendMSG(logr_queue, str, logff[pos].file,
                        LOCALFILE_MQ) < 0) {
                merror(QUEUE_SEND, ARGV0);
                if ((logr_queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                    ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
                }
            }
        }

        /* Incorrect message size */
        if (__ms) {
            // strlen(str) >= (OS_MAXSTR - OS_LOG_HEADER - 2)
            // truncate str before logging to ossec.log
#define OUTSIZE 4096
            char buf[OUTSIZE + 1];
            buf[OUTSIZE] = '\0';
            snprintf(buf, OUTSIZE, "%s", str);
            merror("%s: Large message size(length=%d): '%s...'", ARGV0, (int)strlen(str), buf);
            while (fgets(str, OS_MAXSTR - 2, logff[pos].fp) != NULL) {
                /* Get the last occurence of \n */
                if (strrchr(str, '\n') != NULL) {
                    break;
                }
            }
            __ms = 0;
        }

        fgetpos(logff[pos].fp, &fp_pos);
        continue;
    }

    return (NULL);
}

