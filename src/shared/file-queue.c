/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* File monitoring functions */

#include "shared.h"
#include "file-queue.h"

static void file_sleep(void);
static void GetFile_Queue(file_queue *fileq) __attribute__((nonnull));
static int Handle_Queue(file_queue *fileq, int flags) __attribute__((nonnull));
/* To translante between month (int) to month (char) */
static const char *(s_month[]) = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
                                 };


static void file_sleep()
{
#ifndef WIN32
    struct timeval fp_timeout;

    fp_timeout.tv_sec = FQ_TIMEOUT;
    fp_timeout.tv_usec = 0;

    /* Wait for the select timeout */
    select(0, NULL, NULL, NULL, &fp_timeout);

#else
    /* Windows does not like select that way */
    Sleep((FQ_TIMEOUT + 2) * 1000);
#endif

    return;
}

/* Get the file queue for that specific hour */
static void GetFile_Queue(file_queue *fileq)
{
    /* Create the logfile name */
    fileq->file_name[0] = '\0';
    fileq->file_name[MAX_FQUEUE] = '\0';

    if (fileq->flags & CRALERT_FP_SET) {
        snprintf(fileq->file_name, MAX_FQUEUE,
                 "<stdin>");
    } else {
        snprintf(fileq->file_name, MAX_FQUEUE,
                 "%s/%d/%s/ossec-alerts-%02d.log",
                 ALERTS,
                 fileq->year,
                 fileq->mon,
                 fileq->day);
    }
}

/* Re Handle the file queue */
static int Handle_Queue(file_queue *fileq, int flags)
{
    /* Close if it is open */
    if (!(flags & CRALERT_FP_SET)) {
        if (fileq->fp) {
            fclose(fileq->fp);
            fileq->fp = NULL;
        }

        /* We must be able to open the file, fseek and get the
         * time of change from it.
         */
        fileq->fp = fopen(fileq->file_name, "r");
        if (!fileq->fp) {
            /* Queue not available */
            return (0);
        }
    }

    /* Seek to the end of the file */
    if (!(flags & CRALERT_READ_ALL)) {
        if (fseek(fileq->fp, 0, SEEK_END) < 0) {
            merror(FSEEK_ERROR, __local_name, fileq->file_name, errno, strerror(errno));
            fclose(fileq->fp);
            fileq->fp = NULL;
            return (-1);
        }
    }

    /* File change time */
    if (fstat(fileno(fileq->fp), &fileq->f_status) < 0) {
        merror(FSTAT_ERROR, __local_name, fileq->file_name, errno, strerror(errno));
        fclose(fileq->fp);
        fileq->fp = NULL;
        return (-1);
    }

    fileq->last_change = fileq->f_status.st_mtime;

    return (1);
}

/* Initiates the file monitoring */
int Init_FileQueue(file_queue *fileq, const struct tm *p, int flags)
{
    /* Initialize file_queue fields */
    if (!(flags & CRALERT_FP_SET)) {
        fileq->fp = NULL;
    }
    fileq->last_change = 0;
    fileq->flags = 0;

    fileq->day = p->tm_mday;
    fileq->year = p->tm_year + 1900;

    strncpy(fileq->mon, s_month[p->tm_mon], 3);
    memset(fileq->file_name, '\0', MAX_FQUEUE + 1);

    /* Set the supplied flags */
    fileq->flags = flags;

    /* Get latest file */
    GetFile_Queue(fileq);

    /* Always seek to the end when starting the queue */
    if (Handle_Queue(fileq, fileq->flags) < 0) {
        return (-1);
    }

    return (0);
}

/* Reads from the monitored file */
alert_data *Read_FileMon(file_queue *fileq, const struct tm *p, unsigned int timeout)
{
    unsigned int i = 0;
    alert_data *al_data;

    /* If the file queue is not available, try to access it */
    if (!fileq->fp) {
        if (Handle_Queue(fileq, 0) != 1) {
            file_sleep();
            return (NULL);
        }
    }

    /* Get current file */
    if (p->tm_mday != fileq->day) {
        /* If the day changes, get all remaining alerts */
        al_data = GetAlertData(fileq->flags, fileq->fp);
        if (!al_data) {
            fileq->day = p->tm_mday;
            fileq->year = p->tm_year + 1900;
            strncpy(fileq->mon, s_month[p->tm_mon], 3);

            /* Get latest file */
            GetFile_Queue(fileq);

            if (Handle_Queue(fileq, 0) != 1) {
                file_sleep();
                return (NULL);
            }
        } else {
            return (al_data);
        }
    }

    /* Try up to timeout times to get an event */
    while (i < timeout) {
        al_data = GetAlertData(fileq->flags, fileq->fp);
        if (al_data) {
            return (al_data);
        }

        i++;
        file_sleep();
    }

    /* Return NULL if timeout expires */
    return (NULL);
}
