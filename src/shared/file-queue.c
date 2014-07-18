/* @(#) $Id: ./src/shared/file-queue.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


/* File monitoring functions */

#include "shared.h"
#include "file-queue.h"

static void file_sleep();
static void GetFile_Queue(file_queue *fileq) __attribute__((nonnull));
static int Handle_Queue(file_queue *fileq, int flags) __attribute__((nonnull));
/* To translante between month (int) to month (char) */
static const char *(s_month[])={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug",
                   "Sep","Oct","Nov","Dec"};



/** void file_sleep();
 * file_sleep
 */
static void file_sleep()
{
    #ifndef WIN32
    struct timeval fp_timeout;

    fp_timeout.tv_sec = FQ_TIMEOUT;
    fp_timeout.tv_usec = 0;

    /* Waiting for the select timeout */
    select(0, NULL, NULL, NULL, &fp_timeout);

    #else
    /* Windows don't like select that way */
    Sleep((FQ_TIMEOUT + 2) * 1000);
    #endif

    return;
}



/** void GetFile_Queue(file_queue *fileq)
 * Get the file queue for that specific hour
 */
static void GetFile_Queue(file_queue *fileq)
{
    /* Creating the logfile name */
    fileq->file_name[0] = '\0';
    fileq->file_name[MAX_FQUEUE] = '\0';

    if(fileq->flags & CRALERT_FP_SET)
    {
        snprintf(fileq->file_name, MAX_FQUEUE,
                 "<stdin>");
    }
    else
    {
        snprintf(fileq->file_name, MAX_FQUEUE,
                                   "%s/%d/%s/ossec-alerts-%02d.log",
                                   ALERTS,
                                   fileq->year,
                                   fileq->mon,
                                   fileq->day);
    }
}



/** int Handle_Queue(file_queue *fileq)
 * Re Handle the file queue.
 */
static int Handle_Queue(file_queue *fileq, int flags)
{
    /* Closing if it is open */
    if(!(flags & CRALERT_FP_SET))
    {
        if(fileq->fp)
        {
            fclose(fileq->fp);
            fileq->fp = NULL;
        }


        /* We must be able to open the file, fseek and get the
         * time of change from it.
         */
        fileq->fp = fopen(fileq->file_name, "r");
        if(!fileq->fp)
        {
            /* Queue not available */
            return(0);
        }
    }


    /* Seeking the end of file */
    if(!(flags & CRALERT_READ_ALL))
    {
        if(fseek(fileq->fp, 0, SEEK_END) < 0)
        {
            merror(FSEEK_ERROR, __local_name, fileq->file_name);
            fclose(fileq->fp);
            fileq->fp = NULL;
            return(-1);
        }
    }


    /* File change time */
    if(fstat(fileno(fileq->fp), &fileq->f_status) < 0)
    {
        merror(FILE_ERROR, __local_name, fileq->file_name);
        fclose(fileq->fp);
        fileq->fp = NULL;
        return(-1);
    }

    fileq->last_change = fileq->f_status.st_mtime;

    return(1);
}



/** int Init_FileQueue(file_queue *fileq, struct tm *p, int flags)
 * Initiates the file monitoring.
 */
int Init_FileQueue(file_queue *fileq, const struct tm *p, int flags)
{
    /* Initializing file_queue fields. */
    if(!(flags & CRALERT_FP_SET))
    {
        fileq->fp = NULL;
    }
    fileq->last_change = 0;
    fileq->flags = 0;

    fileq->day = p->tm_mday;
    fileq->year = p->tm_year+1900;

    strncpy(fileq->mon, s_month[p->tm_mon], 4);
    memset(fileq->file_name, '\0',MAX_FQUEUE + 1);


    /* Setting the supplied flags */
    fileq->flags = flags;


    /* Getting latest file */
    GetFile_Queue(fileq);


    /* Always seek end when starting the queue */
    if(Handle_Queue(fileq, fileq->flags) < 0)
    {
        return(-1);
    }

    return(0);
}



/** int Read_FileMon(file_queue *fileq, struct tm *p, int timeout)
 * Reads from the monitored file.
 */
alert_data *Read_FileMon(file_queue *fileq, const struct tm *p, int timeout)
{
    int i = 0;
    alert_data *al_data;


    /* If the file queue is not available, try to access it */
    if(!fileq->fp)
    {
        if(Handle_Queue(fileq, 0) != 1)
        {
            file_sleep();
            return(NULL);
        }
    }


    /* Getting currently file */
    if(p->tm_mday != fileq->day)
    {
        /* If the day changes, we need to get all remaining alerts. */
        al_data = GetAlertData(fileq->flags, fileq->fp);
        if(!al_data)
        {
            fileq->day = p->tm_mday;
            fileq->year = p->tm_year+1900;
            strncpy(fileq->mon, s_month[p->tm_mon], 4);

            /* Getting latest file */
            GetFile_Queue(fileq);

            if(Handle_Queue(fileq, 0) != 1)
            {
                file_sleep();
                return(NULL);
            }
        }
        else
        {
            return(al_data);
        }
    }


    /* Try up to timeout times to get an event */
    while(i < timeout)
    {
        al_data = GetAlertData(fileq->flags, fileq->fp);
        if(al_data)
        {
            return(al_data);
        }

        i++;
        file_sleep();
    }


    /* Returning NULL if timeout expires. */
    return(NULL);
}


/* EOF */
