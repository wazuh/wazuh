/* @(#) $Id$ */

/* Copyright (C) 2010 Trend Micro Inc.
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

typedef struct _runtime_data {
    OSRegex start, end;
} runtime_data;

int read_regex_init(int i)
{
    runtime_data *rd;

    os_calloc(1, sizeof(runtime_data), rd);

    if (!OSRegex_Compile(logff[i].start_regex, &(rd->start), 0)) {
        debug1("%s: Error in start regex. Giving up from this log source.", ARGV0);
        os_free(rd);
        return 0;
    }

    if (logff[i].end_regex && !OSRegex_Compile(logff[i].start_regex, &(rd->start), 0)) {
        debug1("%s: Error in end regex. Giving up from this log source.", ARGV0);
        OSRegex_FreePattern(&(rd->start));
        os_free(rd);
        return 0;
    }

    return 1;
}

/* Read multiline regex bounded logs. */
int read_regex(int pos, int drop_it)
{
    int __ms = 0, __bs = 0;
    int buffer_size = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    char buffer[OS_MAXSTR +1];

    fpos_t fp_pos;

    buffer[0] = '\0';
    buffer[OS_MAXSTR] = '\0';
    str[OS_MAXSTR]= '\0';

    int in_block = 0;

    runtime_data *rd = (runtime_data *)logff[pos].private_data;

    /* Getting initial file location */
    fgetpos(logff[pos].fp, &fp_pos);

    while(fgets(str, OS_MAXSTR - OS_LOG_HEADER, logff[pos].fp) != NULL)
    {

        /* Getting the last occurence of \n */
        if ((p = strrchr(str, '\n')) != NULL) 
        {
            *p = '\0';
        }
 
        /* If we didn't get the new line, because the
         * size is large, send what we got so far.
         */
        else if(strlen(str) >= (OS_MAXSTR - OS_LOG_HEADER - 2))
        {
            /* Message size > maximum allowed */
            __ms = 1;
        }
        else
        {
            /* Message not complete. Return. */
            debug1("%s: Message not complete. Trying again: '%s'", ARGV0,str);
            fsetpos(logff[pos].fp, &fp_pos);
            break;
        }    
        
        #ifdef WIN32
        if ((p = strrchr(str, '\r')) != NULL)
        {
            *p = '\0';
        }
        #endif
                      
        debug2("%s: DEBUG: Reading message: '%s'", ARGV0, str);

        // Check if starting regex matches...
        if (in_block == 0) {
            if (OSRegex_Execute(str, &(rd->start)))
                in_block = 1;
            continue;
        }

        /* Adding to buffer. */
        buffer_size = strlen(buffer);
        if(buffer[0] != '\0')
        {
            buffer[buffer_size] = ' ';
            buffer_size++;
        }

        if (buffer_size + strlen(str) > OS_MAXSTR - OS_LOG_HEADER - 2)
            __bs = 1;
        else
            strncpy(buffer + buffer_size, str, OS_MAXSTR - buffer_size -2);

        // If we don't have yet an end of the message and maximum size wasn't
        // exceeded then go to the next line.
        if (!__ms && !__bs &&
            (!(logff[pos].end_regex != NULL && OSRegex_Execute(str, &(rd->end))) ||
             !(logff[pos].end_regex == NULL && OSRegex_Execute(str, &(rd->start)))))
            continue;

        in_block = 0;

        /* Sending message to queue */
        if(drop_it == 0)
        {
            if(SendMSG(logr_queue, buffer, logff[pos].file,
                        LOCALFILE_MQ) < 0)
            {
                merror(QUEUE_SEND, ARGV0);
                if((logr_queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
                {
                    ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
                }
            }
        }

        buffer[0] = '\0';

        /* Incorrectly message size */
        if(__ms || __bs)
        {
            merror("%s: Large message size: '%s'", ARGV0, str);

            // The following isn't used if buffer size was exceeded. Upon return
            // to this function we'll anyway discard anything that isn't a start
            // marker.
            while(__ms && fgets(str, OS_MAXSTR - 2, logff[pos].fp) != NULL)
            {
                /* Getting the last occurence of \n */
                if ((p = strrchr(str, '\n')) != NULL)
                {
                    break;
                }
            }
        }
        
        fgetpos(logff[pos].fp, &fp_pos);
        continue;
    }

    return 0; 
}

/* EOF */

