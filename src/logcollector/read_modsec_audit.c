/* @(#) $Id$ */

/* Copyright (C) 2012 Trend Micro Inc.
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



/* Read multiline logs. */
int read_modsec_audit(int pos, int drop_it)
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

        // See if the line has the following form: --62a78a12-A--
        // If so, than it is a start marker.
        if (in_block == 0) {

            if (str[0] == '-' && str[1] == '-' && isxdigit(str[2])
                    && isxdigit(str[3]) && isxdigit(str[4])
                    && isxdigit(str[5]) && isxdigit(str[6])
                    && isxdigit(str[7]) && isxdigit(str[8])
                    && isxdigit(str[9]) && str[10] == '-'
                    && str[11] == 'A' && str[12] == '-'
                    && str[13] == '-' && str[14] == '\n')
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
            (str[0] != '-' || str[1] != '-' || !isxdigit(str[2])
                    || !isxdigit(str[3]) || !isxdigit(str[4])
                    || !isxdigit(str[5]) || !isxdigit(str[6])
                    || !isxdigit(str[7]) || !isxdigit(str[8])
                    || !isxdigit(str[9]) || str[10] != '-'
                    || str[11] != 'Z' || str[12] != '-'
                    || str[13] != '-' || str[14] != '\n'))
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
