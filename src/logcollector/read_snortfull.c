/* @(#) $Id: ./src/logcollector/read_snortfull.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* v0.4 (2006/01/13): Fixing to read snort-full logs correctly.
 *
 */


#include "shared.h"
#include "logcollector.h"


/* Read snort_full files */
void *read_snortfull(int pos, int *rc, int drop_it)
{
    int f_msg_size = OS_MAXSTR;

    char *one = "one";
    char *two = "two";

    char *p = NULL;
    char *q;
    char str[OS_MAXSTR + 1];
    char f_msg[OS_MAXSTR +1];

    *rc = 0;
    str[OS_MAXSTR]='\0';
    f_msg[OS_MAXSTR] = '\0';

    while(fgets(str, OS_MAXSTR, logff[pos].fp) != NULL)
    {
        /* Removing \n at the end of the string */
        if ((q = strrchr(str, '\n')) != NULL)
        {
            *q = '\0';
        }
        else
        {
            goto file_error;
        }

        /* First part of the message */
        if(p == NULL)
        {
            if(strncmp(str, "[**] [", 6) == 0)
            {
                strncpy(f_msg, str, OS_MAXSTR);
                f_msg_size -= strlen(str)+1;
                p = one;
            }
        }
        else
        {
            if(p == one)
            {
                /* Second line has the [Classification: */
                if(strncmp(str, "[Classification: ", 16) == 0)
                {
                    strncat(f_msg, str, f_msg_size);
                    f_msg_size -= strlen(str)+1;
                    p = two;
                }
                else if(strncmp(str, "[Priority: ", 10) == 0)
                {
                    strncat(f_msg, "[Classification: Preprocessor] "
                                   "[Priority: 3] ", f_msg_size);
                    f_msg_size -= strlen(str)+1;
                    p = two;
                }

                /* If it is a preprocessor message, it will not have
                 * the classification.
                 */
                else if((str[2] == '/')&&(str[5] == '-')&&(q = strchr(str,' ')))
                {
                    strncat(f_msg, "[Classification: Preprocessor] "
                                   "[Priority: 3] ", f_msg_size);
                    strncat(f_msg, ++q, f_msg_size -40);

                    /* Cleaning for next event */
                    p = NULL;

                    /* Sending the message */
                    if(drop_it == 0)
                    {
                        if(SendMSG(logr_queue,f_msg, logff[pos].file,
                                    LOCALFILE_MQ) < 0)
                        {
                            merror(QUEUE_SEND, ARGV0);
                            if((logr_queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
                            {
                                ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
                            }
                        }
                    }

                    f_msg[0] = '\0';
                    f_msg_size = OS_MAXSTR;
                    str[0] = '\0';
                }
                else
                {
                    goto file_error;
                }
            }
            else if(p == two)
            {
                /* Third line has the 01/13-15 (date) */
                if((str[2] == '/')&&(str[5] == '-')&&(q = strchr(str,' ')))
                {
                    strncat(f_msg, ++q, f_msg_size);
                    f_msg_size -= strlen(q)+1;
                    p = NULL;

                    /* Sending the message */
                    if(drop_it == 0)
                    {
                        if(SendMSG(logr_queue,f_msg, logff[pos].file,
                                    LOCALFILE_MQ) < 0)
                        {
                            merror(QUEUE_SEND, ARGV0);
                            if((logr_queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
                            {
                                ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
                            }
                        }
                    }

                    f_msg[0] = '\0';
                    f_msg_size = OS_MAXSTR;
                    str[0] = '\0';
                }
                else
                {
                    goto file_error;
                }

            }
        }

        continue;

        file_error:

        merror("%s: Bad formatted snort full file.", ARGV0);
        *rc = -1;
        return(NULL);

    }


    return(NULL);
}

/* EOF */
