/*   $OSSEC, read_snortfull.c, v0.4, 2006/01/13, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005,2006 Daniel B. Cid <dcid@ossec.net>
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
void *read_snortfull(int pos, int *rc)
{
    int __rc = 0;
    int f_msg_size = OS_MAXSTR;
    
    char *one = "one";
    char *two = "two";
    
    char *p = NULL;
    char *q;
    char str[OS_MAXSTR + 1];
    char f_msg[OS_MAXSTR +1];
    
    str[OS_MAXSTR]='\0';
    f_msg[OS_MAXSTR] = '\0';

    while(fgets(str, OS_MAXSTR, logr[pos].fp) != NULL)
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
                    if(SendMSG(logr_queue,f_msg, logr[pos].file,
                               LOCALFILE_MQ) < 0)
                    {
                        merror(QUEUE_SEND, ARGV0);
                        if((logr_queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
                        {
                            ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
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
                    if(SendMSG(logr_queue,f_msg, logr[pos].file,
                               LOCALFILE_MQ) < 0)
                    {
                        merror(QUEUE_SEND, ARGV0);
                        if((logr_queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
                        {
                            ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
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

        __rc = 1;
        continue;

        file_error:

        merror("%s: Bad formated snort full file", ARGV0);
        *rc = -1;
        return(NULL);

    }

    *rc = __rc;

    return(NULL);
}

/* EOF */
