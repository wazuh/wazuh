/*   $OSSEC, read_syslog.c, v0.3, 2005/08/24, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
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



/* v0.3 (2005/08/24): Using fgets instead of fgetc
 * v0.2 (2005/04/04)
 */

/* Read syslog files/snort fast/apache files */
void *read_syslog(int pos, int *rc)
{
    int __rc = 0;
    char *p;
    char str[OS_MAXSTR+1];

    str[OS_MAXSTR]='\0';

    while(fgets(str, OS_MAXSTR, logff[pos].fp) != NULL)
    {
        /* Getting the last occurence of \n */
        if ((p = strrchr(str, '\n')) != NULL) 
        {
            *p = '\0';
        }
                      
        
        /* Sending message to queue */
        if(SendMSG(logr_queue,str,logff[pos].file,
                   LOCALFILE_MQ) < 0)
        {
            merror(QUEUE_SEND, ARGV0);
            if((logr_queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
            {
                ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
            }

        }

        __rc++;
        continue;
    }

    /* Nothing was available to be read */
    if(__rc == 0)
    {
        *rc = 1;
    }
    else
    {
        *rc = 0;
    }
    return(NULL); 
}

/* EOF */
