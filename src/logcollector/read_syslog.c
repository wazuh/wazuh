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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "headers/defs.h"
#include "headers/debug_op.h"
#include "headers/mq_op.h"
#include "logcollector.h"



/* v0.3 (2005/08/24): Using fgets instead of fgetc
 * v0.2 (2005/04/04)
 */

/* Read syslog files/snort fast/apache files */
void *read_syslog(int pos, int *rc)
{
    char *p;
    char str[OS_MAXSTR+1];

    str[OS_MAXSTR]='\0';

    while(fgets(str, OS_MAXSTR, logr[pos].fp) != NULL)
    {

        if ((p = strchr(str, '\n')) != NULL) 
        {
            *p = '\0';
        }
                      

        #ifdef DEBUG
        verbose("%s: Read message: '%s'",ARGV0,str);
        #endif

        if(SendMSG(logr_queue,str,logr[pos].file,
                    logr[pos].logformat, LOCALFILE_MQ) < 0)
        {
            merror(QUEUE_SEND, ARGV0);
            if((logr_queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
            {
                ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
            }
        }

        continue;
    }

    /* We are checking for errors in the main function */
    *rc = 0;
    return(NULL); 
}

/* EOF */
