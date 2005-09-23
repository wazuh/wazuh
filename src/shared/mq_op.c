/*      $OSSEC, mq_op.c, v0.2, 2005/02/15, Daniel B. Cid$      */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "headers/defs.h"
#include "headers/mq_op.h"
#include "headers/file_op.h"
#include "os_net/os_net.h"
#include "os_regex/os_regex.h"

/* StartMQ v0.2, 2004/07/30
 * Start the Message Queue. type: WRITE||READ
 */
int StartMQ(char * path, short int type)
{
    if(type == READ)
        return(OS_BindUnixDomain(path,0660));
    else
    {
        if(File_DateofChange(path) < 0)
        {
            return(-1);
        }

        return(OS_ConnectUnixDomain(path));
    }
}

/* FinishMQ v0.2, 2004/07/29
 * Finish the Messahe queue.
 */
int FinishMQ()
{
    return(0);
}


/* SendMSG v0.1, 2005/02/15
 * Send a message to the queue.
 */
int SendMSG(int queue, char *message, char *locmsg,
                       char *logroup, unsigned short int loc)
{
    char **pieces = NULL;
    char tmpstr[OS_MAXSTR+1];

    /* This may be a big loss in here... */
    memset(tmpstr,'\0',OS_MAXSTR+1);

    if(loc == SECURE_MQ)
    {
        /* Breaking in six pieces */
        pieces = OS_StrBreak(':', message, 7);
        if(pieces == NULL)
            return(-1);

        /* If pieces[6] is not null, pieces[0]-[5] will not be */
        else if(pieces[6] == NULL)
        {
            if(pieces[0])
                free(pieces[0]);
            
            if(pieces[1])
                free(pieces[1]);
            
            if(pieces[2])
                free(pieces[2]);
            
            if(pieces[3])
                free(pieces[3]);
            
            if(pieces[4])
                free(pieces[4]);
            
            if(pieces[5])
                free(pieces[5]);
                
            free(pieces);                    
            return(-1);
        }   
        
        snprintf(tmpstr,OS_MAXSTR,"%s:%s->%s:%s:%s",pieces[3],locmsg,
                pieces[4],pieces[5],pieces[6]);
        
        free(pieces[0]);
        free(pieces[1]);
        free(pieces[2]);
        free(pieces[3]);
        free(pieces[4]);
        free(pieces[5]);
        free(pieces[6]);
        free(pieces);
    }
    else
        snprintf(tmpstr,OS_MAXSTR,"%d:%s:%s:%s",loc,locmsg,logroup,message);

    /* We attempt 5 times to send the message.
     * After the first error, we wait 0.001 seconds.
     * After the second error, we wait 0.01 seconds.
     * After the third error, we wait 1 second.
     * After the fourth error, we wait 2 seconds.
     * If we failed again, the message is not going
     * to be delivered and an error is sent back.
     */
    if(OS_SendUnix(queue, tmpstr,0) < 0)
    {
        /* Impossible to send. Trying again.. */
        usleep(10000);
        if(OS_SendUnix(queue, tmpstr,0) < 0)
        {
            /* When the socket is to busy, we may get some
             * error here. Just sleep 0.01 seconds and try
             * again.
             */
            usleep(100000);
            if(OS_SendUnix(queue, tmpstr,0) < 0)
            {
                sleep(1);
                if(OS_SendUnix(queue, tmpstr,0) < 0)
                {
                    sleep(2);
                    if(OS_SendUnix(queue, tmpstr,0) < 0)
                    {
                        /* Message is going to be lost
                         * if the application does not care
                         * about checking the error 
                         */ 
                        close(queue); 
                        return(-1);
                    }
                }
            }
        }
    }

    return(0);
}

/* EOF */
