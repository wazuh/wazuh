/*      $OSSEC, mq_op.c, v0.2, 2005/02/15, Daniel B. Cid$      */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "os_net/os_net.h"
int __mq_rcode;


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
            merror(QUEUE_ERROR, ARGV0, path);
            sleep(15);
            if(File_DateofChange(path) < 0)
            {
                sleep(15);
                return(-1);
            }
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
                       char *logroup, char loc)
{
    char tmpstr[OS_MAXSTR+1];


    tmpstr[OS_MAXSTR] = '\0';

    if(loc == SECURE_MQ)
    {

        loc = message[0];
        message++;

        if(message[0] != ':')
        {
            merror("%s: Error deserializing message",ARGV0);
            return(0);
        }
        
        message++; /* Pointing now to the location */
        
        snprintf(tmpstr,OS_MAXSTR,"%c:%s->%s",loc, locmsg, message);
    }
    else
        snprintf(tmpstr,OS_MAXSTR,"%c:%s:%s:%s",loc,locmsg,logroup,message);


    /* queue not available */
    if(queue < 0)
        return(-1);

        
    /* We attempt 5 times to send the message if
     * the receiver socket is busy.
     * After the first error, we wait 1 second.
     * After the second error, we wait more 1 seconds.
     * After the third error, we wait 2 seconds.
     * After the fourth error, we wait 2 seconds.
     * If we failed again, the message is not going
     * to be delivered and an error is sent back.
     */
    if((__mq_rcode = OS_SendUnix(queue, tmpstr,0)) < 0)
    {
        /* Error on the socket */
        if(__mq_rcode == OS_SOCKTERR)
        {
            return(-1);
        }
        
        /* Unable to send. Socket busy */
        sleep(1);
        if(OS_SendUnix(queue, tmpstr,0) < 0)
        {
            /* When the socket is to busy, we may get some
             * error here. Just sleep 1 second and try
             * again.
             */
            sleep(1);
            if(OS_SendUnix(queue, tmpstr,0) < 0)
            {
                sleep(2);
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
                        queue = -1; 
                        return(-1);
                    }
                }
            }
        }
    }

    return(0);
}

/* EOF */
