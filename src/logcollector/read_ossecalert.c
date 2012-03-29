/* @(#) $Id$ */

/* Copyright (C) 2012 Daniel B. Cid (http://dcid.me)
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Read the syslog */


#include "shared.h"
#include "headers/read-alert.h"
#include "logcollector.h"



/* Read syslog files/snort fast/apache files */
void *read_ossecalert(int pos, int *rc, int drop_it)
{
    alert_data *al_data;
    char user_msg[256];
    char srcip_msg[256];
    
    char syslog_msg[OS_SIZE_2048 +1];

    al_data = GetAlertData(0, logff[pos].fp);
    if(!al_data)
    {
        return(NULL);
    }


    memset(syslog_msg, '\0', OS_SIZE_2048 +1);



    /* Adding source ip. */
    if(!al_data->srcip || 
       ((al_data->srcip[0] == '(') &&
        (al_data->srcip[1] == 'n') &&
        (al_data->srcip[2] == 'o')))
    {
        srcip_msg[0] = '\0';
    }
    else
    {
        snprintf(srcip_msg, 255, " srcip: %s;", al_data->srcip);
    }


    /* Adding username. */
    if(!al_data->user || 
       ((al_data->user[0] == '(') &&
        (al_data->user[1] == 'n') &&
        (al_data->user[2] == 'o')))
    {
        user_msg[0] = '\0';
    }
    else
    {
        snprintf(user_msg, 255, " user: %s;", al_data->user);
    }


    /* Building syslog message. */
    snprintf(syslog_msg, OS_SIZE_2048,
          	"ossec: Alert Level: %d; Rule: %d - %s; "
               	"Location: %s;%s%s  %s",
               	al_data->level, al_data->rule, al_data->comment,
               	al_data->location, 
               	srcip_msg,
               	user_msg,
               	al_data->log[0]);


    /* Clearing the memory */
    FreeAlertData(al_data);


        
    /* Sending message to queue */
    if(drop_it == 0)
    {
        if(SendMSG(logr_queue,syslog_msg,logff[pos].file, LOCALFILE_MQ) < 0)
        {
            merror(QUEUE_SEND, ARGV0);
            if((logr_queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
            {
                ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
            }
        }
    }

    return(NULL); 
}


