/* @(#) $Id$ */

/* Copyright (C) 2006 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#include "shared.h"
#include "monitord.h"


/* Real monitord global */
void Monitord()
{
    time_t tm;     
    struct tm *p;       

    int today = 0;		        
    int thishour = 0;

    char str[OS_MAXSTR +1];

    /* Waiting a few seconds to settle */
    sleep(10);

    memset(str, '\0', OS_MAXSTR +1);
    
    
    /* Getting currently time before starting */
    tm = time(NULL);
    p = localtime(&tm);	
    today = p->tm_mday;
    thishour = p->tm_hour;

    
    /* Connecting to the message queue
     * Exit if it fails.
     */
    if((mond.a_queue = StartMQ(DEFAULTQUEUE,WRITE)) < 0)
    {
        ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
    }


    /* Sending startup message */
    snprintf(str, OS_MAXSTR -1, OS_AD_STARTED);
    if(SendMSG(mond.a_queue, str, ARGV0,
                       LOCALFILE_MQ) < 0)
    {
        merror(QUEUE_SEND, ARGV0);
    }
    
    /* Main monitor loop */
    while(1)
    {
        tm = time(NULL);
        p = localtime(&tm);

        /* Checking unavailable agents */
        
        /* Day changed, deal with log files */
        if(today != p->tm_mday)
        {
            manage_files(p->tm_mday, p->tm_mon, p->tm_year+1900);

            today = p->tm_mday;
        }

        /* We only check every minute */
        sleep(60);
    }
}

/* EOF */
