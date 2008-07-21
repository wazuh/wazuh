/* @(#) $Id$ */

/* Copyright (C) 2008 Third Brigade, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or 
 * online at: http://www.ossec.net/en/licensing.html
 */



#include "csyslogd.h"



/* OS_SyslogD: Monitor the alerts and sends them via syslog.
 * Only return in case of error.
 */
void OS_CSyslogD(SyslogConfig **syslog_config)
{
    int s = 0;
    time_t tm;     
    struct tm *p;       

    file_queue *fileq;
    alert_data *al_data;


    /* Getting currently time before starting */
    tm = time(NULL);
    p = localtime(&tm);	


    /* Initating file queue - to read the alerts */
    os_calloc(1, sizeof(file_queue), fileq);
    Init_FileQueue(fileq, p, 0);


    /* Infinite loop reading the alerts and inserting them. */
    while(1)
    {
        tm = time(NULL);
        p = localtime(&tm);


        /* Get message if available (timeout of 5 seconds) */
        al_data = Read_FileMon(fileq, p, 5);
        if(!al_data)
        {
            continue;
        }



        /* Sending via syslog */
        s = 0;
        while(syslog_config[s])
        {
            OS_Alert_SendSyslog(al_data, syslog_config[s]);
            s++;
        }


        /* Clearing the memory */
        FreeAlertData(al_data);
    }
}

/* EOF */
