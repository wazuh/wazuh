/* @(#) $Id: ./src/os_csyslogd/csyslogd.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or 
 * online at: http://www.ossec.net/en/licensing.html
 */



#include "csyslogd.h"
#include "os_net/os_net.h"



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


    /* Connecting to syslog. */
    s = 0;
    while(syslog_config[s])
    {
        syslog_config[s]->socket = OS_ConnectUDP(syslog_config[s]->port,
                                                 syslog_config[s]->server, 0);
        if(syslog_config[s]->socket < 0)
        {
            merror(CONNS_ERROR, ARGV0, syslog_config[s]->server);
        }
        else
        {
            merror("%s: INFO: Forwarding alerts via syslog to: '%s:%d'.", 
                   ARGV0, syslog_config[s]->server, syslog_config[s]->port); 
        }

        s++;
    }


    
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

/* Remove double quotes from these fields */
char *strip_double_quotes(char *source) {
    char *clean = malloc( strlen(source) + 1 );
    char strip = '"';
    int i;

    for( i=0; *source; source++ ) {
        if ( *source != strip ) {
            clean[i] = *source;
            i++;
        }
    }
    clean[i] = 0;

    return clean;
}

/* Format Field for output */
unsigned int field_add_string(char *dest, unsigned int size, const char *format, const char *value ) {
    char buffer[255];
    unsigned int len = 0;

    if(value != NULL &&
            (
                ((value[0] != '(') && (value[1] != 'n') && (value[2] != 'o')) ||
                ((value[0] != '(') && (value[1] != 'u') && (value[2] != 'n')) ||
                ((value[0] != 'u') && (value[1] != 'n') && (value[4] != 'k'))
            )
    ) {
        len = snprintf(buffer, 255, format, value);
        strncat(dest, buffer, OS_SIZE_2048);
    }

    return len;
}

/* Add long string */
unsigned int field_add_long_string(char *dest, unsigned int size, const char *format, const char *value ) {
    char buffer[OS_SIZE_2048 + 1];
    unsigned int len = 0;
    unsigned int dest_sz = strlen(dest);

    if(value != NULL) {
        len = snprintf(buffer, OS_SIZE_2048 - dest_sz - 2  , format, value);
        strncat(dest, buffer, size);
    }

    return len;
}

/* Handle integers in the second position */
unsigned int field_add_int(char *dest, unsigned int size, const char *format, const int value ) {
    char buffer[255];
    unsigned int len = 0;

    if( value > 0 ) {
        len = snprintf(buffer, 255, format, value);
        strncat(dest, buffer, OS_SIZE_2048);
    }

    return len;
}
/* EOF */
