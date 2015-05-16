/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "csyslogd.h"
#include "os_net/os_net.h"

/* Global variables */
char __shost[512];
char __shost_long[512];


/* Monitor the alerts and send them via syslog
 * Only return in case of error
 */
void OS_CSyslogD(SyslogConfig **syslog_config)
{
    int s = 0;
    time_t tm;
    struct tm *p;
    int tries = 0;
    file_queue *fileq;
    alert_data *al_data;

    /* Get current time before starting */
    tm = time(NULL);
    p = localtime(&tm);

    /* Initialize file queue to read the alerts */
    os_calloc(1, sizeof(file_queue), fileq);
    while ( (Init_FileQueue(fileq, p, 0) ) < 0 ) {
        tries++;
        if ( tries > OS_CSYSLOGD_MAX_TRIES ) {
            merror("%s: ERROR: Could not open queue after %d tries, exiting!",
                   ARGV0, tries
                  );
            exit(1);
        }
        sleep(1);
    }
    debug1("%s: INFO: File queue connected.", ARGV0 );

    /* Connect to syslog */
    s = 0;
    while (syslog_config[s]) {
        syslog_config[s]->socket = OS_ConnectUDP(syslog_config[s]->port,
                                   syslog_config[s]->server, 0, NULL);
        if (syslog_config[s]->socket < 0) {
            merror(CONNS_ERROR, ARGV0, syslog_config[s]->server);
        } else {
            merror("%s: INFO: Forwarding alerts via syslog to: '%s:%d'.",
                   ARGV0, syslog_config[s]->server, syslog_config[s]->port);
        }

        s++;
    }

    /* Infinite loop reading the alerts and inserting them */
    while (1) {
        tm = time(NULL);
        p = localtime(&tm);

        /* Get message if available (timeout of 5 seconds) */
        al_data = Read_FileMon(fileq, p, 5);
        if (!al_data) {
            continue;
        }

        /* Send via syslog */
        s = 0;
        while (syslog_config[s]) {
            OS_Alert_SendSyslog(al_data, syslog_config[s]);
            s++;
        }

        /* Clear the memory */
        FreeAlertData(al_data);
    }
}

/* Format Field for output */
int field_add_string(char *dest, size_t size, const char *format, const char *value )
{
    char buffer[OS_SIZE_2048];
    int len = 0;
    int dest_sz = size - strlen(dest);

    /* Not enough room in the buffer? */
    if (dest_sz <= 0 ) {
        return -1;
    }

    if (value != NULL &&
            (
                ((value[0] != '(') && (value[1] != 'n') && (value[2] != 'o')) ||
                ((value[0] != '(') && (value[1] != 'u') && (value[2] != 'n')) ||
                ((value[0] != 'u') && (value[1] != 'n') && (value[4] != 'k'))
            )
       ) {
        len = snprintf(buffer, sizeof(buffer) - dest_sz - 1, format, value);
        strncat(dest, buffer, dest_sz);
    }

    return len;
}

/* Add a field, but truncate if too long */
int field_add_truncated(char *dest, size_t size, const char *format, const char *value, int fmt_size )
{
    char buffer[OS_SIZE_2048];

    int available_sz = size - strlen(dest);
    int total_sz = strlen(value) + strlen(format) - fmt_size;
    int field_sz = available_sz - strlen(format) + fmt_size;

    int len = 0;
    char trailer[] = "...";
    char *truncated = NULL;

    /* Not enough room in the buffer? */
    if (available_sz <= 0 ) {
        return -1;
    }

    if (
        ((value[0] != '(') && (value[1] != 'n') && (value[2] != 'o')) ||
        ((value[0] != '(') && (value[1] != 'u') && (value[2] != 'n')) ||
        ((value[0] != 'u') && (value[1] != 'n') && (value[4] != 'k'))
       ) {

        if ( (truncated = (char *) malloc(field_sz + 1)) != NULL ) {
            if ( total_sz > available_sz ) {
                /* Truncate and add a trailer */
                os_substr(truncated, value, 0, field_sz - strlen(trailer));
                strcat(truncated, trailer);
            } else {
                strncpy(truncated, value, field_sz);
            }

            len = snprintf(buffer, available_sz, format, truncated);
            strncat(dest, buffer, available_sz);
        } else {
            /* Memory Error */
            len = -3;
        }
    }
    /* Free the temporary pointer */
    free(truncated);

    return len;
}

/* Handle integers in the second position */
int field_add_int(char *dest, size_t size, const char *format, const int value )
{
    char buffer[255];
    int len = 0;
    int dest_sz = size - strlen(dest);

    /* Not enough room in the buffer? */
    if (dest_sz <= 0 ) {
        return -1;
    }

    if ( value > 0 ) {
        len = snprintf(buffer, sizeof(buffer), format, value);
        strncat(dest, buffer, dest_sz);
    }

    return len;
}

