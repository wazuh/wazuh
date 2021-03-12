/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "csyslogd.h"
#include "os_net/os_net.h"

typedef struct alert_source_t {
    int alert_log:1;
    int alert_json:1;
} alert_source_t;

/* Global variables */
char __shost[512];
char __shost_long[512];

static alert_source_t get_alert_sources(SyslogConfig **syslog_config);

/* Monitor the alerts and send them via syslog
 * Only return in case of error
 */
void OS_CSyslogD(SyslogConfig **syslog_config)
{
    int s = 0;
    time_t tm;
    struct tm tm_result = { .tm_sec = 0 };
    int tries = 0;
    alert_source_t sources = get_alert_sources(syslog_config);
    file_queue *fileq = NULL;
    file_queue jfileq;
    alert_data *al_data = NULL;
    cJSON *json_data = NULL;

    if (sources.alert_log) {

        /* Get current time before starting */
        tm = time(NULL);
        localtime_r(&tm, &tm_result);

        /* Initialize file queue to read the alerts */
        os_calloc(1, sizeof(file_queue), fileq);

        for (tries = 0; tries < OS_CSYSLOGD_MAX_TRIES && Init_FileQueue(fileq, &tm_result, 0) < 0; tries++) {
            sleep(1);
        }

        if (tries == OS_CSYSLOGD_MAX_TRIES) {
            merror("Could not open queue after %d tries.", tries);
            sources.alert_log = 0;
        } else {
            mdebug1("File queue connected.");
        }
    }

    if (sources.alert_json) {
        jqueue_init(&jfileq);

        for (tries = 1; tries < OS_CSYSLOGD_MAX_TRIES && jqueue_open(&jfileq, 1) < 0; tries++) {
            sleep(1);
        }

        if (tries == OS_CSYSLOGD_MAX_TRIES) {
            merror("Could not open JSON queue after %d tries.", tries);
            sources.alert_json = 0;
        } else {
            mdebug1("JSON file queue connected.");
        }
    }

    if (!(sources.alert_log || sources.alert_json)) {
        merror("No configurations available. Exiting.");
        exit(EXIT_FAILURE);
    }

    /* Connect to syslog */

    for (s = 0; syslog_config[s]; s++) {
        syslog_config[s]->socket = OS_ConnectUDP(syslog_config[s]->port, syslog_config[s]->server, 0);

        if (syslog_config[s]->socket < 0) {
            merror(CONNS_ERROR, syslog_config[s]->server, syslog_config[s]->port, "udp", strerror(errno));
        } else {
            minfo("Forwarding alerts via syslog to: '%s:%d'.",
                   syslog_config[s]->server, syslog_config[s]->port);
        }
    }

    /* Infinite loop reading the alerts and inserting them */
    while (1) {
        tm = time(NULL);
        localtime_r(&tm, &tm_result);

        if (sources.alert_log) {
            /* Get message if available (timeout of 5 seconds) */
            mdebug2("Read_FileMon()");
            al_data = Read_FileMon(fileq, &tm_result, 1);
        }

        if (sources.alert_json) {
            mdebug2("jqueue_next()");
            json_data = jqueue_next(&jfileq);
        }

        /* Send via syslog */

        for (s = 0; syslog_config[s]; s++) {
            if (syslog_config[s]->format == JSON_CSYSLOG) {
                if (json_data) {
                    OS_Alert_SendSyslog_JSON(json_data, syslog_config[s]);
                }
            } else if (al_data) {
                OS_Alert_SendSyslog(al_data, syslog_config[s]);
            }
        }

        /* Clear the memory */

        if (al_data) {
            FreeAlertData(al_data);
        }

        if (json_data) {
            cJSON_Delete(json_data);
        }
    }
}

/* Format Field for output */
int field_add_string(char *dest, size_t size, const char *format, const char *value )
{
    char buffer[OS_MAXSTR];
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
    char buffer[OS_MAXSTR];

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

alert_source_t get_alert_sources(SyslogConfig **syslog_config) {
    alert_source_t sources = { 0, 0 };
    int i;

    for (i = 0; syslog_config[i]; i++) {
        if (syslog_config[i]->format == JSON_CSYSLOG) {
            sources.alert_json = 1;
        } else {
            sources.alert_log = 1;
        }
    }

    return sources;
}
