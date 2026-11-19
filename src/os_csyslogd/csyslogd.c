/* Copyright (C) 2015, Wazuh Inc.
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
            os_free(fileq);
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
        #ifdef WAZUH_UNIT_TESTING
            return;
        #else
            exit(EXIT_FAILURE);
        #endif
    }

    /* Connect to syslog */

    for (s = 0; syslog_config[s]; s++) {
        mdebug2("Resolving server hostname: %s", syslog_config[s]->server);
        resolve_hostname(&syslog_config[s]->server, 5);

        syslog_config[s]->socket = OS_ConnectUDP(syslog_config[s]->port, get_ip_from_resolved_hostname(syslog_config[s]->server), 0, 0);

        if (syslog_config[s]->socket < 0) {
            merror(CONNS_ERROR, syslog_config[s]->server, syslog_config[s]->port, "udp", strerror(errno));
        } else {
            minfo("Forwarding alerts via syslog to: '%s:%d'.",
                   syslog_config[s]->server, syslog_config[s]->port);
        }
    }

    /* Infinite loop reading the alerts and inserting them */
    while (FOREVER()) {
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

        if(al_data == NULL && json_data == NULL) {
            sleep(1);
        } else {

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

    if (sources.alert_log) {
        os_free(fileq);
    }
}

/* Copy value escaping the characters in escape (none if NULL).
 * A double quote in escape marks a quoted value, which carries no escape
 * sequences: the quote becomes a single quote, CR and LF become a space, and a
 * trailing odd run of backslashes gets one more so that a receiver that honors
 * \" (Splunk KV_MODE=auto_escaped) keeps the closing quote */
char *field_escape(const char *value, const char *escape)
{
    char *escaped;
    size_t i = 0;
    size_t backslashes = 0;
    int quoted = escape != NULL && strchr(escape, '"') != NULL;

    if (value == NULL) {
        return NULL;
    }

    os_malloc(2 * strlen(value) + 1, escaped);

    for (; *value != '\0'; value++) {
        if (escape != NULL && strchr(escape, *value) != NULL) {
            if (quoted) {
                escaped[i++] = (*value == '"') ? '\'' : ' ';
                continue;
            }
            escaped[i++] = '\\';
            escaped[i++] = (*value == '\r') ? 'r' : (*value == '\n') ? 'n' : *value;
        } else {
            escaped[i++] = *value;
        }
    }

    if (quoted) {
        while (backslashes < i && escaped[i - 1 - backslashes] == '\\') {
            backslashes++;
        }
        if (backslashes % 2) {
            escaped[i++] = '\\';
        }
    }

    escaped[i] = '\0';
    return escaped;
}

/* Format Field for output */
int field_add_string(char *dest, size_t size, const char *format, const char *value, const char *escape )
{
    char buffer[OS_MAXSTR];
    char *escaped = NULL;
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
        escaped = field_escape(value, escape);
        len = snprintf(buffer, sizeof(buffer) - dest_sz - 1, format, escaped);
        os_free(escaped);

        /* A cut field would leave its quotes or an escape sequence open */
        if (len > dest_sz && escape != NULL) {
            return -1;
        }

        strncat(dest, buffer, dest_sz);
    }

    return len;
}

/* Add a field, but truncate if too long */
int field_add_truncated(char *dest, size_t size, const char *format, const char *value, int fmt_size, const char *escape )
{
    char buffer[OS_MAXSTR];

    int available_sz = size - strlen(dest);
    int field_sz = available_sz - strlen(format) + fmt_size;

    int len = 0;
    int cut = 0;
    int backslashes = 0;
    char trailer[] = "...";
    char *escaped = NULL;

    /* Not enough room in the buffer? */
    if (available_sz <= 0 ) {
        return -1;
    }

    if (
        ((value[0] != '(') && (value[1] != 'n') && (value[2] != 'o')) ||
        ((value[0] != '(') && (value[1] != 'u') && (value[2] != 'n')) ||
        ((value[0] != 'u') && (value[1] != 'n') && (value[4] != 'k'))
       ) {
        escaped = field_escape(value, escape);

        /* snprintf below keeps one byte of available_sz for the terminator */
        if ((int)strlen(escaped) >= field_sz) {
            cut = field_sz - (int)sizeof(trailer);

            if (cut < 0) {
                os_free(escaped);
                return -1;
            }

            /* Truncate and add a trailer, without leaving half an escape sequence */
            while (escape != NULL && strchr(escape, '\\') != NULL && backslashes < cut && escaped[cut - 1 - backslashes] == '\\') {
                backslashes++;
            }
            cut -= backslashes % 2;
            strcpy(escaped + cut, trailer);
        }

        len = snprintf(buffer, available_sz, format, escaped);
        strncat(dest, buffer, available_sz);
        os_free(escaped);
    }

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
