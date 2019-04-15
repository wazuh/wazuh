/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Read MySQL logs */

#include "shared.h"
#include "logcollector.h"

/* Send MongoDB message and check the return code */
static void __send_mongodb_msg(logreader *lf, int drop_it, char *buffer) {
    if (drop_it == 0) {
        w_msg_hash_queues_push(buffer, lf->file, strlen(buffer) + 1, lf->log_target, POSTGRESQL_MQ);
    }
}

/* Read MongoDB log messages*/
void *read_mongodb_log(logreader *lf, int *rc, int drop_it) {

    size_t str_len = 0;
    int need_clear = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    char buffer[OS_MAXSTR + 1];
    int lines = 0;

    /* Zero buffer and str */
    buffer[0] = '\0';
    buffer[OS_MAXSTR] = '\0';
    str[OS_MAXSTR] = '\0';
    *rc = 0;

    /* Get new entry */
    while (fgets(str, OS_MAXSTR - OS_LOG_HEADER, lf->fp) != NULL && (!maximum_lines || lines < maximum_lines)){

        mdebug2("Reading mongodb messages: '%s'", str);

        lines++;
        /* Get buffer size */
        str_len = strlen(str);

        /* Get the last occurrence of \n */
        if ((p = strrchr(str, '\n')) != NULL) {
            *p = '\0';

            /* If need clear is set, we just get the line and ignore it */
            if (need_clear) {
                need_clear = 0;
                continue;
            }
        } else {
            need_clear = 1;
        }

#ifdef WIN32
        if ((p = strrchr(str, '\r')) != NULL) {
            *p = '\0';
        }

        /* Look for empty string (only on windows) */
        if (str_len <= 2) {
            continue;
        }


        /* Windows can have comment on their logs */
        if (str[0] == '#') {
            continue;
        }
#endif

        /* MongoDB log message format:
        2014-11-03T18:28:32.450-0500 I NETWORK [initandlisten] menssage
        */
        if((str_len > 20) &&
            (str[4] == '-') &&
            (str[7] == '-') &&
            (str[10] == 'T') &&
            (str[13] == ':') &&
            (str[16] == ':') &&
            (str[19] == '.')
        ){
            str[19] = ' ';
            strncpy(buffer, str, str_len + 2);

            if(buffer[0] != '\0'){ 
                /* Send message to queue */
                __send_mongodb_msg(lf, drop_it, buffer);
            }
        }

        continue;
    }

    if (buffer[0] != '\0'){
        /* Send message to queue */
        __send_mongodb_msg(lf, drop_it, buffer);
    }

    mdebug2("Read %d lines from %s", lines, lf->file);
    return (NULL);
}