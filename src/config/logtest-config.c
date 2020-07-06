/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "logtest-config.h"

int Read_Logtest(XML_NODE node, void *config) {

    const char *logtest_enabled = "enabled";
    const char *logtest_threads = "threads";
    const char *logtest_users_allowed = "max_sessions";
    const char *logtest_idle_time_allowed = "session_timeout";

    logtestConfig *logtest_conf = (logtestConfig *) config;

    for(int i = 0; node[i]; i++) {

        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        }

        else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return OS_INVALID;
        }

        else if (!strcmp(node[i]->element, logtest_enabled)) {
            if (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no")) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }
            strcpy(logtest_conf->enabled, node[i]->content);
        }

        else if (!strcmp(node[i]->element, logtest_threads)) {
            if (!strcmp(node[i]->content, "auto")) {
                logtest_conf->threads = get_nprocs();
                continue;
            }

            char *end;
            long value = strtol(node[i]->content, &end, 10);
            if (value < 0 || value > 65534 || *end) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            logtest_conf->threads = (unsigned short) value;
            if(logtest_conf->threads > LOGTEST_MAXTHREAD) {
                logtest_conf->threads = LOGTEST_MAXTHREAD;
                mwarn(LOGTEST_INV_NUM_THREADS, LOGTEST_MAXTHREAD);
            }
        }

        else if(!strcmp(node[i]->element, logtest_users_allowed)) {
            char *end;
            long value = strtol(node[i]->content, &end, 10);
            if (value < 0 || value > 65534 || *end) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }
            logtest_conf->max_sessions = (unsigned short) value;
        }

        else if(!strcmp(node[i]->element, logtest_idle_time_allowed)) {
            long value = w_parse_time(node[i]->content);
            if (value <= 0) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }
            logtest_conf->session_timeout = value;
        }

        else {
            merror(XML_INVELEM, node[i]->element);
            return OS_INVALID;
        }
    }

    return OS_SUCCESS;
}
