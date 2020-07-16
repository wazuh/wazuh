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


const char *enabled = "enabled";
const char *threads = "threads";
const char *max_sessions = "max_sessions";
const char *session_timeout = "session_timeout";


int Read_Logtest(XML_NODE node) {

    for (int i = 0; node[i]; i++) {

        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        }

        else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return OS_INVALID;
        }

        else if (!strcmp(node[i]->element, enabled)) {
            if (strcmp(node[i]->content, "yes") && strcmp(node[i]->content, "no")) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }
            strcpy(w_logtest_conf.enabled, node[i]->content);
        }

        else if (!strcmp(node[i]->element, threads)) {
            if (!strcmp(node[i]->content, "auto")) {
                w_logtest_conf.threads = get_nproc();
                continue;
            }

            char *end;
            long value = strtol(node[i]->content, &end, 10);

            if (value < 0 || value > 65534 || *end) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            } else if (value > LOGTEST_LIMIT_THREAD) {
                mdebug2(LOGTEST_INV_NUM_THREADS, LOGTEST_LIMIT_THREAD);
                w_logtest_conf.threads = LOGTEST_LIMIT_THREAD;
            } else {
                w_logtest_conf.threads = (unsigned short) value;
            }
        }

        else if (!strcmp(node[i]->element, max_sessions)) {
            char *end;
            long value = strtol(node[i]->content, &end, 10);

            if (value < 0 || value > 65534 || *end) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            } else if (value > LOGTEST_LIMIT_MAX_SESSIONS) {
                mdebug2(LOGTEST_INV_NUM_USERS, LOGTEST_LIMIT_MAX_SESSIONS);
                w_logtest_conf.max_sessions = LOGTEST_LIMIT_MAX_SESSIONS;
            } else {
                w_logtest_conf.max_sessions = (unsigned short) value;
            }
        }

        else if (!strcmp(node[i]->element, session_timeout)) {
            long value = w_parse_time(node[i]->content);

            if (value <= 0) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            } else if (value > LOGTEST_LIMIT_SESSION_TIMEOUT) {
                mdebug2(LOGTEST_INV_NUM_TIMEOUT, LOGTEST_LIMIT_SESSION_TIMEOUT);
                w_logtest_conf.session_timeout = LOGTEST_LIMIT_SESSION_TIMEOUT;
            } else {
                w_logtest_conf.session_timeout = value;
            }
        }

        else {
            merror(XML_INVELEM, node[i]->element);
            return OS_INVALID;
        }
    }

    return OS_SUCCESS;
}


cJSON *getRuleTestConfig() {

    cJSON *root = cJSON_CreateObject();
    cJSON *ruletest = cJSON_CreateObject();

    if (w_logtest_conf.enabled)cJSON_AddStringToObject(ruletest, enabled, w_logtest_conf.enabled);
    if (w_logtest_conf.threads)cJSON_AddNumberToObject(ruletest, threads, w_logtest_conf.threads);
    if (w_logtest_conf.max_sessions)cJSON_AddNumberToObject(ruletest, max_sessions, w_logtest_conf.max_sessions);
    if (w_logtest_conf.session_timeout)cJSON_AddNumberToObject(ruletest, session_timeout, w_logtest_conf.session_timeout);

    cJSON_AddItemToObject(root, "rule_test", ruletest);

    return root;
}
