/*
 * Socket settings manager
 * Copyright (C) 2018 Wazuh Inc.
 * Feb 7, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "config.h"
#include "localfile-config.h"


int Read_Socket(XML_NODE node, void *d1, __attribute__((unused)) void *d2) {

    static const char *socket_name = "name";
    static const char *socket_location = "location";
    static const char *socket_mode = "mode";
    static const char *socket_prefix = "prefix";

    logsocket *logf;
    logreader_config *log_config;

    log_config = (logreader_config *)d1;

    unsigned int pl = 0;
    unsigned int i = 0;

    /* If config is not set, create it */
    if (!log_config->socket_list) {
        os_calloc(2, sizeof(logsocket), log_config->socket_list);
        logf = log_config->socket_list;
        logf[0].name = NULL;
        logf[0].location = NULL;
        logf[0].mode = NULL;
        logf[0].prefix = NULL;
        logf[0].socket = 0;
        logf[1].name = NULL;
        logf[1].location = NULL;
        logf[1].mode = NULL;
        logf[1].prefix = NULL;
        logf[1].socket = 0;
    } else {
        logf = log_config->socket_list;
        while (logf[pl].name != NULL) {
            pl++;
        }

        /* Allocate more memory */
        os_realloc(logf, (pl + 2)*sizeof(logsocket), log_config->socket_list);
        logf = log_config->socket_list;
        logf[pl + 1].name = NULL;
        logf[pl + 1].location = NULL;
        logf[pl + 1].mode = NULL;
        logf[pl + 1].prefix = NULL;
        logf[pl + 1].socket = 0;
    }
    logf[pl].name = NULL;
    logf[pl].location = NULL;
    logf[pl].mode = NULL;
    logf[pl].prefix = NULL;
    logf[pl].socket = 0;

    for (i = 0; node[i]; i++) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return OS_INVALID;
        } else if (!strcmp(node[i]->element, socket_name)) {
            // Socket 'agent' is reserved for internal purpose.
            // Defining a new socket with this name is not allowed.
            if (!strcmp(node[i]->content, "agent")) {
                merror("Invalid socket name 'agent'.");
                return OS_INVALID;
            }
            os_strdup(node[i]->content, logf[pl].name);
        } else if (!strcmp(node[i]->element, socket_location)) {
            os_strdup(node[i]->content, logf[pl].location);
        } else if (!strcmp(node[i]->element, socket_mode)) {
            if (!strcmp(node[i]->content, "tcp") || !strcmp(node[i]->content, "udp")){
                os_strdup(node[i]->content, logf[pl].mode);
            } else {
                merror("Socket type '%s' is not valid. Should be 'udp' or 'tcp'.", node[i]->content);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, socket_prefix)) {
            os_strdup(node[i]->content, logf[pl].prefix);
        } else {
            merror(XML_INVELEM, node[i]->element);
            return OS_INVALID;
        }
    }

    /* Missing name */
    if (!logf[pl].name) {
        merror(MISS_SOCK_NAME);
        return (OS_INVALID);
    }

    /* Missing location */
    if (!logf[pl].location) {
        merror(MISS_SOCK_LOC);
        return (OS_INVALID);
    }

    if (logf[pl].mode == NULL) {
        os_strdup("udp", logf[pl].mode);
    }

    return 0;
 }
