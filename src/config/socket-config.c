/*
 * Socket settings manager
 * Copyright (C) 2015-2019, Wazuh Inc.
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
        memset(logf, 0, 2 * sizeof(logsocket));
    } else {
        logf = log_config->socket_list;
        while (logf[pl].name != NULL) {
            pl++;
        }

        /* Allocate more memory */
        os_realloc(logf, (pl + 2)*sizeof(logsocket), log_config->socket_list);
        logf = log_config->socket_list;
        memset(logf + pl + 1, 0, sizeof(logsocket));
    }
    logf[pl].name = NULL;
    logf[pl].location = NULL;
    logf[pl].mode = UDP_PROTO;
    logf[pl].prefix = NULL;
    logf[pl].socket = -1;

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
            free(logf[pl].name);
            os_strdup(node[i]->content, logf[pl].name);
        } else if (!strcmp(node[i]->element, socket_location)) {
            free(logf[pl].location);
            os_strdup(node[i]->content, logf[pl].location);
        } else if (!strcmp(node[i]->element, socket_mode)) {
            if (strcasecmp(node[i]->content, "tcp") == 0) {
                logf[pl].mode = TCP_PROTO;
            } else if (strcasecmp(node[i]->content, "udp") == 0) {
                logf[pl].mode = UDP_PROTO;
            } else {
                merror("Socket type '%s' is not valid at <%s>. Should be 'udp' or 'tcp'.", node[i]->content, node[i]->element);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, socket_prefix)) {
            free(logf[pl].prefix);
            logf[pl].prefix = filter_special_chars(node[i]->content);
        } else {
            merror(XML_INVELEM, node[i]->element);
            return OS_INVALID;
        }
    }

    /* Missing name */
    if (!(logf[pl].name && *logf[pl].name)) {
        merror(MISS_SOCK_NAME);
        return (OS_INVALID);
    }

    /* Missing location */
    if (!(logf[pl].location && *logf[pl].location)) {
        merror(MISS_SOCK_LOC);
        return (OS_INVALID);
    }

    return 0;
 }
