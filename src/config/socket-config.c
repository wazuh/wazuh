/*
 * Socket settings manager
 * Copyright (C) 2015-2019, Wazuh Inc.
 * Feb 7, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "config.h"
#include "localfile-config.h"


int Read_Socket(XML_NODE node, void *d1, __attribute__((unused)) void *d2, char **output) {

    static const char *socket_name = "name";
    static const char *socket_location = "location";
    static const char *socket_mode = "mode";
    static const char *socket_prefix = "prefix";

    logsocket *logf;
    logreader_config *log_config;

    log_config = (logreader_config *)d1;

    unsigned int pl = 0;
    unsigned int i = 0;
    char message[OS_FLSIZE];

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
    logf[pl].mode = IPPROTO_UDP;
    logf[pl].prefix = NULL;
    logf[pl].socket = -1;

    for (i = 0; node[i]; i++) {
        if (!node[i]->element) {
            if (output == NULL) {
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            return OS_INVALID;
        } else if (!node[i]->content) {
            if (output == NULL) {
                merror(XML_VALUENULL, node[i]->element);
            } else {
                snprintf(message, OS_FLSIZE + 1,
                    "Invalid NULL content for element: %s.",
                    node[i]->element);
                wm_strcat(output, message, '\n');
            }
            return OS_INVALID;
        } else if (!strcmp(node[i]->element, socket_name)) {
            // Socket 'agent' is reserved for internal purpose.
            // Defining a new socket with this name is not allowed.
            if (!strcmp(node[i]->content, "agent")) {
                if (output == NULL) {
                    merror("Invalid socket name 'agent'.");
                } else {
                    wm_strcat(output, "Invalid socket name 'agent'.", '\n');
                }
                return OS_INVALID;
            }
            free(logf[pl].name);
            os_strdup(node[i]->content, logf[pl].name);
        } else if (!strcmp(node[i]->element, socket_location)) {
            free(logf[pl].location);
            os_strdup(node[i]->content, logf[pl].location);
        } else if (!strcmp(node[i]->element, socket_mode)) {
            if (strcasecmp(node[i]->content, "tcp") == 0) {
                logf[pl].mode = IPPROTO_TCP;
            } else if (strcasecmp(node[i]->content, "udp") == 0) {
                logf[pl].mode = IPPROTO_UDP;
            } else if (output == NULL) {
                merror("Socket type '%s' is not valid at <%s>. Should be 'udp' or 'tcp'.",
                    node[i]->content, node[i]->element);
                return OS_INVALID;
            } else {
                snprintf(message, OS_FLSIZE + 1,
                    "Socket type '%s' is not valid at <%s>. Should be 'udp' or 'tcp'.",
                    node[i]->content, node[i]->element);
                wm_strcat(output, message, '\n');
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, socket_prefix)) {
            free(logf[pl].prefix);
            logf[pl].prefix = filter_special_chars(node[i]->content);
        } else if (output == NULL) {
            merror(XML_INVELEM, node[i]->element);
            return OS_INVALID;
        } else {
            snprintf(message, OS_FLSIZE + 1,
                "Invalid element in the configuration: '%s'.",
                node[i]->element);
            wm_strcat(output, message, '\n');
            return OS_INVALID;
        }
    }

    /* Missing name */
    if (!(logf[pl].name && *logf[pl].name)) {
        if (output == NULL) {
            merror(MISS_SOCK_NAME);
        } else {
            wm_strcat(output, "Missing field 'name' for socket.", '\n');
        }
        return (OS_INVALID);
    }

    /* Missing location */
    if (!(logf[pl].location && *logf[pl].location)) {
        if (output == NULL) {
            merror(MISS_SOCK_LOC);
        } else {
            wm_strcat(output, "Missing field 'location' for socket.", '\n');
        }
        return (OS_INVALID);
    }

    return 0;
 }
