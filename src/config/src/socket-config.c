/*
 * Socket settings manager
 * Copyright (C) 2015, Wazuh Inc.
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
#include "global-config.h"

static const char *socket_name = "name";
static const char *socket_location = "location";
static const char *socket_mode = "mode";
static const char *socket_prefix = "prefix";

int Read_LogCollecSocket(XML_NODE node, void *d1, __attribute__((unused)) void *d2) {

    socket_forwarder *sktf;
    logreader_config *log_config;

    log_config = (logreader_config *)d1;

    unsigned int pl = 0;
    unsigned int i = 0;

    /* If config is not set, create it */
    if (!log_config->socket_list) {
        os_calloc(2, sizeof(socket_forwarder), log_config->socket_list);
        sktf = log_config->socket_list;
        memset(sktf, 0, 2 * sizeof(socket_forwarder));
    } else {
        sktf = log_config->socket_list;
        while (sktf[pl].name != NULL) {
            pl++;
        }

        /* Allocate more memory */
        os_realloc(sktf, (pl + 2)*sizeof(socket_forwarder), log_config->socket_list);
        sktf = log_config->socket_list;
        memset(sktf + pl + 1, 0, sizeof(socket_forwarder));
    }

    sktf[pl].name = NULL;
    sktf[pl].location = NULL;
    sktf[pl].mode = IPPROTO_UDP;
    sktf[pl].prefix = NULL;
    sktf[pl].socket = -1;

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
            os_free(sktf[pl].name);
            os_strdup(node[i]->content, sktf[pl].name);
        } else if (!strcmp(node[i]->element, socket_location)) {
            os_free(sktf[pl].location);
            os_strdup(node[i]->content, sktf[pl].location);
        } else if (!strcmp(node[i]->element, socket_mode)) {
            if (strcasecmp(node[i]->content, "tcp") == 0) {
                sktf[pl].mode = IPPROTO_TCP;
            } else if (strcasecmp(node[i]->content, "udp") == 0) {
                sktf[pl].mode = IPPROTO_UDP;
            } else {
                merror("Socket type '%s' is not valid at <%s>. Should be 'udp' or 'tcp'.", node[i]->content, node[i]->element);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, socket_prefix)) {
            os_free(sktf[pl].prefix);
            sktf[pl].prefix = filter_special_chars(node[i]->content);
        } else {
            merror(XML_INVELEM, node[i]->element);
            return OS_INVALID;
        }
    }

    /* Missing name */
    if (!(sktf[pl].name && *sktf[pl].name)) {
        merror(MISS_SOCK_NAME);
        return (OS_INVALID);
    }

    /* Missing location */
    if (!(sktf[pl].location && *sktf[pl].location)) {
        merror(MISS_SOCK_LOC);
        return (OS_INVALID);
    }

    return 0;
}
