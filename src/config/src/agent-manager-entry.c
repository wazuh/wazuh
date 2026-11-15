/* Copyright (C) Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agent-manager-entry.h"

void w_agent_free_managers(agent *logr)
{
    for (int i = 0; logr->server && logr->server[i].rip; i++) {
        os_free(logr->server[i].rip);
        os_free(logr->server[i].endpoint);
    }

    os_free(logr->server);
    logr->server_count = 0;
}

/* An IPv6 host is stored expanded. A host with a ':' that doesn't expand, such as a
 * hostname written with its port, is kept as written, however long it is. */
static char *w_agent_manager_host(const char *host)
{
    char expanded[IPSIZE + 1];
    char *stored = NULL;

    if (strchr(host, ':') != NULL && strlen(host) <= IPSIZE) {
        snprintf(expanded, sizeof(expanded), "%s", host);

        if (OS_ExpandIPv6(expanded, sizeof(expanded)) == OS_SUCCESS) {
            host = expanded;
        }
    }

    os_strdup(host, stored);
    return stored;
}

void w_agent_set_manager(agent *logr, const char *host, int port, const char *endpoint,
                         uint32_t scope_id)
{
    agent_server *server = NULL;

    /* Built before the earlier entry is freed: host and endpoint may be its own strings. */
    os_calloc(2, sizeof(agent_server), server);
    server[0].rip = w_agent_manager_host(host);

    if (endpoint[0] != '\0') {
        os_strdup(endpoint, server[0].endpoint);
    }

    server[0].scope_id = scope_id;
    server[0].port = port;

    w_agent_free_managers(logr);
    logr->server = server;
    logr->server_count = 1;
}
