/* Copyright (C) Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "legacy-server-entry.h"

/* Install the single manager entry, with the NULL-rip sentinel at index 1. */
static void w_set_legacy_server(agent *logr, const char *host, int port, const char *endpoint,
                                uint32_t scope_id)
{
    os_calloc(2, sizeof(agent_server), logr->server);
    os_strdup(host, logr->server[0].rip);

    if (strchr(logr->server[0].rip, ':') != NULL) {
        os_realloc(logr->server[0].rip, IPSIZE + 1, logr->server[0].rip);
        OS_ExpandIPv6(logr->server[0].rip, IPSIZE);
    }

    if (endpoint[0] != '\0') {
        os_strdup(endpoint, logr->server[0].endpoint);
    }

    logr->server[0].scope_id = scope_id;
    logr->server[0].port = port;
    logr->server_count = 1;
}

/* An <endpoint> carries the whole target and is parsed exactly as one under
 * <agent><manager> would be. */
static int w_set_legacy_server_from_endpoint(agent *logr, const char *value)
{
    char host[AGENT_SERVER_HOST_MAX_LEN + 1] = {'\0'};
    char endpoint[AGENT_SERVER_ENDPOINT_MAX_LEN + 1] = {'\0'};
    uint32_t scope_id = 0;
    int port = DEFAULT_HTTPS_REMOTE_PORT;
    bool port_present = false;

    if (w_parse_agent_endpoint(value, host, sizeof(host), &port, &port_present, endpoint,
                               sizeof(endpoint), &scope_id) == OS_INVALID) {
        return OS_INVALID;
    }

    w_set_legacy_server(logr, host, port, endpoint, scope_id);
    return 0;
}

/* 4.x had no <endpoint>, and its <port> is the old TCP port, so the agent connects on the
 * 5.x HTTPS port with the manager's default prefix. This is the upgrade path most likely
 * to be edited by hand, so the message gives the exact line that keeps the agent where it
 * connects now. */
static void w_set_legacy_server_from_address(agent *logr, const char *address)
{
    w_set_legacy_server(logr, address, DEFAULT_HTTPS_REMOTE_PORT, DEFAULT_AGENT_ENDPOINT_PREFIX, 0);

    const bool is_ipv6 = strchr(logr->server[0].rip, ':') != NULL;

    minfo("<agent><manager><endpoint> is not configured. Using <client><server><address> '%s' "
          "with the default port %d and the default endpoint prefix '%s'. Replace the "
          "<client><server> block with a single <endpoint>%s%s%s:%d/%s</endpoint>",
          logr->server[0].rip, DEFAULT_HTTPS_REMOTE_PORT, DEFAULT_AGENT_ENDPOINT_PREFIX,
          is_ipv6 ? "[" : "", logr->server[0].rip, is_ipv6 ? "]" : "",
          DEFAULT_HTTPS_REMOTE_PORT, DEFAULT_AGENT_ENDPOINT_PREFIX);
}

int w_legacy_server_install(agent *logr, const w_legacy_target_t *target)
{
    if (!target->is_endpoint) {
        w_set_legacy_server_from_address(logr, target->value);
        return 0;
    }

    return w_set_legacy_server_from_endpoint(logr, target->value);
}
