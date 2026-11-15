/* Copyright (C) Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "legacy-client-manager.h"
#include "agent-manager-entry.h"

/* An <endpoint> written here by the installer carries the whole target, so it is parsed
 * exactly as one under <agent><manager> would be. */
static int w_set_legacy_endpoint(agent *logr, const char *value)
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

    w_agent_set_manager(logr, host, port, endpoint, scope_id);
    return 0;
}

/* 4.x had no <endpoint> concept at all -- any <port> under this legacy <client><server>
 * block was never read either -- so a WPK-upgraded agent always reconnects on the 5.x
 * HTTPS port with the manager's default reverse-proxy prefix, never the old 4.x port or
 * unprefixed requests.
 *
 * A 4.x file has no <endpoint> at all, so say exactly what to write -- this is the upgrade
 * path most likely to be edited by hand, and a copy-pasteable line is the whole point. The
 * composed value is the one now in use, so pasting it changes nothing about where the
 * agent connects. */
static void w_set_legacy_address(agent *logr, const char *address)
{
    char *name = NULL;

    w_agent_set_manager(logr, address, DEFAULT_HTTPS_REMOTE_PORT, DEFAULT_AGENT_ENDPOINT_PREFIX, 0);
    name = w_agent_manager_name(&logr->server[0]);

    minfo("<agent><manager><endpoint> is not configured. Using <client><server><address> '%s' "
          "with the default port %d and the default endpoint prefix '%s'. Replace the "
          "<client><server> block with a single <endpoint>%s</endpoint>",
          logr->server[0].rip, DEFAULT_HTTPS_REMOTE_PORT, DEFAULT_AGENT_ENDPOINT_PREFIX, name);
    os_free(name);
}

int w_legacy_client_set_manager(agent *logr, const w_legacy_targets_t *targets)
{
    size_t chosen = 0;

    if (!w_legacy_targets_chosen(targets, &chosen)) {
        return 0;
    }

    if (targets->items[chosen].is_endpoint) {
        return w_set_legacy_endpoint(logr, targets->items[chosen].value);
    }

    w_set_legacy_address(logr, targets->items[chosen].value);
    return 0;
}
