/* Copyright (C) Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Settle_Legacy_Client(), declared in config.h beside Read_Legacy_Client(): once the whole
 * file is read, the targets of the legacy <client> blocks make the agent's manager unless
 * <agent> set one. */

#include "shared.h"
#include "config.h"
#include "client-config.h"
#include "legacy-server-targets.h"
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

/* An <endpoint> is parsed exactly as one under <agent><manager> would be; an <address> gets
 * the 5.x HTTPS port and the manager's default prefix. OS_INVALID when an <endpoint> doesn't
 * parse (logged). */
static int w_set_legacy_target(agent *logr, const w_legacy_target_t *target)
{
    if (target->is_endpoint) {
        return w_set_legacy_endpoint(logr, target->value);
    }

    w_set_legacy_address(logr, target->value);
    return 0;
}

/* 5.x connects to a single manager (#37702), so a 4.x failover list loses all but one. The
 * dropped ones are named as written, so they can be found in the file. `chosen` is the
 * legacy target in use, NULL when <agent> set the manager and every target is dropped. */
static void w_warn_legacy_dropped(const w_legacy_targets_t *targets, const char *chosen,
                                  const agent_server *in_use)
{
    char *ignored = w_legacy_targets_quote(targets, chosen);
    char *name = ignored ? w_agent_manager_name(in_use) : NULL;

    if (ignored && chosen) {
        mwarn("The legacy <client> block names more than one manager, and only one is "
              "supported. Using '%s', ignoring %s.", name, ignored);
    } else if (ignored) {
        mwarn("<server> inside the legacy <client> block is ignored: the manager is already "
              "set to '%s'. Ignoring %s.", name, ignored);
    }

    os_free(name);
    os_free(ignored);
}

/* The chosen target becomes the manager and the others are named in a warning. */
static int w_legacy_client_set_manager(agent *logr, const w_legacy_targets_t *targets)
{
    size_t chosen = 0;

    if (!w_legacy_targets_chosen(targets, &chosen)) {
        return 0;
    }

    if (w_set_legacy_target(logr, &targets->items[chosen]) < 0) {
        return OS_INVALID;
    }

    w_warn_legacy_dropped(targets, targets->items[chosen].value, &logr->server[0]);
    return 0;
}

/**
 * @brief Make the legacy <client> targets the agent's manager, once the whole file is read.
 *
 * An <agent> that set a manager, through <manager> or the deprecated <server-ip> or
 * <server-hostname>, wins wherever it sits in the file, and the legacy targets are named in
 * a warning. Otherwise the first <client> block that names a manager decides it: its last
 * <endpoint> wins, else its last <address>, and every other target of the file is named in
 * a warning. Only the target in use is parsed, so a malformed one the agent doesn't use
 * cannot fail the configuration.
 *
 * @param d1 Agent configuration.
 * @return 0 on success, OS_INVALID when the chosen <endpoint> doesn't parse (logged).
 */
int Settle_Legacy_Client(void *d1)
{
    agent *logr = (agent *)d1;
    int ret = 0;

    if (!logr->legacy_targets) {
        return 0;
    }

    if (logr->server) {
        w_warn_legacy_dropped(logr->legacy_targets, NULL, &logr->server[0]);
    } else {
        ret = w_legacy_client_set_manager(logr, logr->legacy_targets);
    }

    w_legacy_targets_free(logr->legacy_targets);
    os_free(logr->legacy_targets);
    return ret;
}
