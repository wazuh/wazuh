/* Copyright (C) Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "legacy-target-name.h"

/* host:port/prefix, an IPv6 host expanded and bracketed with its zone, as the agent stores
 * and dials it. `fold` lowercases the host: host names and IPv6 digits are case-insensitive,
 * the prefix is a path and is not. */
static char *w_legacy_name_format(const char *host, int port, const char *prefix,
                                  uint32_t scope_id, bool fold)
{
    char expanded[IPSIZE + 1];
    char zone[16] = "";
    const bool is_ipv6 = strchr(host, ':') != NULL;
    char *name = NULL;
    size_t size = 0;

    if (is_ipv6) {
        snprintf(expanded, sizeof(expanded), "%s", host);
        OS_ExpandIPv6(expanded, IPSIZE);
        host = expanded;
    }

    if (scope_id != 0) {
        snprintf(zone, sizeof(zone), "%%%u", scope_id);
    }

    size = strlen(host) + strlen(zone) + strlen(prefix) + 16;
    os_malloc(size, name);
    snprintf(name, size, "%s%s%s%s:%d/%s", is_ipv6 ? "[" : "", host, zone, is_ipv6 ? "]" : "", port, prefix);

    for (size_t i = 0; fold && i < strlen(host) + (is_ipv6 ? 1 : 0); i++) {
        name[i] = (char)tolower((unsigned char)name[i]);
    }

    return name;
}

/* The host an <address> really reaches, written the way the URL parser writes it, so that
 * "127.1" and "127.0.0.1" compare equal. An IPv6 address is left to the expansion in
 * w_legacy_name_format(). Falls back to the text as written. */
static const char *w_legacy_key_host(const char *address, char host[AGENT_SERVER_HOST_MAX_LEN + 1])
{
    char prefix[AGENT_SERVER_ENDPOINT_MAX_LEN + 1];
    int port = DEFAULT_HTTPS_REMOTE_PORT;
    bool port_present = false;
    uint32_t scope_id = 0;

    if (strchr(address, ':') == NULL &&
        w_parse_agent_endpoint_quiet(address, host, AGENT_SERVER_HOST_MAX_LEN + 1, &port,
                                     &port_present, prefix, sizeof(prefix), &scope_id) == 0) {
        return host;
    }

    return address;
}

static void w_legacy_name_address(const char *host, int port, const char *prefix, uint32_t scope_id,
                                  char **dialed, char **key)
{
    char parsed[AGENT_SERVER_HOST_MAX_LEN + 1];

    *dialed = w_legacy_name_format(host, port, prefix, scope_id, false);
    *key = w_legacy_name_format(w_legacy_key_host(host, parsed), port, prefix, scope_id, true);
}

void w_legacy_name_target(const char *value, bool is_endpoint, char **dialed, char **key)
{
    char host[AGENT_SERVER_HOST_MAX_LEN + 1];
    char prefix[AGENT_SERVER_ENDPOINT_MAX_LEN + 1];
    int port = DEFAULT_HTTPS_REMOTE_PORT;
    bool port_present = false;
    uint32_t scope_id = 0;

    if (!is_endpoint) {
        w_legacy_name_address(value, DEFAULT_HTTPS_REMOTE_PORT, DEFAULT_AGENT_ENDPOINT_PREFIX, 0, dialed, key);
    } else if (w_parse_agent_endpoint_quiet(value, host, sizeof(host), &port, &port_present, prefix,
                                            sizeof(prefix), &scope_id) == 0) {
        *dialed = w_legacy_name_format(host, port, prefix, scope_id, false);
        *key = w_legacy_name_format(host, port, prefix, scope_id, true);
    } else {
        os_strdup(value, *dialed);
        os_strdup(value, *key);
    }
}

void w_legacy_name_server(const agent_server *server, char **dialed, char **key)
{
    w_legacy_name_address(server->rip, server->port, server->endpoint ? server->endpoint : "",
                          server->scope_id, dialed, key);
}
