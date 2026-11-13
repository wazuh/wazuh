/* Copyright (C) Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* The 4.x <client> block, still read on an upgraded agent for the manager address and
 * the enrollment identity (#38103). The 5.x <agent> block is read in client-config.c. */

#include "shared.h"
#include "client-config.h"
#include "config.h"

/* Direct children of a 4.x <client> block that 5.x reads under <agent> instead. */
static const char * LEGACY_CLIENT_MOVED_OPTIONS[] = {
    "config-profile", "notify_time", "auto_restart", "disable-active-response", NULL
};

/**
 * @brief Report a <client> child that is read from neither <server> nor <enrollment>.
 *
 * A warning rather than info: on an upgraded agent this is a setting that used to apply
 * and silently stopped. The message never advises renaming the block, because <server>
 * and a bare <port> are rejected under <agent> - that advice would leave a configuration
 * that no longer starts.
 */
static void w_warn_legacy_client_option(const char *option)
{
    for (int i = 0; LEGACY_CLIENT_MOVED_OPTIONS[i]; i++) {
        if (strcmp(option, LEGACY_CLIENT_MOVED_OPTIONS[i]) == 0) {
            mwarn("<%s> inside the legacy <client> block is ignored. Configure it under <agent>.", option);
            return;
        }
    }

    mwarn("<%s> inside the legacy <client> block is ignored: only <server> and <enrollment> "
          "are read from it.", option);
}

/**
 * @brief Read the two things still wanted from a 4.x <client> block: the manager
 *        address under <server>, and the whole <enrollment> sub-block.
 *
 * A WPK upgrade never rewrites ossec.conf, so a 5.x agent can start against a file that
 * only has <client>. The address is taken when <agent> did not already provide one - so
 * <agent> wins whichever block comes first - and <enrollment> is read because it carries
 * the agent's identity, which has no 5.x replacement inside the legacy block: dropping it
 * makes the agent re-register under its hostname with no groups. Every other direct child
 * is ignored, and says so, since the block is 4.x's and its options are not. <server>'s
 * own children stay silent: neither <port> nor <protocol> is read, and the message printed
 * for the address already names the port in use and a copy-pasteable replacement for the
 * whole block.
 *
 * Repeated addresses resolve the same way as under <agent>: the last one prevails
 */
int Read_Legacy_Client(const OS_XML *xml, XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    const char *xml_client_server = "server";
    const char *xml_client_addr = "address";
    const char *xml_client_endpoint = "endpoint";
    const char *xml_client_enrollment = "enrollment";
    char * address = NULL;
    char * endpoint_value = NULL;

    agent * logr = (agent *)d1;

    /* Captured once rather than returned on, so the block is still walked for its
     * <enrollment> child. <server> is then skipped whole instead of parsed and
     * discarded, so a malformed legacy <endpoint> cannot fail a configuration that
     * is not using it. */
    const bool address_taken = (logr->server != NULL);

    for (int i = 0; node[i]; i++) {
        XML_NODE chld_node = NULL;

        if (!node[i]->element) {
            continue;
        }

        if (strcmp(node[i]->element, xml_client_enrollment) == 0) {
            /* Skipped, rather than merged, once <agent> supplied this block: the two
             * are one block under two names, and an identity assembled from both is
             * not one an operator wrote. A legacy block listed first still stands for
             * whatever an <agent> one below it leaves unset, the same way repeated
             * <agent><enrollment> blocks resolve. */
            if (logr->enrollment.set_under_agent) {
                mwarn("<enrollment> inside the legacy <client> block is ignored: <agent> "
                      "already supplies it. Keep the identity in one of the two blocks.");
                continue;
            }

            if ((chld_node = OS_GetElementsbyNode(xml, node[i]))) {
                if (Read_Agent_Enrollment(chld_node, logr) < 0) {
                    OS_ClearNode(chld_node);
                    os_free(address);
                    os_free(endpoint_value);
                    return (OS_INVALID);
                }

                OS_ClearNode(chld_node);
            }

            continue;
        }

        if (strcmp(node[i]->element, xml_client_server) != 0) {
            w_warn_legacy_client_option(node[i]->element);
            continue;
        }

        if (address_taken) {
            continue;
        }

        if (!(chld_node = OS_GetElementsbyNode(xml, node[i]))) {
            continue;
        }

        for (int j = 0; chld_node[j]; j++) {
            if (!chld_node[j]->element || !chld_node[j]->content) {
                continue;
            }

            if (strcmp(chld_node[j]->element, xml_client_addr) == 0) {
                os_free(address);
                os_strdup(chld_node[j]->content, address);
            } else if (strcmp(chld_node[j]->element, xml_client_endpoint) == 0) {
                /* The MSI reconfigures a preserved 4.x file in place and, having no
                 * <agent> block to target, writes the endpoint into this <server> one.
                 * Reading only <address> here left that agent with no manager at all. */
                os_free(endpoint_value);
                os_strdup(chld_node[j]->content, endpoint_value);
            }
        }

        OS_ClearNode(chld_node);
    }

    /* An <endpoint> written here by the installer carries the whole target, so it wins
     * and is parsed exactly as one under <agent><manager> would be. */
    if (endpoint_value) {
        char host[AGENT_SERVER_HOST_MAX_LEN + 1] = {'\0'};
        char endpoint[AGENT_SERVER_ENDPOINT_MAX_LEN + 1] = {'\0'};
        uint32_t scope_id = 0;
        int port = DEFAULT_HTTPS_REMOTE_PORT;
        bool port_present = false;

        if (w_parse_agent_endpoint(endpoint_value, host, sizeof(host), &port, &port_present,
                                   endpoint, sizeof(endpoint), &scope_id) == OS_INVALID) {
            os_free(address);
            os_free(endpoint_value);
            return (OS_INVALID);
        }

        os_free(address);
        os_free(endpoint_value);

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

        return (0);
    }

    if (!address) {
        return (0);
    }

    os_calloc(2, sizeof(agent_server), logr->server);
    logr->server[0].rip = address;
    if (strchr(logr->server[0].rip, ':') != NULL) {
        os_realloc(logr->server[0].rip, IPSIZE + 1, logr->server[0].rip);
        OS_ExpandIPv6(logr->server[0].rip, IPSIZE);
    }
    logr->server[0].port = DEFAULT_HTTPS_REMOTE_PORT;
    /* 4.x had no <endpoint> concept at all -- any <port> under this legacy
     * <client><server> block was never read either (see this function's own
     * docstring), so a WPK-upgraded agent always reconnects on the 5.x HTTPS
     * port with the manager's default reverse-proxy prefix, never the old
     * 4.x port or unprefixed requests. */
    os_strdup(DEFAULT_AGENT_ENDPOINT_PREFIX, logr->server[0].endpoint);
    logr->server_count = 1;

    /* A 4.x file has no <endpoint> at all, so say exactly what to write -- this is the
     * upgrade path most likely to be edited by hand, and a copy-pasteable line is the
     * whole point. The composed value is the one now in use, so pasting it changes
     * nothing about where the agent connects. */
    minfo("<agent><manager><endpoint> is not configured. Using <client><server><address> '%s' "
          "with the default port %d and the default endpoint prefix '%s'. Replace the "
          "<client><server> block with a single <endpoint>%s%s%s:%d/%s</endpoint>",
          logr->server[0].rip, DEFAULT_HTTPS_REMOTE_PORT, DEFAULT_AGENT_ENDPOINT_PREFIX,
          (strchr(logr->server[0].rip, ':') != NULL) ? "[" : "",
          logr->server[0].rip,
          (strchr(logr->server[0].rip, ':') != NULL) ? "]" : "",
          DEFAULT_HTTPS_REMOTE_PORT, DEFAULT_AGENT_ENDPOINT_PREFIX);

    return (0);
}
