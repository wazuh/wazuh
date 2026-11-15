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
#include "legacy-server-targets.h"

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

/* Read <enrollment> unless <agent> already supplied it. Skipped, rather than merged: the
 * two are one block under two names, and an identity assembled from both is not one an
 * operator wrote. A legacy block listed first still stands for whatever an <agent> one
 * below it leaves unset, the same way repeated <agent><enrollment> blocks resolve. */
static int w_read_legacy_enrollment(const OS_XML *xml, xml_node *enrollment, agent *logr)
{
    XML_NODE chld_node = NULL;
    int ret = 0;

    if (logr->enrollment.set_under_agent) {
        mwarn("<enrollment> inside the legacy <client> block is ignored: <agent> "
              "already supplies it. Keep the identity in one of the two blocks.");
        return 0;
    }

    if ((chld_node = OS_GetElementsbyNode(xml, enrollment))) {
        ret = Read_Agent_Enrollment(chld_node, logr);
        OS_ClearNode(chld_node);
    }

    return ret;
}

/* Collect the <address> and <endpoint> of one <server>, as written. The MSI reconfigures
 * a preserved 4.x file in place and, having no <agent> block to target, writes the
 * endpoint into a <server> one: reading only <address> left that agent with no manager. */
static void w_collect_legacy_server(const OS_XML *xml, xml_node *server, w_legacy_targets_t *targets)
{
    XML_NODE chld_node = OS_GetElementsbyNode(xml, server);

    for (int j = 0; chld_node && chld_node[j]; j++) {
        if (!chld_node[j]->element || !chld_node[j]->content) {
            continue;
        }

        if (strcmp(chld_node[j]->element, "address") == 0) {
            w_legacy_targets_add(targets, chld_node[j]->content, false);
        } else if (strcmp(chld_node[j]->element, "endpoint") == 0) {
            w_legacy_targets_add(targets, chld_node[j]->content, true);
        }
    }

    OS_ClearNode(chld_node);
}

/* <enrollment> is read, <server> targets are collected, anything else is warned about.
 * Stops at the first error. */
static int w_read_legacy_children(const OS_XML *xml, XML_NODE node, agent *logr,
                                  w_legacy_targets_t *targets)
{
    int ret = 0;

    for (int i = 0; node[i] && ret == 0; i++) {
        if (!node[i]->element) {
            continue;
        } else if (strcmp(node[i]->element, "enrollment") == 0) {
            ret = w_read_legacy_enrollment(xml, node[i], logr);
        } else if (strcmp(node[i]->element, "server") == 0) {
            w_collect_legacy_server(xml, node[i], targets);
        } else {
            w_warn_legacy_client_option(node[i]->element);
        }
    }

    return ret;
}

/**
 * @brief Read the two things still wanted from a 4.x <client> block: the manager
 *        under <server>, and the whole <enrollment> sub-block.
 *
 * A WPK upgrade never rewrites ossec.conf, so a 5.x agent can start against a file that
 * only has <client>. The <server> targets are recorded on the agent configuration and
 * settled once the whole file is read (Settle_Legacy_Client()), so <agent> wins wherever
 * it sits. <enrollment> is read because it carries the agent's identity, which has no 5.x
 * replacement inside the legacy block: dropping it makes the agent re-register under its
 * hostname with no groups. Every other direct child
 * is ignored, and says so, since the block is 4.x's and its options are not. <server>'s
 * own children other than <address> and <endpoint> stay silent: neither <port> nor
 * <protocol> is read, and the message printed for the address already names the port in
 * use and a copy-pasteable replacement for the whole block.
 */
int Read_Legacy_Client(const OS_XML *xml, XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    agent *logr = (agent *)d1;

    if (!logr->legacy_targets) {
        os_calloc(1, sizeof(w_legacy_targets_t), logr->legacy_targets);
    }

    if (w_read_legacy_children(xml, node, logr, logr->legacy_targets) < 0) {
        return OS_INVALID;
    }

    w_legacy_targets_end_block(logr->legacy_targets);
    return 0;
}
