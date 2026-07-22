/*
 * Wazuh agent HTTPS client bridge (development scaffold)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * Wires the C++ https_client module (src/client-agent/https_client) into
 * agentd behind an internal-option gate. This is a DEVELOPMENT SCAFFOLD: it
 * is off by default and runs INDEPENDENTLY of the legacy TCP path, so the
 * agent keeps working exactly as before unless a developer opts in with
 *
 *     agent.https_client=1
 *
 * in etc/local_internal_options.conf. The real configuration surface (the
 * <server>/<ssl>/<batch> XML parser) and the callback hookups into the
 * existing dispatch handlers are separate workstreams of #37702; here the
 * config is derived from the already-parsed client.keys and <client> block,
 * and the received-work callbacks are debug stubs.
 */

#include "https_client_bridge.h"

#include "agentd.h" /* pulls defs.h (__wazuh_version), sec.h (keys), client-config.h (agt) */
#include "https_client.h"

static hc_handle *g_https_client = NULL;

/* Received-work callbacks: debug stubs for the scaffold. The production
 * hookups (execd / module com / restart handlers, the .state metrics and the
 * startup gate) land with the integration workstream. */
static void bridge_on_reenroll_required(void *user_data)
{
    /* Production hookup (later integration workstream): run the authd re-
     * enrollment (start_agent.c try_enroll_to_server, 5 retries as before)
     * and call hc_set_agent_key() with the new client.keys value. The dev
     * scaffold only logs; the module has paused all traffic until then. */
    (void)user_data;
    mwarn("https_client: credential rejected (401); re-enrollment required.");
}

static void bridge_on_state_change(int state, void *user_data)
{
    (void)user_data;
    mdebug1("https_client connection state -> %d", state);
}

/* Builds the module config from the already-available agent state. The raw
 * client.keys value is passed through and the module's key provider validates
 * it (AES-128/192/256-CMAC by byte length), so a non-conforming key simply
 * prevents signing (the scaffold stays inert). */
static void bridge_build_config(hc_config_t *config)
{
    memset(config, 0, sizeof(*config));

    if (agt->server && agt->server[0].rip) {
        strncpy(config->server_host, agt->server[0].rip, sizeof(config->server_host) - 1);
        config->server_port = (uint16_t)agt->server[0].port;
    }
    if (keys.keyentries && keys.keyentries[0]) {
        if (keys.keyentries[0]->id) {
            strncpy(config->agent_id, keys.keyentries[0]->id, sizeof(config->agent_id) - 1);
        }
        if (keys.keyentries[0]->raw_key) {
            strncpy(config->agent_key, keys.keyentries[0]->raw_key, sizeof(config->agent_key) - 1);
        }
    }

    /* Dev scaffold: no CA is configurable before the parser exists, so TLS
     * verification is explicitly disabled here. The parser workstream flips
     * this to full verification against the configured certificate_authorities. */
    config->verify_mode = HC_VERIFY_NONE;
    mwarn("https_client: TLS verification DISABLED (development scaffold; no CA configured).");
}

void w_https_client_start(void)
{
    int enabled = getDefine_Int_default("agent", "https_client", 0, 1, 0);
    if (!enabled) {
        return; /* Off by default; the legacy transport is untouched. */
    }

    minfo("https_client: development scaffold enabled (agent.https_client=1).");

    hc_config_t config;
    bridge_build_config(&config);

    hc_callbacks_t callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.log = mtLoggingFunctionsWrapper;
    callbacks.on_reenroll_required = bridge_on_reenroll_required;
    callbacks.on_state_change = bridge_on_state_change;

    g_https_client = hc_create(&config, &callbacks);
    if (!g_https_client) {
        merror("https_client: failed to create the client instance.");
        return;
    }
    if (!hc_start(g_https_client)) {
        merror("https_client: failed to start (configuration rejected).");
        hc_destroy(g_https_client);
        g_https_client = NULL;
    }
}

void w_https_client_stop(void)
{
    if (g_https_client) {
        hc_destroy(g_https_client); /* Implies stop + join. */
        g_https_client = NULL;
    }
}
