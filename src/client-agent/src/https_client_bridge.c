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
 * agentd behind an internal-option gate. It is off by default and runs
 * INDEPENDENTLY of the legacy TCP path, so the agent keeps working exactly
 * as before unless a developer opts in with
 *
 *     agent.https_client=1
 *
 * in etc/local_internal_options.conf.
 *
 * The config surface (<server>/<ssl>, parsed by Read_Client/Read_Client_SSL
 * in src/config/src/client-config.c) and the real TLS wiring are done: the
 * module's own fail-closed validation (ModuleConfig::validateTls) now gets a
 * real verify_mode/CA/cert/key/ciphers instead of a forced HC_VERIFY_NONE.
 * Still pending (later integration workstreams of #37702): the
 * on_reenroll_required hookup into authd re-enrollment, the .state metrics,
 * and removing the internal-option gate once the legacy TCP path is retired.
 */

#include "https_client_bridge.h"

#include <ctype.h>

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

/* Maps the agent config parser's verification_mode enum onto the module
 * ABI's hc_verify_mode_t. The two are defined in independent headers with
 * matching values by convention (both documented "FULL is 0, fails closed");
 * an explicit switch (instead of relying on the numeric coincidence) keeps
 * that convention from silently breaking if either enum is reordered. */
static int bridge_map_verify_mode(int agent_verify_mode)
{
    switch (agent_verify_mode) {
    case AGENT_VERIFY_CERT:
        return HC_VERIFY_CERT;
    case AGENT_VERIFY_NONE:
        return HC_VERIFY_NONE;
    case AGENT_VERIFY_FULL:
    default:
        return HC_VERIFY_FULL;
    }
}

/* The AES-CMAC recipe (settled by the manager's resolver, PR #37821): decode
 * client.keys' raw_key verbatim as hex, cipher chosen by byte length
 * (16/24/32 bytes = 32/48/64 hex chars). The module's key provider re-derives
 * the same check lazily at signing time (so a bad key never crashes
 * anything), but that means a misconfigured key otherwise fails every
 * request silently forever with no startup error. Validate it here so a
 * broken client.keys is caught once, loudly, at start. */
static bool bridge_key_is_valid(const char *raw_key)
{
    if (!raw_key) {
        return false;
    }

    size_t len = strlen(raw_key);
    if (len != 32 && len != 48 && len != 64) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)raw_key[i])) {
            return false;
        }
    }

    return true;
}

/* Builds the module config from the parsed <server>/<ssl> block (agt->server,
 * agt->ssl; src/config/src/client-config.c) and the already-parsed
 * client.keys entry. Returns false (config left unusable) when the signing
 * key fails validation; the caller must not start the client in that case. */
static bool bridge_build_config(hc_config_t *config)
{
    memset(config, 0, sizeof(*config));

    if (agt->server && agt->server[0].rip) {
        strncpy(config->server_host, agt->server[0].rip, sizeof(config->server_host) - 1);
        config->server_port = (uint16_t)agt->server[0].port;
    }

    const char *raw_key = (keys.keyentries && keys.keyentries[0]) ? keys.keyentries[0]->raw_key : NULL;
    if (!bridge_key_is_valid(raw_key)) {
        merror("https_client: agent key is missing or has an invalid length for AES-CMAC "
               "(expected 32, 48 or 64 hex characters); refusing to start.");
        return false;
    }
    if (keys.keyentries[0]->id) {
        strncpy(config->agent_id, keys.keyentries[0]->id, sizeof(config->agent_id) - 1);
    }
    strncpy(config->agent_key, raw_key, sizeof(config->agent_key) - 1);

    config->verify_mode = bridge_map_verify_mode(agt->ssl.verification_mode);
    if (agt->ssl.certificate_authorities) {
        strncpy(config->ca_path, agt->ssl.certificate_authorities, sizeof(config->ca_path) - 1);
    }
    if (agt->ssl.certificate) {
        strncpy(config->client_cert, agt->ssl.certificate, sizeof(config->client_cert) - 1);
    }
    if (agt->ssl.key) {
        strncpy(config->client_key, agt->ssl.key, sizeof(config->client_key) - 1);
    }
    if (agt->ssl.ciphers) {
        strncpy(config->ciphers, agt->ssl.ciphers, sizeof(config->ciphers) - 1);
    }

    return true;
}

void w_https_client_start(void)
{
    int enabled = getDefine_Int_default("agent", "https_client", 0, 1, 0);
    if (!enabled) {
        return; /* Off by default; the legacy transport is untouched. */
    }

    minfo("https_client: enabled (agent.https_client=1).");

    hc_config_t config;
    if (!bridge_build_config(&config)) {
        return; /* bridge_build_config already logged the reason. */
    }

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
