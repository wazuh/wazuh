/*
 * Authd settings manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 29, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "auth.h"
#include "config.h"
#include "mconf-config.h"

// Read configuration
int authd_read_config(const char *path) {
    config.port = DEFAULT_PORT;
    config.allow_higher_versions = AUTHD_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT;

    mdebug2("Reading configuration '%s'", path);

    /* etc/wazuh-manager.yml: loaded once per process, then the `auth` section as cJSON (mconf-config.h). */
    if (w_mconf_load(path) < 0) {
        return OS_INVALID;
    }

    {
        cJSON *auth = w_mconf_section("auth");
        int ret = Read_Authd_JSON(auth, &config);
        cJSON_Delete(auth);

        if (ret < 0) {
            return OS_INVALID;
        }
    }

    if (!config.ciphers) {
        config.ciphers = strdup(DEFAULT_CIPHERS);
    }

    switch (config.flags.disabled) {
    case AD_CONF_UNPARSED:
        config.flags.disabled = 1;
        break;
    case AD_CONF_UNDEFINED:
        config.flags.disabled = 0;
    }

    config.timeout_sec = getDefine_Int_default("auth", "timeout_seconds", 0, INT_MAX, 1);
    config.timeout_usec = getDefine_Int_default("auth", "timeout_microseconds", 0, 999999, 0);
    config.max_agents = (unsigned int)getDefine_Int_default("authd", "max_agents", 0, INT_MAX, 0);
    /* How long a deletion waits before its indexer purge is relayed. The default is picked from the
     * three intervals it has to outlast, not guessed:
     *   - the index refresh (~1 s): a delete-by-query is a SEARCH, so it cannot match documents the
     *     indexer has not made searchable yet;
     *   - the cluster integrity sync (9 s): until a worker pulls the new client.keys it keeps
     *     accepting that agent's data and writing it;
     *   - the master's keepalive tolerance (120 s): the longest a worker can be out of touch and
     *     still be considered alive, so the longest it can legitimately be behind.
     * Whatever the purge misses survives forever -- with the agent gone, nothing overwrites it --
     * so the default covers the widest of the three. A single-node manager only needs the first and
     * can lower this a lot; 0 (immediate) exists for tests. */
    config.purge_delay = getDefine_Int_default("authd", "purge_delay", 0, 3600, 120);

    return 0;
}

/* getconfig "auth": the effective `auth` section of etc/wazuh-manager.yml (schema defaults applied,
 * native types), exactly what authd_read_config() loaded. The internal options authd reads on top of it
 * (auth.timeout_*, authd.max_agents, authd.purge_delay) are not configuration-file options and are not
 * reported here. */
cJSON *getAuthdConfig(void) {
    cJSON *root = cJSON_CreateObject();
    cJSON *auth = w_mconf_section("auth");

    cJSON_AddItemToObject(root, "auth", auth != NULL ? auth : cJSON_CreateObject());
    return root;
}
