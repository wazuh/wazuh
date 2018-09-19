/*
 * Authd settings manager
 * Copyright (C) 2017 Wazuh Inc.
 * May 29, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "auth.h"
#include "config/config.h"

// Read configuration
int authd_read_config(const char *path) {
    config.port = DEFAULT_PORT;
    config.force_time = -1;
    config.flags.register_limit = 1;

    mdebug2("Reading configuration '%s'", path);

    if (ReadConfig(CAUTHD, path, &config, NULL) < 0) {
        return OS_INVALID;
    }

    if (!config.flags.force_insert) {
        config.force_time = -1;
    }

    if (!config.ciphers) {
        config.ciphers = strdup(DEFAULT_CIPHERS);
    }

    config.timeout_sec = getDefine_Int("auth", "timeout_seconds", 0, INT_MAX);
    config.timeout_usec = getDefine_Int("auth", "timeout_microseconds", 0, 999999);

    return 0;
}
