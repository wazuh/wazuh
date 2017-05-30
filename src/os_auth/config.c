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

    debug2("%s: debug: Reading configuration '%s'", __local_name, path);

    if (ReadConfig(CAUTHD, path, &config, NULL) < 0) {
        return OS_INVALID;
    }

    return 0;
}
