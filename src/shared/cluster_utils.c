/*
 * URL download support library
 * Copyright (C) 2018 Wazuh Inc.
 * October 26, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "../config/config.h"
#include "../config/global-config.h"

int w_is_worker(){

    const char *cfgfile = DEFAULTCPATH;
    int modules = 0;
    int is_worker = 0;
    _Config cfg;

    modules |= CCLUSTER;

    if (ReadConfig(modules, cfgfile, &cfg, NULL) < 0) {
        return (OS_INVALID);
    }
    is_worker = !strncmp(cfg.node_type, "worker", 6) ? 1 : 0;

    return is_worker;
}