/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"
#include "os_net/os_net.h"
#include "agentd.h"

/* Global variables */
time_t available_server;
int run_foreground;
keystore keys;
agent *agt;


/* Read the config file (for the remote client) */
int ClientConf(const char *cfgfile)
{
    int modules = 0;
    agt->port = DEFAULT_SECURE;
    agt->rip = NULL;
    agt->lip = NULL;
    agt->rip_id = 0;
    agt->execdq = 0;
    agt->profile = NULL;

    modules |= CCLIENT;

    if (ReadConfig(modules, cfgfile, agt, NULL) < 0) {
        return (OS_INVALID);
    }

    return (1);
}

