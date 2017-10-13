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
    int min_eps;

    agt->server = NULL;
    agt->lip = NULL;
    agt->rip_id = 0;
    agt->execdq = 0;
    agt->profile = NULL;
    agt->buffer = 1;
    agt->buflength = 5000;
    agt->events_persec = 500;
    agt->flags.auto_restart = 1;

    os_calloc(1, sizeof(wlabel_t), agt->labels);
    modules |= CCLIENT;

    if (ReadConfig(modules, cfgfile, agt, NULL) < 0 ||
        ReadConfig(CLABELS | CBUFFER, cfgfile, &agt->labels, agt) < 0) {
        return (OS_INVALID);
    }

#ifdef CLIENT
    ReadConfig(CLABELS | CBUFFER | CAGENT_CONFIG, AGENTCONFIG, &agt->labels, agt);
#endif

    if (min_eps = getDefine_Int("agent", "min_eps", 1, 1000), agt->events_persec < min_eps) {
        mwarn("Client buffer throughput too low: set to %d eps", min_eps);
        agt->events_persec = min_eps;
    }

    return (1);
}
