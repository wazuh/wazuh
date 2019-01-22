/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _AGENTLESSD_H
#define _AGENTLESSD_H

#include "config/agentlessd-config.h"

#ifndef ARGV0
#define ARGV0 "ossec-agentlessd"
#endif

/** Prototypes **/

/* Main monitord */
void Agentlessd(void) __attribute__((noreturn));

// Read config
cJSON *getAgentlessConfig(void);
size_t lessdcom_dispatch(char * command, char ** output);
size_t lessdcom_getconfig(const char * section, char ** output);
void * lessdcom_main(__attribute__((unused)) void * arg);

/* Global variables */
extern agentlessd_config lessdc;

#endif
