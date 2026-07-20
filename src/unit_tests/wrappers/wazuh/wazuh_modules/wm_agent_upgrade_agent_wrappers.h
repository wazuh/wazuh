/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WM_AGENT_UPGRADE_AGENT_WRAPPERS_H
#define WM_AGENT_UPGRADE_AGENT_WRAPPERS_H

#include "shared.h"
#include "wm_agent_upgrade_agent.h"
#include "wmodules.h"

void __wrap_wm_agent_upgrade_start_agent_module(const wm_agent_configs* agent_config, const int enabled);

size_t __wrap_wm_agent_upgrade_process_command(const char* buffer, char** output);

#endif
