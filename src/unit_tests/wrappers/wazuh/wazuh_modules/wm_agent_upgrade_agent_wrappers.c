/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "wm_agent_upgrade_agent_wrappers.h"

void __wrap_wm_agent_upgrade_start_agent_module(const wm_agent_configs* agent_config) {
    // This methods should also be wrapped
    wm_agent_upgrade_listen_messages();
    wm_agent_upgrade_check_status(agent_config);
}
