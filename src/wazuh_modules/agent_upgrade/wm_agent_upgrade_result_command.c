/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 3, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "wm_agent_upgrade.h"
#include "wazuh_db/wdb.h"

cJSON* wm_agent_process_upgrade_result_command(const cJSON* agents) {
    cJSON* agents_info = wdb_select_agents_version(agents);
    mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_RESULT_AGENT_INFO, cJSON_Print(agents_info));
    const char* agents_info_string = cJSON_Print(agents_info);
    return NULL;
}
