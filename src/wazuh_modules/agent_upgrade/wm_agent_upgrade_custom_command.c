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
#include "wazuh_modules/wmodules.h"
#include "wm_agent_upgrade.h"
#include "wm_agent_parsing.h"
#include "wm_agent_upgrade_tasks.h"
#include "os_net/os_net.h"

cJSON *wm_agent_upgrade_process_upgrade_custom_command(const cJSON* params, const cJSON* agents) {
    cJSON *json_api = NULL;
    char *output = NULL;
    wm_upgrade_custom_task *task = NULL;
    os_calloc(OS_MAXSTR, sizeof(char), output);
    task = wm_agent_upgrade_parse_upgrade_custom_command(params, output);
    if (!task) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMMAND_PARSE_ERROR, output);
        json_api = wm_agent_upgrade_parse_response_message(WM_UPGRADE_TASK_CONFIGURATIONS, output, NULL, NULL, NULL);
    } else {
        json_api = wm_agent_upgrade_create_agent_tasks(agents, task, WM_UPGRADE_UPGRADE_CUSTOM);
    }
    os_free(output);
    return json_api;
}
