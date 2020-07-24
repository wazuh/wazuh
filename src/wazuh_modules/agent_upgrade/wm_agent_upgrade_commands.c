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
#include "wm_agent_upgrade_parsing.h"
#include "wm_agent_upgrade_tasks.h"
#include "os_net/os_net.h"

typedef enum _upgrade_results_codes {
    STATUS_UPDATED = 0,
    STATUS_UPDATING,
    STATUS_OUTDATED,
    STATUS_ERROR
} upgrade_results_codes;

static const char* upgrade_results_status[] = {
    [STATUS_UPDATED] = "UPDATED",
    [STATUS_UPDATING] = "UPDATING",
    [STATUS_OUTDATED] = "OUTDATED",
    [STATUS_ERROR]    = "ERROR"
};

static const char* upgrade_results_messages[] = {
    [STATUS_UPDATED]  = "Agent is updated",
    [STATUS_UPDATING] = "Agent is updating",
    [STATUS_OUTDATED] = "Agent is outdated",
    [STATUS_ERROR]    = "Agent upgrade process failed"
};

cJSON* wm_agent_upgrade_process_upgrade_command(const cJSON* agents, wm_upgrade_task* task) {
    cJSON *json_api = NULL;
    wm_agent_task *agent_task = NULL;

    agent_task = wm_agent_upgrade_init_agent_task();
    agent_task->agent_info = wm_agent_upgrade_init_agent_info();
    agent_task->task_info = wm_agent_upgrade_init_task_info();

    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = task;

    json_api = wm_agent_upgrade_create_agents_tasks(agents, agent_task->task_info);

    wm_agent_upgrade_free_agent_task(agent_task);

    return json_api;
}

cJSON* wm_agent_upgrade_process_upgrade_custom_command(const cJSON* agents, wm_upgrade_custom_task* task) {
    cJSON *json_api = NULL;
    wm_agent_task *agent_task = NULL;

    agent_task = wm_agent_upgrade_init_agent_task();
    agent_task->agent_info = wm_agent_upgrade_init_agent_info();
    agent_task->task_info = wm_agent_upgrade_init_task_info();

    agent_task->task_info->command = WM_UPGRADE_UPGRADE_CUSTOM;
    agent_task->task_info->task = task;

    json_api = wm_agent_upgrade_create_agents_tasks(agents, agent_task->task_info);

    wm_agent_upgrade_free_agent_task(agent_task);

    return json_api;
}

cJSON* wm_agent_upgrade_process_upgrade_result_command(const cJSON* agents) {
    cJSON* response = cJSON_CreateArray();
    for(int i = 0; i < cJSON_GetArraySize(agents); i++) {
        int agent_id = cJSON_GetArrayItem(agents, i)->valueint;

        // TODO: implement upgrade_result command
        cJSON_AddItemToArray(response, wm_agent_upgrade_parse_response_message(WM_UPGRADE_SUCCESS, upgrade_results_messages[STATUS_OUTDATED], &agent_id, NULL, upgrade_results_status[STATUS_OUTDATED]));
    }
    char *response_string = cJSON_PrintUnformatted(response);
    mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_RESULT_SHOW_RESULTS, response_string);
    os_free(response_string);

    return response;
}
