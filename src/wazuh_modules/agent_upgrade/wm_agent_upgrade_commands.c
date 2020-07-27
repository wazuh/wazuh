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

char* wm_agent_upgrade_process_upgrade_command(const int* agent_ids, wm_upgrade_task* task) {
    char* response = NULL;
    cJSON* json_response = cJSON_CreateArray();

    // TODO

    wm_agent_upgrade_create_agents_tasks(json_response, agent_ids, WM_UPGRADE_UPGRADE, (void *)task);

    // TODO

    response = cJSON_PrintUnformatted(json_response);
    cJSON_Delete(json_response);

    return response;
}

char* wm_agent_upgrade_process_upgrade_custom_command(const int* agent_ids, wm_upgrade_custom_task* task) {
    char* response = NULL;
    cJSON* json_response = cJSON_CreateArray();

    // TODO

    wm_agent_upgrade_create_agents_tasks(json_response, agent_ids, WM_UPGRADE_UPGRADE_CUSTOM, (void *)task);

    // TODO

    response = cJSON_PrintUnformatted(json_response);
    cJSON_Delete(json_response);

    return response;
}

char* wm_agent_upgrade_process_upgrade_result_command(const int* agent_ids) {
    char* response = NULL;
    cJSON* json_response = cJSON_CreateArray();
    int agent = 0;
    int agent_id = 0;

    while (agent_id = agent_ids[agent++], agent_id) {

        // TODO: implement upgrade_result command
        cJSON_AddItemToArray(json_response, wm_agent_upgrade_parse_response_message(WM_UPGRADE_SUCCESS, upgrade_results_messages[STATUS_OUTDATED], &agent_id, NULL, upgrade_results_status[STATUS_OUTDATED]));
    }

    response = cJSON_PrintUnformatted(json_response);
    cJSON_Delete(json_response);

    return response;
}
