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
#include "wm_agent_parsing.h"
#include "wm_agent_upgrade_tasks.h"
#include "wazuh_db/wdb.h"

cJSON* wm_agent_process_upgrade_result_command(const cJSON* agents) {
    cJSON* response = cJSON_CreateArray();
    for(int i = 0; i < cJSON_GetArraySize(agents); i++) {
        int agent_id = cJSON_GetArrayItem(agents, i)->valueint;

        int task_id = wm_agent_task_present(agent_id);
        if(task_id == -1) {
            // TODO: Agent could be updated, we need to ask the task manager, or there could be some error @WIP
            //cJSON_AddItemToArray(response, wm_agent_parse_response_mesage(SUCCESS, "Agent is updated", &agent_id, NULL, "UPDATED"));
            // cJSON_AddItemToArray(response, wm_agent_parse_response_mesage(AGENT_ID_ERROR, upgrade_error_codes[AGENT_ID_ERROR], &agent_id, NULL, "ERROR"));
            // Agent out of date
            cJSON_AddItemToArray(response, wm_agent_parse_response_mesage(SUCCESS, "Agent is outdated", &agent_id, NULL, "OUTDATED"));
        } else {
            // Agent on update process
            cJSON_AddItemToArray(response, wm_agent_parse_response_mesage(SUCCESS, "Agent is updating", &agent_id, &task_id, "UPDATING"));
        }   
    }

    char *response_string = cJSON_Print(response);
    mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_RESULT_SHOW_RESULTS, response_string);
    os_free(response_string);

    return response;
}
