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
    cJSON* agents_info = wdb_select_agents_version(agents);
    char *agents_info_string = cJSON_Print(agents_info);
    mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_RESULT_AGENT_INFO, agents_info_string);
    os_free(agents_info_string);
    // My version: __ossec_version
    for(int i = 0; i < cJSON_GetArraySize(agents); i++) {
        bool agent_matched = false;
        int agent_id = cJSON_GetArrayItem(agents, i)->valueint;

        for (int j=0; j < cJSON_GetArraySize(agents_info); j++) {
            cJSON *agent_info = cJSON_GetArrayItem(agents_info, j);    
            if (agent_id == cJSON_GetObjectItem(agent_info, "agent_id")->valueint) {
                agent_matched = true;
                // Match in agent
                if (strcmp(cJSON_GetObjectItem(agent_info, "version")->valuestring, __ossec_name " " __ossec_version) == 0) {
                    // Agent updated
                    cJSON_AddItemToArray(response, wm_agent_parse_response_mesage(SUCCESS, "Agent is updated", &agent_id, NULL, "UPDATED"));
                } else {
                    int task_id = wm_agent_task_present(agent_id);
                    if(task_id == -1) {
                        // Agent out of date
                        cJSON_AddItemToArray(response, wm_agent_parse_response_mesage(SUCCESS, "Agent is outdated", &agent_id, NULL, "OUTDATED"));
                    } else {
                        // Agent on update process
                        cJSON_AddItemToArray(response, wm_agent_parse_response_mesage(SUCCESS, "Agent is updating", &agent_id, &task_id, "UPDATING"));
                    }
                    
                }
            }
        }

        if (!agent_matched) {
            cJSON_AddItemToArray(response, wm_agent_parse_response_mesage(AGENT_ID_ERROR, "Agent id not present in database", &agent_id, NULL, "ERROR"));
        }   
        
    }
    cJSON_Delete(agents_info);

    char *response_string = cJSON_Print(response);
    mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_RESULT_SHOW_RESULTS, response_string);
    os_free(response_string);

    return response;
}
