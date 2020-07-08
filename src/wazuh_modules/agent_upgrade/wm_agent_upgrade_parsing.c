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

wm_upgrade_task* wm_agent_parse_upgrade_command(const char* buffer, char* output) {
    cJSON * root = cJSON_Parse(buffer);
    wm_upgrade_task *task = init_upgrade_task();

    if (!root) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, "Cannot parse JSON: %s",  buffer);
        sprintf(output, "%s", "Cannot parse JSON message");
        task->state = ERROR;
    } else {
        cJSON *params = cJSON_GetObjectItem(root, "params");
        task->command = cJSON_GetObjectItem(root, "command")->valuestring;
        int param_index = 0;
        while((task->state != ERROR) && (param_index < cJSON_GetArraySize(params))) {
            cJSON *item = cJSON_GetArrayItem(params, param_index++);
            if (strcmp(item->string, "file_path") == 0) {
                /* File_path */
                if ( item->type == cJSON_String) {
                    task->custom_file_path = strdup(item->valuestring);
                } else {
                    sprintf(output, "Parameter \"%s\" should be a string", item->string);
                    task->state = ERROR;
                }
            } else if(strcmp(item->string, "installer") == 0) {
                /* Installer */
                if ( item->type == cJSON_String) {
                    task->custom_installer = strdup(item->valuestring);
                } else {
                    sprintf(output, "Parameter \"%s\" should be a string", item->string);
                    task->state = ERROR;
                }
            } else if(strcmp(item->string, "wpk_repo") == 0) {
                /* wpk repo */
                if ( item->type == cJSON_String) {
                    task->wpk_repository = strdup(item->valuestring);
                } else {
                    sprintf(output, "Parameter \"%s\" should be a string", item->string);
                    task->state = ERROR;
                }
            } else if(strcmp(item->string, "version") == 0) {
                /* version */
                if ( item->type == cJSON_String) {
                    task->custom_version = strdup(item->valuestring);
                } else {
                    sprintf(output, "Parameter \"%s\" should be a string", item->string);
                    task->state = ERROR;
                }
            } else if(strcmp(item->string, "use_http") == 0) {
                /* use_http */
                if (item->valueint == 1) {
                    task->use_http = true;
                } else if(item->valueint == 0) {
                    task->use_http = false;
                } else {
                    sprintf(output, "Parameter \"%s\" should be either true or false", item->string);
                    task->state = ERROR;
                }
            } else if(strcmp(item->string, "force_upgrade") == 0) {
                if(item->valueint == 0) {
                    task->force_upgrade = false;
                } else if(item->valueint == 1) {
                    task->force_upgrade = true;
                } else {
                    sprintf(output, "Parameter \"%s\" can take only values [0, 1]", item->string);
                    task->state = ERROR;
                }
            }
        }
        cJSON_Delete(root);
    }
    return task;
}

char* wm_agent_parse_response_mesage(enum wm_upgrade_state state, const char* message) {
    cJSON * response = cJSON_CreateObject();
    switch (state)
    {
    case STARTED:
        cJSON_AddNumberToObject(response, "error", 0);
        break;
    default:
        cJSON_AddNumberToObject(response, "error", 1);
        break;
    }
    cJSON_AddStringToObject(response, "data", message);
    char *response_str = cJSON_Print(response);
    cJSON_Delete(response);
    return response_str;
}
