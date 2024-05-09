/*
 * Utils Agent Messages Adapter
 * Copyright (C) 2015, Wazuh Inc.
 * Dec 29, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "agent_messages_adapter.h"
#include "cJSON.h"
#include "defs.h"
#include <stdbool.h>

void *agent_data_hash_duplicator(void* data) {
    return cJSON_Duplicate((cJSON*)data, true);
}

char* adapt_delta_message(const char* data, const char* name, const char* id, const char* ip, const OSHash *agent_data_hash) {
    cJSON* j_msg_to_send = NULL;
    cJSON* j_agent_info = NULL;
    cJSON* j_msg = NULL;
    cJSON* j_agent_data = NULL;
    char* msg_to_send = NULL;

    j_msg = cJSON_Parse(data);
    if (!j_msg) {
        return NULL;
    } else {
        // Legacy agents prior to 4.2 used a different message format that isn't supported
        if (cJSON_GetObjectItem(j_msg, "ID") && cJSON_GetObjectItem(j_msg, "timestamp")) {
            cJSON_Delete(j_msg);
            return NULL;
        }
    }

    j_msg_to_send = cJSON_CreateObject();

    j_agent_info = cJSON_CreateObject();

    cJSON_AddStringToObject(j_agent_info, "agent_id", id);
    cJSON_AddStringToObject(j_agent_info, "agent_ip", ip);
    cJSON_AddStringToObject(j_agent_info, "agent_name", name);

    if (NULL != agent_data_hash) {
        // Getting agent context
        j_agent_data = OSHash_Get_ex_dup(agent_data_hash, id, agent_data_hash_duplicator);
        if (cJSON_IsString(cJSON_GetObjectItem(j_agent_data, "version"))) {
            cJSON_AddItemToObject(j_agent_info, "agent_version", cJSON_DetachItemFromObject(j_agent_data, "version"));
        }
        cJSON_Delete(j_agent_data);
    } else {
        // A NULL agent_data_hash is received when the helper is executed from the manager side. Syscollector messages are not received by remoted module for agent 000.
        cJSON_AddItemToObject(j_agent_info, "agent_version", cJSON_CreateString(__ossec_version));
    }

    cJSON_AddItemToObject(j_msg_to_send, "agent_info", j_agent_info);

    cJSON_AddItemToObject(j_msg_to_send, "data_type", cJSON_DetachItemFromObject(j_msg, "type"));

    cJSON_AddItemToObject(j_msg_to_send, "data", cJSON_DetachItemFromObject(j_msg, "data"));
    cJSON_AddItemToObject(j_msg_to_send, "operation", cJSON_DetachItemFromObject(j_msg, "operation"));

    msg_to_send = cJSON_PrintUnformatted(j_msg_to_send);

    cJSON_Delete(j_msg_to_send);
    cJSON_Delete(j_msg);

    return msg_to_send;
}

char* adapt_sync_message(const char* data, const char* name, const char* id, const char* ip, const OSHash *agent_data_hash) {
    cJSON* j_msg_to_send = NULL;
    cJSON* j_agent_info = NULL;
    cJSON* j_msg = NULL;
    cJSON* j_data = NULL;
    cJSON* j_agent_data = NULL;
    char* msg_to_send = NULL;

    j_msg = cJSON_Parse(data);
    if (!j_msg) {
        return NULL;
    } else {
        // Legacy agents prior to 4.2 used a different message format that isn't supported
        if (cJSON_GetObjectItem(j_msg, "ID") && cJSON_GetObjectItem(j_msg, "timestamp")) {
            cJSON_Delete(j_msg);
            return NULL;
        }
    }

    j_msg_to_send = cJSON_CreateObject();

    j_agent_info = cJSON_CreateObject();

    cJSON_AddStringToObject(j_agent_info, "agent_id", id);
    cJSON_AddStringToObject(j_agent_info, "agent_ip", ip);
    cJSON_AddStringToObject(j_agent_info, "agent_name", name);

    if (NULL != agent_data_hash) {
        // Getting agent context
        j_agent_data = OSHash_Get_ex_dup(agent_data_hash, id, agent_data_hash_duplicator);
        if (cJSON_IsString(cJSON_GetObjectItem(j_agent_data, "version"))) {
                cJSON_AddItemToObject(j_agent_info, "agent_version", cJSON_DetachItemFromObject(j_agent_data, "version"));
        }
        cJSON_Delete(j_agent_data);
    } else {
        // A NULL agent_data_hash is received when the helper is executed from the manager side. Syscollector messages are not received by remoted module for agent 000.
        cJSON_AddItemToObject(j_agent_info, "agent_version", cJSON_CreateString(__ossec_version));
    }

    cJSON_AddItemToObject(j_msg_to_send, "agent_info", j_agent_info);

    cJSON_AddItemToObject(j_msg_to_send, "data_type", cJSON_DetachItemFromObject(j_msg, "type"));

    cJSON* j_data_msg = cJSON_GetObjectItem(j_msg, "data");
    if (j_data_msg) {
        j_data = cJSON_CreateObject();
        cJSON_AddItemToObject(j_data, "attributes_type", cJSON_DetachItemFromObject(j_msg, "component"));
        for (cJSON* j_item = j_data_msg->child; j_item; j_item = j_item->next) {
            cJSON_AddItemToObject(j_data, j_item->string, cJSON_Duplicate(cJSON_GetObjectItem(j_data_msg, j_item->string), true));
        }
        cJSON_AddItemToObject(j_msg_to_send, "data", j_data);
    }

    msg_to_send = cJSON_PrintUnformatted(j_msg_to_send);

    cJSON_Delete(j_msg_to_send);
    cJSON_Delete(j_msg);

    return msg_to_send;
}
