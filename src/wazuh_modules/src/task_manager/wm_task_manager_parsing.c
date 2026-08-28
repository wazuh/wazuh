/*
 * Wazuh Module for Task Manager
 * Copyright (C) 2015, Wazuh Inc.
 * July 13, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WAZUH_UNIT_TESTING
#define STATIC
#else
#define STATIC static
#endif

#include "wmodules.h"
#include "wm_task_manager_parsing.h"
#include "shared.h"

// External references from wm_task_manager.c
extern const char *task_type_names[];

/**
 * Parse create_task action parameters
 * @param request parsed JSON request
 * @param error_message message in case of error
 * @return create task params if success, NULL otherwise
 */
STATIC wm_task_create_params* wm_task_manager_parse_create_params(const cJSON *request, char **error_message);

/**
 * Parse get_pending_tasks action parameters
 * @param request parsed JSON request
 * @param error_message message in case of error
 * @return get pending params if success, NULL otherwise
 */
STATIC wm_task_get_pending_params* wm_task_manager_parse_get_pending_params(const cJSON *request, char **error_message);

int wm_task_manager_parse_message(const char* buffer, void** params, char** error) {
    cJSON *root = NULL;
    int retval = OS_INVALID;
    char *error_message = NULL;

    if (root = cJSON_Parse(buffer), !root) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Failed to parse JSON request: %s", buffer);
        *error = wm_task_manager_parse_error_response("invalid_json", "Failed to parse JSON request");
        return retval;
    }

    cJSON *action = cJSON_GetObjectItem(root, "action");

    if (action && cJSON_IsString(action)) {
        if (strcmp(action->valuestring, "create_task") == 0) {
            *params = (wm_task_create_params *)wm_task_manager_parse_create_params(root, &error_message);
            if (!error_message) {
                retval = WM_TASK_MANAGER_CREATE;
            }
        } else if (strcmp(action->valuestring, "get_pending_tasks") == 0) {
            *params = (wm_task_get_pending_params *)wm_task_manager_parse_get_pending_params(root, &error_message);
            if (!error_message) {
                retval = WM_TASK_MANAGER_GET_PENDING;
            }
        } else {
            mterror(WM_TASK_MANAGER_LOGTAG, "Unknown action: %s", action->valuestring);
            error_message = strdup("Unknown action");
        }
    } else {
        mterror(WM_TASK_MANAGER_LOGTAG, "Missing or invalid 'action' field");
        error_message = strdup("Missing or invalid 'action' field");
    }

    if (error_message) {
        *error = wm_task_manager_parse_error_response("parsing_error", error_message);
        os_free(error_message);
    }

    cJSON_Delete(root);

    return retval;
}

STATIC wm_task_create_params* wm_task_manager_parse_create_params(const cJSON *request, char **error_message) {
    wm_task_create_params *params = NULL;

    cJSON *agent_id_obj = cJSON_GetObjectItem(request, "agent_id");
    cJSON *task_type_obj = cJSON_GetObjectItem(request, "task_type");
    cJSON *create_time_obj = cJSON_GetObjectItem(request, "create_time");
    cJSON *payload_obj = cJSON_GetObjectItem(request, "payload");

    if (!agent_id_obj || !cJSON_IsString(agent_id_obj)) {
        *error_message = strdup("Missing or invalid 'agent_id'");
        return NULL;
    }
    if (!task_type_obj || !cJSON_IsString(task_type_obj)) {
        *error_message = strdup("Missing or invalid 'task_type'");
        return NULL;
    }
    if (!create_time_obj || !cJSON_IsNumber(create_time_obj)) {
        *error_message = strdup("Missing or invalid 'create_time'");
        return NULL;
    }
    if (!payload_obj) {
        *error_message = strdup("Missing 'payload'");
        return NULL;
    }

    // Validate create_time
    time_t create_time = (time_t)create_time_obj->valuedouble;
    time_t now = time(NULL);
    if (create_time > now + 60) {
        *error_message = strdup("Timestamp is in the future");
        return NULL;
    }
    if (create_time < now - 31536000) {
        *error_message = strdup("Timestamp is too old (>1 year)");
        return NULL;
    }

    // Validate task_type
    const char *task_type_str = task_type_obj->valuestring;
    wm_task_type task_type = WM_TASK_TYPE_ACTIVE_RESPONSE;
    int found = 0;
    for (int i = 0; i < WM_TASK_TYPE_COUNT; i++) {
        if (strcmp(task_type_str, task_type_names[i]) == 0) {
            task_type = (wm_task_type)i;
            found = 1;
            break;
        }
    }
    if (!found) {
        *error_message = strdup("Invalid 'task_type'");
        return NULL;
    }

    // Convert payload to JSON string
    char *payload_json = cJSON_PrintUnformatted(payload_obj);
    if (!payload_json) {
        *error_message = strdup("Failed to serialize payload");
        return NULL;
    }

    // Allocate params struct
    os_calloc(1, sizeof(wm_task_create_params), params);
    params->agent_id = strdup(agent_id_obj->valuestring);
    params->task_type = task_type;
    params->create_time = create_time;
    params->payload_json = payload_json;

    // Optional source_id
    cJSON *source_id_obj = cJSON_GetObjectItem(request, "source_id");
    if (source_id_obj && cJSON_IsString(source_id_obj)) {
        params->source_id = strdup(source_id_obj->valuestring);
    } else {
        params->source_id = NULL;
    }

    return params;
}

STATIC wm_task_get_pending_params* wm_task_manager_parse_get_pending_params(const cJSON *request, char **error_message) {
    wm_task_get_pending_params *params = NULL;

    cJSON *agent_id_obj = cJSON_GetObjectItem(request, "agent_id");

    if (!agent_id_obj || !cJSON_IsString(agent_id_obj)) {
        *error_message = strdup("Missing or invalid 'agent_id'");
        return NULL;
    }

    os_calloc(1, sizeof(wm_task_get_pending_params), params);
    params->agent_id = strdup(agent_id_obj->valuestring);

    return params;
}

char* wm_task_manager_parse_error_response(const char *error, const char *message) {
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "error", error);
    if (message) {
        cJSON_AddStringToObject(resp, "message", message);
    }

    char *response = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);

    if (!response) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Failed to serialize error response");
        return strdup("{\"error\":\"serialization_failed\"}");
    }

    return response;
}

char* wm_task_manager_parse_create_response(const char *task_id) {
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "ok");
    cJSON_AddStringToObject(resp, "task_id", task_id);

    char *response = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);

    if (!response) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Failed to serialize create response");
        return strdup("{\"error\":\"serialization_failed\"}");
    }

    return response;
}

char* wm_task_manager_parse_get_pending_response(cJSON *tasks) {
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "ok");
    cJSON_AddItemToObject(resp, "tasks", tasks);

    char *response = cJSON_PrintUnformatted(resp);
    cJSON_Delete(resp);

    if (!response) {
        mterror(WM_TASK_MANAGER_LOGTAG, "Failed to serialize get_pending response");
        return strdup("{\"error\":\"serialization_failed\"}");
    }

    return response;
}
