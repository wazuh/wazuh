/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "wmodules.h"

static const char *XML_TASK_TTL = "task_ttl";
static const char *XML_CLEANUP_INTERVAL = "cleanup_interval";
static const char *XML_MAX_PAYLOAD_BYTES = "max_payload_bytes";
static const char *XML_MAX_TASKS_PER_POLL = "max_tasks_per_poll";

int wm_task_manager_read(__attribute__((unused)) const OS_XML *xml, xml_node **nodes, wmodule *module) {

    unsigned int i;
    wm_task_manager* data;

    if (!module->data) {
        os_calloc(1, sizeof(wm_task_manager), data);
        data->enabled = 1;
        data->task_ttl = 0;              // 0 = use default
        data->cleanup_interval = 0;      // 0 = use default
        data->max_payload_bytes = 0;     // 0 = use default
        data->max_tasks_per_poll = 0;    // 0 = use default
        module->context = &WM_TASK_MANAGER_CONTEXT;
        module->tag = strdup(module->context->name);
        module->data = data;
    }

    data = module->data;

    if (!nodes) {
        return 0;
    }

    for (i = 0; nodes[i]; i++)
    {
        if(!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_TASK_TTL)) {
            if (!nodes[i]->content) {
                merror("Empty content for tag '%s' at module '%s'.", XML_TASK_TTL, WM_TASK_MANAGER_CONTEXT.name);
                return OS_INVALID;
            }
            data->task_ttl = atoi(nodes[i]->content);
            if (data->task_ttl < 0) {
                merror("Invalid value for element '%s' at module '%s'.", XML_TASK_TTL, WM_TASK_MANAGER_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_CLEANUP_INTERVAL)) {
            if (!nodes[i]->content) {
                merror("Empty content for tag '%s' at module '%s'.", XML_CLEANUP_INTERVAL, WM_TASK_MANAGER_CONTEXT.name);
                return OS_INVALID;
            }
            data->cleanup_interval = atoi(nodes[i]->content);
            if (data->cleanup_interval < 0) {
                merror("Invalid value for element '%s' at module '%s'.", XML_CLEANUP_INTERVAL, WM_TASK_MANAGER_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_MAX_PAYLOAD_BYTES)) {
            if (!nodes[i]->content) {
                merror("Empty content for tag '%s' at module '%s'.", XML_MAX_PAYLOAD_BYTES, WM_TASK_MANAGER_CONTEXT.name);
                return OS_INVALID;
            }
            data->max_payload_bytes = atoi(nodes[i]->content);
            if (data->max_payload_bytes < 0) {
                merror("Invalid value for element '%s' at module '%s'.", XML_MAX_PAYLOAD_BYTES, WM_TASK_MANAGER_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_MAX_TASKS_PER_POLL)) {
            if (!nodes[i]->content) {
                merror("Empty content for tag '%s' at module '%s'.", XML_MAX_TASKS_PER_POLL, WM_TASK_MANAGER_CONTEXT.name);
                return OS_INVALID;
            }
            data->max_tasks_per_poll = atoi(nodes[i]->content);
            if (data->max_tasks_per_poll < 0) {
                merror("Invalid value for element '%s' at module '%s'.", XML_MAX_TASKS_PER_POLL, WM_TASK_MANAGER_CONTEXT.name);
                return OS_INVALID;
            }
        } else {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_TASK_MANAGER_CONTEXT.name);
        }
    }

    return 0;
}
