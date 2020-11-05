/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#ifndef CLIENT
#ifndef WIN32

#include "wazuh_modules/wmodules.h"

static const char *XML_CLEANUP_TIME = "cleanup_time";
static const char *XML_TASK_TIMEOUT = "task_timeout";

int wm_task_manager_read(xml_node **nodes, wmodule *module) {

    unsigned int i;
    wm_task_manager* data;

    if (!module->data) {
        os_calloc(1, sizeof(wm_task_manager), data);
        data->enabled = 1;
        data->cleanup_time = WM_TASK_DEFAULT_CLEANUP_TIME;
        data->task_timeout = WM_TASK_MAX_IN_PROGRESS_TIME;
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
        } else if (!strcmp(nodes[i]->element, XML_CLEANUP_TIME)) {
            char *endptr;
            data->cleanup_time = strtol(nodes[i]->content, &endptr, 0);

            if (data->cleanup_time == 0 || data->cleanup_time == INT_MAX) {
                merror("Invalid cleanup_time at module '%s'", WM_TASK_MANAGER_CONTEXT.name);
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'd':
                data->cleanup_time *= 86400;
                break;
            case 'h':
                data->cleanup_time *= 3600;
                break;
            case 'm':
                data->cleanup_time *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("Invalid cleanup_time at module '%s'", WM_TASK_MANAGER_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_TASK_TIMEOUT)) {
            char *endptr;
            data->task_timeout = strtol(nodes[i]->content, &endptr, 0);

            if (data->task_timeout == 0 || data->task_timeout == INT_MAX) {
                merror("Invalid task_timeout at module '%s'", WM_TASK_MANAGER_CONTEXT.name);
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'd':
                data->task_timeout *= 86400;
                break;
            case 'h':
                data->task_timeout *= 3600;
                break;
            case 'm':
                data->task_timeout *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("Invalid task_timeout at module '%s'", WM_TASK_MANAGER_CONTEXT.name);
                return OS_INVALID;
            }
        } else {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_TASK_MANAGER_CONTEXT.name);
        }
    }

    if (data->cleanup_time < data->task_timeout) {
        merror("Too short cleanup_time at module '%s'", WM_TASK_MANAGER_CONTEXT.name);
        return OS_INVALID;
    }

    return 0;
}

#endif 
#endif
