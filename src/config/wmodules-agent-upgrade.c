/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "wazuh_modules/wmodules.h"

#ifdef CLIENT
static const char *XML_ENABLED = "enabled";
static const char *XML_WAIT_START = "notification_wait_start";
static const char *XML_WAIT_MAX = "notification_wait_max";
static const char *XML_WAIT_FACTOR = "notification_wait_factor";
#else
static const char *XML_WPK_REPOSITORY = "wpk_repository";
static const char *XML_CHUNK_SIZE = "chunk_size";
static const char *XML_MAX_THREADS = "max_threads";
#endif

int wm_agent_upgrade_read(xml_node **nodes, wmodule *module) {
    wm_agent_upgrade* data = NULL;
    
    if (!module->data) {
        // Default initialization
        module->context = &WM_AGENT_UPGRADE_CONTEXT;
        module->tag = strdup(module->context->name);
        os_calloc(1, sizeof(wm_agent_upgrade), data);
        data->enabled = 1;
        #ifdef CLIENT
        data->agent_config.upgrade_wait_start = WM_UPGRADE_WAIT_START;
        data->agent_config.upgrade_wait_max = WM_UPGRADE_WAIT_MAX;
        data->agent_config.upgrade_wait_factor_increase = WM_UPGRADE_WAIT_FACTOR_INCREASE;
        #else
        data->manager_config.max_threads = WM_UPGRADE_MAX_THREADS;
        data->manager_config.chunk_size = WM_UPGRADE_CHUNK_SIZE;
        data->manager_config.wpk_repository = NULL;
        #endif
        module->data = data;
    }

    data = module->data;

    if (!nodes) {
        return 0;
    }

    for(int i = 0; nodes[i]; i++)
    {
        if(!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } 
        #ifdef CLIENT
        // Agent configurations
        else if (!strcmp(nodes[i]->element, XML_ENABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                data->enabled = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                data->enabled = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_AGENT_UPGRADE_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_WAIT_START)) {
            char *endptr;
            data->agent_config.upgrade_wait_start = strtol(nodes[i]->content,  &endptr, 0);
            
            if (data->agent_config.upgrade_wait_start == 0 || data->agent_config.upgrade_wait_start == INT_MAX) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_WAIT_START, WM_AGENT_UPGRADE_CONTEXT.name);
                return OS_INVALID;
            }
            
            switch (*endptr) {
            case 'h':
                data->agent_config.upgrade_wait_start *= 3600;
                break;
            case 'm':
                data->agent_config.upgrade_wait_start *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("Invalid %s at module '%s'", XML_WAIT_START, WM_AGENT_UPGRADE_CONTEXT.name);
                return OS_INVALID;
            }
            
        } else if (!strcmp(nodes[i]->element, XML_WAIT_MAX)) {
            char *endptr;
            data->agent_config.upgrade_wait_max = strtol(nodes[i]->content, &endptr, 0);
            if (data->agent_config.upgrade_wait_max == 0 || data->agent_config.upgrade_wait_max == INT_MAX) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_WAIT_MAX, WM_AGENT_UPGRADE_CONTEXT.name);
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'h':
                data->agent_config.upgrade_wait_max *= 3600;
                break;
            case 'm':
                data->agent_config.upgrade_wait_max *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("Invalid content for tag '%s' at module '%s'", XML_WAIT_MAX, WM_AGENT_UPGRADE_CONTEXT.name);
                return OS_INVALID;
            }
            
        } else if (!strcmp(nodes[i]->element, XML_WAIT_FACTOR)) {
            float wait_factor = strtol(nodes[i]->content, NULL, 10);
            if (wait_factor > 1.0) {
                data->agent_config.upgrade_wait_factor_increase = wait_factor;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_WAIT_FACTOR, WM_AGENT_UPGRADE_CONTEXT.name);
                return OS_INVALID;
            }
        }
        #else
        else if (!strcmp(nodes[i]->element, XML_CHUNK_SIZE)) {
            if (!OS_StrIsNum(nodes[i]->content)) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_CHUNK_SIZE, WM_AGENT_UPGRADE_CONTEXT.name);
                return (OS_INVALID);
            }
            int chunk;
            if (chunk = atoi(nodes[i]->content), chunk < 64 || chunk > 32768) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_CHUNK_SIZE, WM_AGENT_UPGRADE_CONTEXT.name);
                return (OS_INVALID);
            }

            data->manager_config.chunk_size = chunk;

        } else if (!strcmp(nodes[i]->element, XML_MAX_THREADS)) {
            if (!OS_StrIsNum(nodes[i]->content)) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_MAX_THREADS, WM_AGENT_UPGRADE_CONTEXT.name);
                return (OS_INVALID);
            }
            int max_threads = atoi(nodes[i]->content);
            if (!max_threads) {
                // If 0, we assign the number of cpu cores
                data->manager_config.max_threads = get_nproc();
            } else if (max_threads <= 256) {
                data->manager_config.max_threads = max_threads;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_MAX_THREADS, WM_AGENT_UPGRADE_CONTEXT.name);
                return (OS_INVALID);
            }

        } else if (!strcmp(nodes[i]->element, XML_WPK_REPOSITORY)) {
            os_free(data->manager_config.wpk_repository);
            os_strdup(nodes[i]->content, data->manager_config.wpk_repository);
        }
        #endif
        else {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_AGENT_UPGRADE_CONTEXT.name);
        }
    }

    return 0;
}
