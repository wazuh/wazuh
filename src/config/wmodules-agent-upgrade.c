/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "wazuh_modules/wmodules.h"

static const char *XML_ENABLED = "enabled";
#ifdef CLIENT
static const char *XML_WAIT_START = "notification_wait_start";
static const char *XML_WAIT_MAX = "notification_wait_max";
static const char *XML_WAIT_FACTOR = "notification_wait_factor";
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
        data->agent_config.upgrade_wait_start = 300;
        data->agent_config.upgrade_wait_max = 3600;
        data->agent_config.ugprade_wait_factor_increase = 2.0;
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
        else if (!strcmp(nodes[i]->element, XML_ENABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                data->enabled = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                data->enabled = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_AGENT_UPGRADE_CONTEXT.name);
                return OS_INVALID;
            }
        }
#ifdef CLIENT
        // Agent configurations
        else if (!strcmp(nodes[i]->element, XML_WAIT_START)) {
            int wait_start = strtol(nodes[i]->content, NULL, 10);
            if (wait_start > 0) {
                data->agent_config.upgrade_wait_start = wait_start;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_WAIT_START, WM_AGENT_UPGRADE_CONTEXT.name);
                return OS_INVALID;
            }
            
        } else if (!strcmp(nodes[i]->element, XML_WAIT_MAX)) {
            int wait_max = strtol(nodes[i]->content, NULL, 10);
            if (wait_max > 0) {
                data->agent_config.upgrade_wait_max = wait_max;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_WAIT_MAX, WM_AGENT_UPGRADE_CONTEXT.name);
                return OS_INVALID;
            }
            
        } else if (!strcmp(nodes[i]->element, XML_WAIT_FACTOR)) {
            float wait_factor = strtol(nodes[i]->content, NULL, 10);
            if (wait_factor > 1.0) {
                data->agent_config.ugprade_wait_factor_increase = wait_factor;
            } else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_WAIT_FACTOR, WM_AGENT_UPGRADE_CONTEXT.name);
                return OS_INVALID;
            }
        }
#endif
        else {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_AGENT_UPGRADE_CONTEXT.name);
        }
    }

    return 0;
}
