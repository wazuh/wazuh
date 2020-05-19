/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "wazuh_modules/wmodules.h"
#include <stdio.h>

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER
#endif

static const char *XML_DISABLED = "disabled";
static const char *XML_RUN_DAEMON = "run_daemon";
static const char *XML_PROCESS_EVENTS_DISABLED = "process_events_disabled";
static const char *XML_PROCESS_EVENTS_INTERVAL = "process_events_interval";

static short eval_bool(const char *str)
{
    return !str ? OS_INVALID : !strcmp(str, "yes") ? 1 : !strcmp(str, "no") ? 0 : OS_INVALID;
}

// module configuration reader
int wm_osquery_native_configuration_reader(
    xml_node **nodes, 
    wmodule *module)
{
    int i;
    bool ret_val = false;

    UNREFERENCED_PARAMETER(nodes);

    wm_osquery_native_t *osquery_native_config = NULL;

    os_calloc(1, sizeof(wm_osquery_native_t), osquery_native_config);
    osquery_native_config->disable = FALSE;
    osquery_native_config->run_daemon = TRUE;
    osquery_native_config->disable_process_events = TRUE;
    osquery_native_config->interval_process_events = 5;
    osquery_native_config->remote_ondemand_call = NULL;
    module->context = &WM_OSQUERYNATIVE_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = osquery_native_config;

    if (!nodes)
        return 0;

    for(i = 0; nodes[i]; i++)
    {
        if(!nodes[i]->element)
        {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        }
        else if (!strcmp(nodes[i]->element, XML_DISABLED))
        {
            if (osquery_native_config->disable = eval_bool(nodes[i]->content), osquery_native_config->disable == OS_INVALID) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_DISABLED, WM_OSQUERYNATIVE_CONTEXT.name);
                return OS_INVALID;
            }
        }
        else if (!strcmp(nodes[i]->element, XML_RUN_DAEMON)) {
            if (osquery_native_config->run_daemon = eval_bool(nodes[i]->content), osquery_native_config->run_daemon == OS_INVALID) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_RUN_DAEMON, WM_OSQUERYNATIVE_CONTEXT.name);
                return OS_INVALID;
            }
        }
        else if (!strcmp(nodes[i]->element, XML_PROCESS_EVENTS_INTERVAL))
        {
            osquery_native_config->interval_process_events = strtoul(nodes[i]->content, NULL, 0);

            if (osquery_native_config->interval_process_events == 0 || osquery_native_config->interval_process_events == UINT_MAX) {
                merror("Invalid interval value.");
                return OS_INVALID;
            }
        }
        else if (!strcmp(nodes[i]->element, XML_PROCESS_EVENTS_DISABLED)) {
            if (osquery_native_config->disable_process_events = eval_bool(nodes[i]->content), osquery_native_config->disable_process_events == OS_INVALID) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_PROCESS_EVENTS_DISABLED, WM_OSQUERYNATIVE_CONTEXT.name);
                return OS_INVALID;
            }
        } else {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_OSQUERYNATIVE_CONTEXT.name);
        }

    }

    //TO DO - Read configuration to support packs, scheduled queries and decorators.
    return ret_val;
}
