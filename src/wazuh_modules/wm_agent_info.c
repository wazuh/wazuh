/*
 * Wazuh Module for Agent Information Management
 * Copyright (C) 2015, Wazuh Inc.
 * November 25, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_modules/wm_agent_info.h"
#include "wazuh_modules/agent_info/include/agent_info.h"
#include "wazuh_modules/wmodules.h"
#include "sym_load.h"
#include "logging_helper.h"

#include <stdio.h>
#include <dlfcn.h>

static const char* XML_ENABLED = "enabled";
static const char* XML_INTERVAL = "interval";

#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when testing */
#define static
#endif

#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...)   _mtinfo(WM_AGENT_INFO_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...)   _mtwarn(WM_AGENT_INFO_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...)  _mterror(WM_AGENT_INFO_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_AGENT_INFO_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_AGENT_INFO_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

// Logging callback function for agent-info module
static void agent_info_log_callback(const modules_log_level_t level, const char* log, __attribute__((unused)) const char* tag) {
    switch(level) {
        case LOG_DEBUG:
            mdebug1("%s", log);
            break;
        case LOG_DEBUG_VERBOSE:
            mdebug2("%s", log);
            break;
        case LOG_INFO:
            minfo("%s", log);
            break;
        case LOG_WARNING:
            mwarn("%s", log);
            break;
        case LOG_ERROR:
            merror("%s", log);
            break;
        default:
            minfo("%s", log);
            break;
    }
}

// Module handle and function pointers
void *agent_info_module = NULL;
agent_info_start_func agent_info_start_ptr = NULL;
agent_info_stop_func agent_info_stop_ptr = NULL;
agent_info_set_log_function_func agent_info_set_log_function_ptr = NULL;

// Reading function
int wm_agent_info_read(const OS_XML* xml, xml_node** nodes, wmodule* module)
{
    unsigned int i;
    wm_agent_info_t* agent_info;

    if (!module->data)
    {
        os_calloc(1, sizeof(wm_agent_info_t), agent_info);
        agent_info->enabled = 1;    // Enabled by default
        agent_info->interval = 300; // 5 minutes default interval
        module->context = &WM_AGENT_INFO_CONTEXT;
        module->tag = strdup(module->context->name);
        module->data = agent_info;
    }

    agent_info = module->data;

    if (!nodes)
    {
        return 0;
    }

    for (i = 0; nodes[i]; i++)
    {
        if (!nodes[i]->element)
        {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        }
        else if (!strcmp(nodes[i]->element, XML_ENABLED))
        {
            if (!strcmp(nodes[i]->content, "yes"))
            {
                agent_info->enabled = 1;
            }
            else if (!strcmp(nodes[i]->content, "no"))
            {
                agent_info->enabled = 0;
            }
            else
            {
                mwarn(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
            }
        }
        else if (!strcmp(nodes[i]->element, XML_INTERVAL))
        {
            char* end;
            long value = strtol(nodes[i]->content, &end, 10);

            if (value < 60 || value > DAY_SEC || *end)
            {
                mwarn("Invalid interval time at module '%s'. Value must be between 60 and %d.",
                      WM_AGENT_INFO_CONTEXT.name,
                      DAY_SEC);
            }
            else
            {
                agent_info->interval = value;
            }
        }
        else
        {
            mwarn(XML_INVELEM, nodes[i]->element);
        }
    }

    return 0;
}

// Module context
const wm_context WM_AGENT_INFO_CONTEXT = {.name = AGENT_INFO_WM_NAME,
                                          .start = wm_agent_info_main,
                                          .destroy = wm_agent_info_destroy,
                                          .dump = wm_agent_info_dump,
                                          .sync = NULL,
                                          .stop = NULL,
                                          .query = NULL};

// Main module function (runs in its own thread)
void* wm_agent_info_main(wm_agent_info_t* agent_info)
{
    minfo("Starting agent-info module.");

    if (!agent_info || !agent_info->enabled)
    {
        minfo("Agent-info module disabled. Exiting.");
        return NULL;
    }

    // Get module handle and function pointers
    if (agent_info_module = so_get_module_handle(AGENT_INFO_LIB_NAME), agent_info_module)
    {
        mdebug1("Successfully loaded agent-info library");
        agent_info_start_ptr = so_get_function_sym(agent_info_module, "agent_info_start");
        agent_info_stop_ptr = so_get_function_sym(agent_info_module, "agent_info_stop");
        agent_info_set_log_function_ptr = so_get_function_sym(agent_info_module, "agent_info_set_log_function");

        mdebug2("Function pointers - start: %p, stop: %p, set_log: %p",
                agent_info_start_ptr, agent_info_stop_ptr, agent_info_set_log_function_ptr);

        // Set the logging function pointer in the agent-info module
        if (agent_info_set_log_function_ptr)
        {
            agent_info_set_log_function_ptr(agent_info_log_callback);
        }
    }
    else
    {
        merror("Can't get agent-info module handle for library: lib%s.so", AGENT_INFO_LIB_NAME);
        merror("dlopen error: %s", dlerror());
        return NULL;
    }

    // Initialize the C++ implementation
    if (agent_info_start_ptr)
    {
        agent_info_start_ptr(agent_info);
    }
    else
    {
        merror("agent_info_start function not available.");
        return NULL;
    }

    // Module main loop would go here
    // For now, just sleep
    while (1)
    {
        sleep(60); // Sleep for 1 minute
        // TODO: Add periodic metadata collection/sync logic
    }

    return NULL;
}

// Destroy function
void wm_agent_info_destroy(wm_agent_info_t* agent_info)
{
    if (agent_info)
    {
        if (agent_info_stop_ptr)
        {
            agent_info_stop_ptr();
        }
        free(agent_info);
    }
}

// Dump configuration function
cJSON* wm_agent_info_dump(const wm_agent_info_t* agent_info)
{
    cJSON* root = cJSON_CreateObject();
    cJSON* wm_agent_info = cJSON_CreateObject();

    if (!agent_info)
    {
        cJSON_AddStringToObject(wm_agent_info, "enabled", "no");
    }
    else
    {
        cJSON_AddStringToObject(wm_agent_info, "enabled", agent_info->enabled ? "yes" : "no");
    }

    cJSON_AddItemToObject(root, "agent-info", wm_agent_info);
    return root;
}