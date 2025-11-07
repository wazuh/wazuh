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

// System includes
#include <stdio.h>

// Project includes
#include "agent_info/include/agent_info.h"
#include "wm_agent_info.h"
#include "wmodules.h"

#include "agent_sync_protocol_c_interface_types.h"
#include "logging_helper.h"
#include "mq_op.h"
#include "rc.h"
#include "sym_load.h"
#include <os_net/os_net.h>

// Unit testing support
#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when testing */
#define static
#endif

// Platform-specific defines
#ifdef WIN32
#define AGENT_INFO_SYNC_PROTOCOL_DB_PATH "queue\\agent_info\\db\\agent_info_sync.db"
#else
#define AGENT_INFO_SYNC_PROTOCOL_DB_PATH "queue/agent_info/db/agent_info_sync.db"
#endif

// Logging macros
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

// XML configuration constants
static const char* XML_INTERVAL = "interval";
static const char* XML_SYNC = "synchronization";

// Type definitions
typedef bool (*agent_info_parse_response_func)(const uint8_t* data, size_t data_len);

// Static module variables
static int g_agent_info_queue = 0; // Output queue file descriptor
static int g_shutting_down = 0;
static bool agent_info_enable_synchronization = true;

// Module handle and function pointers
void* agent_info_module = NULL;
agent_info_start_func agent_info_start_ptr = NULL;
agent_info_stop_func agent_info_stop_ptr = NULL;
agent_info_set_log_function_func agent_info_set_log_function_ptr = NULL;
agent_info_set_report_function_func agent_info_set_report_function_ptr = NULL;
agent_info_init_sync_protocol_func agent_info_init_sync_protocol_ptr = NULL;
agent_info_set_query_module_function_func agent_info_set_query_module_function_ptr = NULL;

// Sync protocol function pointers
static agent_info_parse_response_func agent_info_parse_response_ptr = NULL;

// Forward declarations (needed for WM_AGENT_INFO_CONTEXT)
#ifdef WIN32
DWORD WINAPI wm_agent_info_main(void* arg);
#else
void* wm_agent_info_main(wm_agent_info_t* agent_info);
#endif
void wm_agent_info_destroy(wm_agent_info_t* agent_info);
cJSON* wm_agent_info_dump(const wm_agent_info_t* agent_info);
int wm_agent_info_sync_message(const char* command, size_t command_len);
void wm_agent_info_stop(void);

// Module context
const wm_context WM_AGENT_INFO_CONTEXT = {.name = AGENT_INFO_WM_NAME,
                                          .start = (wm_routine)wm_agent_info_main,
                                          .destroy = (void (*)(void*))wm_agent_info_destroy,
                                          .dump = (cJSON * (*)(const void*)) wm_agent_info_dump,
                                          .sync = (int(*)(const char*, size_t)) wm_agent_info_sync_message,
                                          .stop = (void (*)(void*))wm_agent_info_stop,
                                          .query = NULL};

// ==============================================================================
// Static Helper Functions
// ==============================================================================

// Synchronization parsing function
static void wm_agent_info_parse_synchronization(wm_agent_info_t* agent_info, xml_node** node)
{
    const char* XML_DB_SYNC_ENABLED = "enabled";
    const char* XML_DB_SYNC_RESPONSE_TIMEOUT = "response_timeout";
    const char* XML_DB_SYNC_RETRIES = "retries";
    const char* XML_DB_SYNC_MAX_EPS = "max_eps";

    for (int i = 0; node[i]; ++i)
    {
        if (strcmp(node[i]->element, XML_DB_SYNC_ENABLED) == 0)
        {
            int r = w_parse_bool(node[i]->content);

            if (r < 0)
            {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            }
            else
            {
                agent_info->sync.enable_synchronization = r;
            }
        }
        else if (strcmp(node[i]->element, XML_DB_SYNC_RESPONSE_TIMEOUT) == 0)
        {
            long response_timeout = w_parse_time(node[i]->content);

            if (response_timeout < 0)
            {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            }
            else
            {
                agent_info->sync.sync_response_timeout = (uint32_t)response_timeout;
            }
        }
        else if (strcmp(node[i]->element, XML_DB_SYNC_RETRIES) == 0)
        {
            char* end;
            const long value = strtol(node[i]->content, &end, 10);

            if (value < 0 || value > 100 || *end)
            {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            }
            else
            {
                agent_info->sync.sync_retries = (uint32_t)value;
            }
        }
        else if (strcmp(node[i]->element, XML_DB_SYNC_MAX_EPS) == 0)
        {
            char* end;
            const long value = strtol(node[i]->content, &end, 10);

            if (value < 0 || value > 1000000 || *end)
            {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            }
            else
            {
                agent_info->sync.sync_max_eps = value;
            }
        }
        else
        {
            mwarn(XML_INVELEM, node[i]->element);
        }
    }
}

// Logging callback function for agent-info module
static void
agent_info_log_callback(const modules_log_level_t level, const char* log, __attribute__((unused)) const char* tag)
{
    switch (level)
    {
        case LOG_DEBUG: mdebug1("%s", log); break;
        case LOG_DEBUG_VERBOSE: mdebug2("%s", log); break;
        case LOG_INFO: minfo("%s", log); break;
        case LOG_WARNING: mwarn("%s", log); break;
        case LOG_ERROR: merror("%s", log); break;
        default: minfo("%s", log); break;
    }
}

// Check if module is shutting down
static bool wm_agent_info_is_shutting_down()
{
    return g_shutting_down;
}

// Agent-info message queue functions
static int wm_agent_info_startmq(const char* key, short type, short attempts)
{
    return StartMQ(key, type, attempts);
}

static int
wm_agent_info_send_binary_msg(int queue, const void* message, size_t message_len, const char* locmsg, char loc)
{
    return SendBinaryMSG(queue, message, message_len, locmsg, loc);
}

// Wrapper function to adapt wm_module_query signature to the expected callback type
static int wm_agent_info_query_module_wrapper(const char* module_name, const char* json_query, char** response)
{
    if (!module_name || !json_query || !response)
    {
        return -1;
    }

    mdebug1("Received JSON for %s: %s", module_name, json_query);

    // Check if this is a request for FIM module (separate process)
    if (strcmp(module_name, FIM_NAME) == 0) {
        size_t result_len = wm_fim_query_json(json_query, response);

        if (result_len > 0 && *response) {
            // Parse JSON response to check for success
            cJSON *json_obj = cJSON_Parse(*response);
            if (json_obj) {
                cJSON *error_item = cJSON_GetObjectItem(json_obj, "error");
                if (error_item && cJSON_IsNumber(error_item)) {
                    int error_code = (int)cJSON_GetNumberValue(error_item);
                    cJSON_Delete(json_obj);
                    return (error_code == 0) ? 0 : -1;
                }
                cJSON_Delete(json_obj);
            }
        }
        return -1;
    }

    // For SCA, Syscollector and other wm_modules
    // Use wm_module_query_json_ex which accepts module_name directly (more efficient)
    size_t result_len = wm_module_query_json_ex(module_name, json_query, response);

    if (result_len > 0 && *response) {
        // Parse JSON response to check for success
        cJSON *json_obj = cJSON_Parse(*response);
        if (json_obj) {
            cJSON *error_item = cJSON_GetObjectItem(json_obj, "error");
            if (error_item && cJSON_IsNumber(error_item)) {
                int error_code = (int)cJSON_GetNumberValue(error_item);
                cJSON_Delete(json_obj);
                return (error_code == 0) ? 0 : -1;
            }
            cJSON_Delete(json_obj);
        }
    }

    return -1;
}

// Callback to send stateless messages
static int wm_agent_info_send_stateless(const char* message)
{
    if (g_shutting_down)
    {
        return -1;
    }

    if (!message)
    {
        return -1;
    }

    mdebug1("Sending agent-info event: %s", message);

    if (SendMSGPredicated(
            g_agent_info_queue, message, WM_AGENT_INFO_LOGTAG, LOCALFILE_MQ, wm_agent_info_is_shutting_down) < 0)
    {
        merror("Error sending message to queue");

        if ((g_agent_info_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0)
        {
            merror("Cannot restart agent-info message queue");
            return -1;
        }

        // Try to send it again
        if (SendMSGPredicated(
                g_agent_info_queue, message, WM_AGENT_INFO_LOGTAG, LOCALFILE_MQ, wm_agent_info_is_shutting_down) < 0)
        {
            merror("Error sending message to queue after reconnection");
            return -1;
        }
    }

    return 0;
}

// ==============================================================================
// Public Module Interface Functions
// ==============================================================================

// Reading function
int wm_agent_info_read(__attribute__((unused)) const OS_XML* xml, xml_node** nodes, wmodule* module)
{
    unsigned int i;
    wm_agent_info_t* agent_info;

    if (module->data)
    {
        agent_info = module->data;
    }
    else
    {
        os_calloc(1, sizeof(wm_agent_info_t), agent_info);
    }

    // Set default configuration values
    agent_info->interval = 60;

    // Database synchronization config values
    agent_info->sync.enable_synchronization = 1;
    agent_info->sync.sync_response_timeout = 60;
    agent_info->sync.sync_retries = 3;
    agent_info->sync.sync_max_eps = 10;

    module->context = &WM_AGENT_INFO_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = agent_info;

#ifdef CLIENT
    agent_info->is_agent = true;
#else
    agent_info->is_agent = false;
#endif

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
        else if (!strcmp(nodes[i]->element, XML_SYNC))
        {
            // Synchronization section - Let's get the children node and iterate the values
            xml_node** children = OS_GetElementsbyNode(xml, nodes[i]);

            if (children)
            {
                wm_agent_info_parse_synchronization(agent_info, children);
                OS_ClearNode(children);
            }
        }
        else
        {
            mwarn(XML_INVELEM, nodes[i]->element);
        }
    }

    return 0;
}

// Stop function
void wm_agent_info_stop()
{
    g_shutting_down = 1;

    if (agent_info_stop_ptr)
    {
        agent_info_stop_ptr();
    }
}

// Sync message function
int wm_agent_info_sync_message(const char* command, size_t command_len)
{
    if (agent_info_enable_synchronization && agent_info_parse_response_ptr)
    {
        size_t header_len = strlen(AGENT_INFO_SYNC_HEADER);
        const uint8_t* data = (const uint8_t*)(command + header_len);
        size_t data_len = command_len - header_len;

        bool ret = agent_info_parse_response_ptr(data, data_len);

        if (!ret)
        {
            mdebug1("Error syncing module");
            return -1;
        }

        return 0;
    }
    else
    {
        mdebug1("Agent-info synchronization is disabled or function not available");
        return -1;
    }
}

// Main module function
#ifdef WIN32
DWORD WINAPI wm_agent_info_main(void* arg)
{
    wm_agent_info_t* agent_info = (wm_agent_info_t*)arg;
#else
void* wm_agent_info_main(wm_agent_info_t* agent_info)
{
#endif
    g_shutting_down = 0;

    minfo("Starting agent-info module.");

    if (!agent_info)
    {
        merror("Agent-info configuration is NULL. Exiting.");
        return NULL;
    }

    // Initialize message queue
    g_agent_info_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

    if (g_agent_info_queue < 0)
    {
        merror("Cannot initialize agent-info message queue.");
        return NULL;
    }

    minfo("Agent-info message queue initialized successfully.");

    // Set synchronization parameters from configuration
    agent_info_enable_synchronization = agent_info->sync.enable_synchronization;

    // Get module handle and function pointers
    if (agent_info_module = so_get_module_handle(AGENT_INFO_LIB_NAME), agent_info_module)
    {
        mdebug1("Successfully loaded agent-info library");
        agent_info_start_ptr = so_get_function_sym(agent_info_module, "agent_info_start");
        agent_info_stop_ptr = so_get_function_sym(agent_info_module, "agent_info_stop");
        agent_info_set_log_function_ptr = so_get_function_sym(agent_info_module, "agent_info_set_log_function");
        agent_info_set_report_function_ptr = so_get_function_sym(agent_info_module, "agent_info_set_report_function");
        agent_info_init_sync_protocol_ptr = so_get_function_sym(agent_info_module, "agent_info_init_sync_protocol");
        agent_info_set_query_module_function_ptr = so_get_function_sym(agent_info_module, "agent_info_set_query_module_function");

        // Get sync protocol function pointers
        agent_info_parse_response_ptr = so_get_function_sym(agent_info_module, "agent_info_parse_response");

        // Set the logging function pointer in the agent-info module
        if (agent_info_set_log_function_ptr)
        {
            agent_info_set_log_function_ptr(agent_info_log_callback);
        }

        // Set the push functions for message handling (report and persist)
        if (agent_info_set_report_function_ptr)
        {
            agent_info_set_report_function_ptr(wm_agent_info_send_stateless);
        }

        // Set the query module function for inter-module communication
        if (agent_info_set_query_module_function_ptr)
        {
            agent_info_set_query_module_function_ptr(wm_agent_info_query_module_wrapper);
        }
    }
    else
    {
        merror("Can't get agent-info module handle for library: lib%s.so", AGENT_INFO_LIB_NAME);
        return NULL;
    }

    if (agent_info_init_sync_protocol_ptr)
    {
        MQ_Functions mq_funcs = {.start = wm_agent_info_startmq, .send_binary = wm_agent_info_send_binary_msg};
        agent_info_init_sync_protocol_ptr(AGENT_INFO_WM_NAME, AGENT_INFO_SYNC_PROTOCOL_DB_PATH, &mq_funcs);
    }

    // Initialize the C++ implementation (this will create the AgentInfoImpl with the callbacks)
    // This call will populate the agent metadata and send it to the queue
    if (agent_info_start_ptr)
    {
        minfo("Starting agent-info module...");

        agent_info_start_ptr(agent_info);
    }
    else
    {
        merror("agent_info_start function not available.");
        return NULL;
    }

    // The module has completed its initialization and metadata collection
    // The thread will now exit as agent-info is a one-time collection module
    return NULL;
}

// Destroy function
void wm_agent_info_destroy(wm_agent_info_t* agent_info)
{
    minfo("Destroying agent-info module.");

    g_shutting_down = 1;

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

    if (agent_info)
    {
        cJSON_AddNumberToObject(wm_agent_info, "interval", agent_info->interval);

        // Database synchronization values
        cJSON* synchronization = cJSON_CreateObject();
        cJSON_AddStringToObject(synchronization, "enabled", agent_info->sync.enable_synchronization ? "yes" : "no");
        cJSON_AddNumberToObject(synchronization, "response_timeout", agent_info->sync.sync_response_timeout);
        cJSON_AddNumberToObject(synchronization, "retries", agent_info->sync.sync_retries);
        cJSON_AddNumberToObject(synchronization, "max_eps", agent_info->sync.sync_max_eps);

        cJSON_AddItemToObject(wm_agent_info, "synchronization", synchronization);
    }

    cJSON_AddItemToObject(root, "agent-info", wm_agent_info);
    return root;
}
