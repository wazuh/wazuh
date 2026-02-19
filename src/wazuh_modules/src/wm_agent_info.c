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
#include "agent_info.h"
#include "wm_agent_info.h"
#include "wmodules.h"

#include "agent_sync_protocol_c_interface_types.h"
#include "logging_helper.h"
#include "mq_op.h"
#include "rc.h"
#include "sym_load.h"
#include "os_net.h"

// Unit testing support
#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when testing */
#define static
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
static const char* XML_INTEGRITY_INTERVAL = "integrity_interval";
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
agent_info_set_cluster_name_func agent_info_set_cluster_name_ptr = NULL;
agent_info_set_cluster_node_func agent_info_set_cluster_node_ptr = NULL;
agent_info_set_agent_groups_func agent_info_set_agent_groups_ptr = NULL;

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
                                          .sync = (int (*)(const char*, size_t))wm_agent_info_sync_message,
                                          .stop = (void (*)(void*))wm_agent_info_stop,
                                          .query = NULL};

// ==============================================================================
// Static Helper Functions
// ==============================================================================

// Synchronization parsing function
static void wm_agent_info_parse_synchronization(wm_agent_info_t* agent_info, xml_node** node)
{
    const char* XML_DB_SYNC_ENABLED = "enabled";
    const char* XML_DB_SYNC_END_DELAY = "sync_end_delay";
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
        else if (strcmp(node[i]->element, XML_DB_SYNC_END_DELAY) == 0)
        {
            long sync_end_delay = w_parse_time(node[i]->content);

            if (sync_end_delay < 0)
            {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            }
            else
            {
                agent_info->sync.sync_end_delay = (uint32_t)sync_end_delay;
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
    if (strcmp(module_name, FIM_NAME) == 0)
    {
        size_t result_len = wm_fim_query_json(json_query, response);

        if (result_len > 0 && *response)
        {
            // Parse JSON response to check for success
            cJSON* json_obj = cJSON_Parse(*response);
            if (json_obj)
            {
                cJSON* error_item = cJSON_GetObjectItem(json_obj, "error");
                if (error_item && cJSON_IsNumber(error_item))
                {
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

    if (result_len > 0 && *response)
    {
        // Parse JSON response to check for success
        cJSON* json_obj = cJSON_Parse(*response);
        if (json_obj)
        {
            cJSON* error_item = cJSON_GetObjectItem(json_obj, "error");
            if (error_item && cJSON_IsNumber(error_item))
            {
                int error_code = (int)cJSON_GetNumberValue(error_item);
                cJSON_Delete(json_obj);
                return (error_code == 0) ? 0 : -1;
            }
            cJSON_Delete(json_obj);
        }
    }

    return -1;
}

#ifdef WIN32
// Forward declaration - agcom_dispatch is available in the same process on Windows
extern size_t agcom_dispatch(char* command, char** output);
#endif

// Query agentd for handshake data via agcom
// On Windows: calls agcom_dispatch directly (same process)
// On Unix: connects to agcom socket (AG_LOCAL_SOCK)
static bool wm_agent_info_query_agentd_handshake(char* cluster_name,
                                                 size_t cluster_name_size,
                                                 char* cluster_node,
                                                 size_t cluster_node_size,
                                                 char* agent_groups,
                                                 size_t agent_groups_size)
{
    if (cluster_name && cluster_name_size > 0)
    {
        cluster_name[0] = '\0';
    }
    if (cluster_node && cluster_node_size > 0)
    {
        cluster_node[0] = '\0';
    }
    if (agent_groups && agent_groups_size > 0)
    {
        agent_groups[0] = '\0';
    }

    char* response = NULL;

#ifdef WIN32
    // On Windows, call agcom_dispatch directly (agent and wmodules are in same process)
    size_t len = agcom_dispatch("gethandshake", &response);
    if (len == 0 || !response)
    {
        mdebug1("No response from agcom for gethandshake");
        os_free(response);
        return false;
    }
#else
    // On Unix, connect to agcom socket (agentd)
    int sock = OS_ConnectUnixDomain(AG_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
    if (sock < 0)
    {
        mdebug1("Cannot connect to agcom socket, agentd may not be ready yet");
        return false;
    }

    // Send query
    const char* query = "gethandshake";
    if (OS_SendSecureTCP(sock, strlen(query), query) != 0)
    {
        mdebug1("Failed to send gethandshake query to agentd");
        close(sock);
        return false;
    }

    // Receive response
    char buffer[OS_MAXSTR + 1] = {0};
    ssize_t len = OS_RecvSecureTCP(sock, buffer, OS_MAXSTR);
    close(sock);

    if (len <= 0)
    {
        mdebug1("No response from agentd for gethandshake");
        return false;
    }

    response = buffer;
#endif

    // Parse JSON response
    cJSON* root = cJSON_Parse(response);

#ifdef WIN32
    os_free(response);
#endif

    if (!root)
    {
        mdebug1("Failed to parse gethandshake response");
        return false;
    }

    cJSON* cluster = cJSON_GetObjectItem(root, "cluster_name");
    if (cluster && cJSON_IsString(cluster) && cluster->valuestring)
    {
        if (cluster_name && cluster_name_size > 0)
        {
            strncpy(cluster_name, cluster->valuestring, cluster_name_size - 1);
            cluster_name[cluster_name_size - 1] = '\0';
        }
    }

    cJSON* node = cJSON_GetObjectItem(root, "cluster_node");
    if (node && cJSON_IsString(node) && node->valuestring)
    {
        if (cluster_node && cluster_node_size > 0)
        {
            strncpy(cluster_node, node->valuestring, cluster_node_size - 1);
            cluster_node[cluster_node_size - 1] = '\0';
        }
    }

    cJSON* groups = cJSON_GetObjectItem(root, "agent_groups");
    if (groups && cJSON_IsString(groups) && groups->valuestring)
    {
        if (agent_groups && agent_groups_size > 0)
        {
            strncpy(agent_groups, groups->valuestring, agent_groups_size - 1);
            agent_groups[agent_groups_size - 1] = '\0';
        }
    }

    cJSON_Delete(root);

    mdebug1("Received handshake data from agentd: cluster_name=%s, cluster_node=%s, agent_groups=%s",
            cluster_name ? cluster_name : "",
            cluster_node ? cluster_node : "",
            agent_groups ? agent_groups : "");
    return true;
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
    agent_info->interval = 60;              // Delta updates every 60 seconds
    agent_info->integrity_interval = 86400; // Integrity check every 24 hours (86400 seconds)

    // Database synchronization config values
    agent_info->sync.enable_synchronization = 1;
    agent_info->sync.sync_end_delay = 1;
    agent_info->sync.sync_response_timeout = 30;
    agent_info->sync.sync_retries = 3;
    agent_info->sync.sync_max_eps = 50;

    module->context = &WM_AGENT_INFO_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = agent_info;

#ifdef CLIENT
    agent_info->is_agent = true;
#else
    agent_info->is_agent = false;
    mdebug2("Agent-info module is not supported on manager. Ignoring configuration.");
    return 0;

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
        else if (!strcmp(nodes[i]->element, XML_INTEGRITY_INTERVAL))
        {
            char* end;
            long value = strtol(nodes[i]->content, &end, 10);

            if (value < 60 || value > 7 * DAY_SEC || *end)
            {
                mwarn("Invalid integrity_interval time at module '%s'. Value must be between 60 (1 minute) and %d (7 "
                      "days).",
                      WM_AGENT_INFO_CONTEXT.name,
                      7 * DAY_SEC);
            }
            else
            {
                agent_info->integrity_interval = value;
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
        agent_info_set_query_module_function_ptr =
            so_get_function_sym(agent_info_module, "agent_info_set_query_module_function");
        agent_info_set_cluster_name_ptr = so_get_function_sym(agent_info_module, "agent_info_set_cluster_name");
        agent_info_set_cluster_node_ptr = so_get_function_sym(agent_info_module, "agent_info_set_cluster_node");
        agent_info_set_agent_groups_ptr = so_get_function_sym(agent_info_module, "agent_info_set_agent_groups");

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
        agent_info_init_sync_protocol_ptr(AGENT_INFO_WM_NAME, &mq_funcs);
    }

    // Query agentd for handshake data (cluster_name, cluster_node, agent_groups) via agcom - only on agents

    char cluster_name[256] = {0};
    char cluster_node[256] = {0};
    char agent_groups[OS_SIZE_65536] = {0};
    bool handshake_success = false;

    while (!handshake_success && !g_shutting_down)
    {
        if (wm_agent_info_query_agentd_handshake(cluster_name,
                                                 sizeof(cluster_name),
                                                 cluster_node,
                                                 sizeof(cluster_node),
                                                 agent_groups,
                                                 sizeof(agent_groups)))
        {
            handshake_success = true;
            if (cluster_name[0] != '\0' && agent_info_set_cluster_name_ptr)
            {
                agent_info_set_cluster_name_ptr(cluster_name);
                minfo("Cluster name received from agentd: %s", cluster_name);
            }
            if (cluster_node[0] != '\0' && agent_info_set_cluster_node_ptr)
            {
                agent_info_set_cluster_node_ptr(cluster_node);
                mdebug1("Cluster node received from agentd: %s", cluster_node);
            }
            if (agent_groups[0] != '\0' && agent_info_set_agent_groups_ptr)
            {
                agent_info_set_agent_groups_ptr(agent_groups);
                mdebug1("Agent groups received from agentd: %s", agent_groups);
            }
        }
        else
        {
            mdebug1("Handshake data not available yet, retrying in 1 second...");
            sleep(1);
        }
    }

    if (g_shutting_down)
    {
        minfo("Shutdown requested during handshake wait, exiting.");
        return NULL;
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
        cJSON_AddNumberToObject(wm_agent_info, "integrity_interval", agent_info->integrity_interval);

        // Database synchronization values
        cJSON* synchronization = cJSON_CreateObject();
        cJSON_AddStringToObject(synchronization, "enabled", agent_info->sync.enable_synchronization ? "yes" : "no");
        cJSON_AddNumberToObject(synchronization, "sync_end_delay", agent_info->sync.sync_end_delay);
        cJSON_AddNumberToObject(synchronization, "response_timeout", agent_info->sync.sync_response_timeout);
        cJSON_AddNumberToObject(synchronization, "retries", agent_info->sync.sync_retries);
        cJSON_AddNumberToObject(synchronization, "max_eps", agent_info->sync.sync_max_eps);

        cJSON_AddItemToObject(wm_agent_info, "synchronization", synchronization);
    }

    cJSON_AddItemToObject(root, "agent-info", wm_agent_info);
    return root;
}
