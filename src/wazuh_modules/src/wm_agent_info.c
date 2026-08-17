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
#include "module_query_errors.h"
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
agent_info_cleanup_func agent_info_cleanup_ptr = NULL;
agent_info_set_log_function_func agent_info_set_log_function_ptr = NULL;
agent_info_set_report_function_func agent_info_set_report_function_ptr = NULL;
agent_info_init_sync_protocol_func agent_info_init_sync_protocol_ptr = NULL;
agent_info_set_query_module_function_func agent_info_set_query_module_function_ptr = NULL;
agent_info_set_is_shutting_down_function_func agent_info_set_is_shutting_down_function_ptr = NULL;
agent_info_set_cluster_name_func agent_info_set_cluster_name_ptr = NULL;
agent_info_set_agent_groups_func agent_info_set_agent_groups_ptr = NULL;
agent_info_set_query_handshake_function_func agent_info_set_query_handshake_function_ptr = NULL;

// Durable task_id registry function pointers. Cleanup runs automatically from
// within AgentInfoImpl::start()'s own loop -- no separate cleanup function
// pointer/thread needed here anymore.
agent_info_task_registry_init_func agent_info_task_registry_init_ptr = NULL;
agent_info_task_check_and_record_func agent_info_task_check_and_record_ptr = NULL;

// Durable VD feed offset / pending-rescan function pointers (see agent_info.h).
agent_info_vd_offset_observe_func agent_info_vd_offset_observe_ptr = NULL;
agent_info_vd_offset_clear_pending_func agent_info_vd_offset_clear_pending_ptr = NULL;
agent_info_vd_offset_get_state_func agent_info_vd_offset_get_state_ptr = NULL;

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
size_t wm_agent_info_query(void* data, char* args, char** output);

// Module context
const wm_context WM_AGENT_INFO_CONTEXT = {.name = AGENT_INFO_WM_NAME,
                                          .start = (wm_routine)wm_agent_info_main,
                                          .destroy = (void (*)(void*))wm_agent_info_destroy,
                                          .dump = (cJSON * (*)(const void*)) wm_agent_info_dump,
                                          .sync = (int (*)(const char*, size_t))wm_agent_info_sync_message,
                                          .stop = (void (*)(void*))wm_agent_info_stop,
                                          .query = wm_agent_info_query};

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

// Durable task_id registry bounds are internal_options.conf tunables
// (agent_info.max_entries/agent_info.ttl), read via getDefine_Int_default() in
// wm_agent_info_read() -- not part of this module's ossec.conf configuration surface,
// so there is no XML parsing for them here.

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

// True once a shutdown is requested. Checks both flags: wm_shutdown_requested
// is set first, g_shutting_down later.
static bool wm_agent_info_is_shutting_down(void)
{
    return g_shutting_down || wm_shutdown_requested;
}

// Open the queue. StartMQPredicated re-checks the shutdown predicate during its
// (now interruptible) backoff, so both finite and infinite attempts honor
// shutdown within ~1 s; delegate directly.
static int wm_agent_info_startmq(const char* key, short type, short attempts)
{
    return StartMQPredicated(key, type, attempts, wm_agent_info_is_shutting_down);
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
                                                 char* agent_groups,
                                                 size_t agent_groups_size)
{
    if (cluster_name && cluster_name_size > 0)
    {
        cluster_name[0] = '\0';
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

    mdebug1("Received handshake data from agentd: cluster_name=%s, agent_groups=%s",
            cluster_name ? cluster_name : "",
            agent_groups ? agent_groups : "");
    return true;
}

// Callback to send stateless messages
static int wm_agent_info_send_stateless(const char* message)
{
    if (wm_agent_info_is_shutting_down())
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
        // Aborted by shutdown: exit quietly.
        if (wm_agent_info_is_shutting_down())
        {
            return -1;
        }

        mdebug1("Failed to send message to queue, attempting reconnection.");

        // A negative result here means shutdown, so exit quietly.
        if ((g_agent_info_queue = wm_agent_info_startmq(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0)
        {
            return -1;
        }

        // Try to send it again
        if (SendMSGPredicated(
                g_agent_info_queue, message, WM_AGENT_INFO_LOGTAG, LOCALFILE_MQ, wm_agent_info_is_shutting_down) < 0)
        {
            if (!wm_agent_info_is_shutting_down())
            {
                merror("Error sending message to queue after reconnection");
            }
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

    // Durable task_id registry bounds: not part of this module's ossec.conf configuration
    // surface, so these are internal_options.conf tunables (agent_info.max_entries/
    // agent_info.ttl) rather than an ossec.conf <task_registry> block. Defaults: 4096
    // entries, remembered for 24h (matching remote_upgrade's own TTL, the longest-lived of
    // the four /control task types, since the registry must outlast whichever task type
    // needs the longest at-least-once redelivery window). Cleanup runs on the module's own
    // <interval> cycle (AgentInfoImpl::start()'s loop) -- no separate cadence to configure.
    agent_info->task_registry.max_entries = (uint32_t)getDefine_Int_default("agent_info", "max_entries", 1, 1000000, 4096);
    agent_info->task_registry.ttl_s = (uint32_t)getDefine_Int_default("agent_info", "ttl", 1, 31536000, 86400);

    module->context = &WM_AGENT_INFO_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = agent_info;

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

// Builds a {"error":<code>,"message":"..."} response, the same envelope
// SCA/Syscollector's own query handlers use (module_query_errors.h) so
// agent-info's coordination-facing callers (queryModuleWithRetry,
// task_registry_client.c) parse every module's query response the same way.
static void wm_agent_info_query_error(char** output, int error_code, const char* message)
{
    cJSON* response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", error_code);
    cJSON_AddStringToObject(response, "message", message);
    *output = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);
}

// Query handler: the same generic per-module request/response path
// SCA/Syscollector already use for their own query handlers (wm_find_module +
// module->context->query(), src/wazuh_modules/src/wmodules.c's
// wm_module_query()/wm_module_query_json_ex()) -- no new socket. On
// Linux/macOS it is reached over the existing wmcom request socket
// (WM_LOCAL_SOCK: "query agent-info {...}" -> wmcom_dispatch() ->
// wm_module_query(), which strips "agent-info " and calls this with `args`
// holding exactly the remaining JSON); on Windows, task_registry_client.c
// calls wm_module_query_json_ex("agent-info", ..., ...) directly in-process,
// which reaches this the same way. Supports:
// {"command":"task_check_and_record","task_id":"..."} ->
//   {"error":0,"data":{"new":true|false}}.
// {"command":"vd_offset_observe","offset":N} ->
//   {"error":0,"data":{"changed":bool,"pending":bool,"pending_offset":N}}.
// {"command":"vd_offset_clear_pending","offset":N} ->
//   {"error":0,"data":{"cleared":true|false}}.
// {"command":"vd_offset_get_state"} ->
//   {"error":0,"data":{"has_offset":bool,"offset":N,"pending":bool,"pending_offset":N}}.
size_t wm_agent_info_query(__attribute__((unused)) void* data, char* args, char** output)
{
    cJSON* request = args ? cJSON_Parse(args) : NULL;

    if (!request)
    {
        wm_agent_info_query_error(output, MQ_ERR_INVALID_JSON, MQ_MSG_INVALID_JSON);
        return strlen(*output);
    }

    cJSON* command_item = cJSON_GetObjectItem(request, "command");

    if (!command_item || !cJSON_IsString(command_item))
    {
        cJSON_Delete(request);
        wm_agent_info_query_error(output, MQ_ERR_INVALID_PARAMS, MQ_MSG_INVALID_PARAMS);
        return strlen(*output);
    }

    if (strcmp(command_item->valuestring, "task_check_and_record") == 0)
    {
        cJSON* task_id_item = cJSON_GetObjectItem(request, "task_id");

        if (!task_id_item || !cJSON_IsString(task_id_item) || !task_id_item->valuestring ||
            !*task_id_item->valuestring)
        {
            cJSON_Delete(request);
            wm_agent_info_query_error(output, MQ_ERR_INVALID_PARAMS, MQ_MSG_INVALID_PARAMS);
            return strlen(*output);
        }

        if (!agent_info_task_check_and_record_ptr)
        {
            cJSON_Delete(request);
            wm_agent_info_query_error(output, MQ_ERR_MODULE_NOT_RUNNING, MQ_MSG_MODULE_NOT_RUNNING);
            return strlen(*output);
        }

        int result = agent_info_task_check_and_record_ptr(task_id_item->valuestring);
        cJSON_Delete(request);

        if (result < 0)
        {
            wm_agent_info_query_error(output, MQ_ERR_INTERNAL, MQ_MSG_INTERNAL);
            return strlen(*output);
        }

        cJSON* response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "error", MQ_SUCCESS);
        cJSON* response_data = cJSON_CreateObject();
        cJSON_AddBoolToObject(response_data, "new", result == 1);
        cJSON_AddItemToObject(response, "data", response_data);
        *output = cJSON_PrintUnformatted(response);
        cJSON_Delete(response);
        return strlen(*output);
    }

    if (strcmp(command_item->valuestring, "vd_offset_observe") == 0)
    {
        cJSON* offset_item = cJSON_GetObjectItem(request, "offset");

        if (!offset_item || !cJSON_IsNumber(offset_item))
        {
            cJSON_Delete(request);
            wm_agent_info_query_error(output, MQ_ERR_INVALID_PARAMS, MQ_MSG_INVALID_PARAMS);
            return strlen(*output);
        }

        if (!agent_info_vd_offset_observe_ptr)
        {
            cJSON_Delete(request);
            wm_agent_info_query_error(output, MQ_ERR_MODULE_NOT_RUNNING, MQ_MSG_MODULE_NOT_RUNNING);
            return strlen(*output);
        }

        uint64_t offset = (uint64_t)offset_item->valuedouble;
        int out_changed = 0;
        int out_pending = 0;
        uint64_t out_pending_offset = 0;
        int result = agent_info_vd_offset_observe_ptr(offset, &out_changed, &out_pending, &out_pending_offset);
        cJSON_Delete(request);

        if (result < 0)
        {
            wm_agent_info_query_error(output, MQ_ERR_INTERNAL, MQ_MSG_INTERNAL);
            return strlen(*output);
        }

        cJSON* response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "error", MQ_SUCCESS);
        cJSON* response_data = cJSON_CreateObject();
        cJSON_AddBoolToObject(response_data, "changed", out_changed != 0);
        cJSON_AddBoolToObject(response_data, "pending", out_pending != 0);
        cJSON_AddNumberToObject(response_data, "pending_offset", (double)out_pending_offset);
        cJSON_AddItemToObject(response, "data", response_data);
        *output = cJSON_PrintUnformatted(response);
        cJSON_Delete(response);
        return strlen(*output);
    }

    if (strcmp(command_item->valuestring, "vd_offset_clear_pending") == 0)
    {
        cJSON* offset_item = cJSON_GetObjectItem(request, "offset");

        if (!offset_item || !cJSON_IsNumber(offset_item))
        {
            cJSON_Delete(request);
            wm_agent_info_query_error(output, MQ_ERR_INVALID_PARAMS, MQ_MSG_INVALID_PARAMS);
            return strlen(*output);
        }

        if (!agent_info_vd_offset_clear_pending_ptr)
        {
            cJSON_Delete(request);
            wm_agent_info_query_error(output, MQ_ERR_MODULE_NOT_RUNNING, MQ_MSG_MODULE_NOT_RUNNING);
            return strlen(*output);
        }

        uint64_t offset = (uint64_t)offset_item->valuedouble;
        int result = agent_info_vd_offset_clear_pending_ptr(offset);
        cJSON_Delete(request);

        if (result < 0)
        {
            wm_agent_info_query_error(output, MQ_ERR_INTERNAL, MQ_MSG_INTERNAL);
            return strlen(*output);
        }

        cJSON* response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "error", MQ_SUCCESS);
        cJSON* response_data = cJSON_CreateObject();
        cJSON_AddBoolToObject(response_data, "cleared", result == 1);
        cJSON_AddItemToObject(response, "data", response_data);
        *output = cJSON_PrintUnformatted(response);
        cJSON_Delete(response);
        return strlen(*output);
    }

    if (strcmp(command_item->valuestring, "vd_offset_get_state") == 0)
    {
        cJSON_Delete(request);

        if (!agent_info_vd_offset_get_state_ptr)
        {
            wm_agent_info_query_error(output, MQ_ERR_MODULE_NOT_RUNNING, MQ_MSG_MODULE_NOT_RUNNING);
            return strlen(*output);
        }

        int out_has_offset = 0;
        uint64_t out_offset = 0;
        int out_pending = 0;
        uint64_t out_pending_offset = 0;
        int result = agent_info_vd_offset_get_state_ptr(&out_has_offset, &out_offset, &out_pending, &out_pending_offset);

        if (result < 0)
        {
            wm_agent_info_query_error(output, MQ_ERR_INTERNAL, MQ_MSG_INTERNAL);
            return strlen(*output);
        }

        cJSON* response = cJSON_CreateObject();
        cJSON_AddNumberToObject(response, "error", MQ_SUCCESS);
        cJSON* response_data = cJSON_CreateObject();
        cJSON_AddBoolToObject(response_data, "has_offset", out_has_offset != 0);
        cJSON_AddNumberToObject(response_data, "offset", (double)out_offset);
        cJSON_AddBoolToObject(response_data, "pending", out_pending != 0);
        cJSON_AddNumberToObject(response_data, "pending_offset", (double)out_pending_offset);
        cJSON_AddItemToObject(response, "data", response_data);
        *output = cJSON_PrintUnformatted(response);
        cJSON_Delete(response);
        return strlen(*output);
    }

    /* Echo the unrecognized command back in "data.command", matching
     * SCA/Syscollector's own query() unknown-command responses
     * (sca_impl.cpp/syscollectorImp.cpp: response["data"]["command"] =
     * command) -- wm_agent_info_query_error() alone (used for every other
     * error path above) never adds a "data" object, so this one path is
     * built by hand instead. */
    char unknown_command[128];
    strncpy(unknown_command, command_item->valuestring, sizeof(unknown_command) - 1);
    unknown_command[sizeof(unknown_command) - 1] = '\0';
    cJSON_Delete(request);

    cJSON* response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", MQ_ERR_UNKNOWN_COMMAND);
    cJSON_AddStringToObject(response, "message", MQ_MSG_UNKNOWN_COMMAND);
    cJSON* response_data = cJSON_CreateObject();
    cJSON_AddStringToObject(response_data, "command", unknown_command);
    cJSON_AddItemToObject(response, "data", response_data);
    *output = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);
    return strlen(*output);
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

    mdebug1("Module enabled.");

    if (!agent_info)
    {
        merror("Agent-info configuration is NULL. Exiting.");
        return NULL;
    }

    // Initialize message queue
    g_agent_info_queue = wm_agent_info_startmq(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

    if (g_agent_info_queue < 0)
    {
        // A negative result here means shutdown, so don't log an error.
        if (!wm_agent_info_is_shutting_down())
        {
            merror("Cannot initialize agent-info message queue.");
        }
        return NULL;
    }

    mdebug1("Agent-info message queue initialized successfully.");

    // Set synchronization parameters from configuration
    agent_info_enable_synchronization = agent_info->sync.enable_synchronization;

    // Get module handle and function pointers
    if (agent_info_module = so_get_module_handle(AGENT_INFO_LIB_NAME), agent_info_module)
    {
        mdebug1("Successfully loaded agent-info library");
        agent_info_start_ptr = so_get_function_sym(agent_info_module, "agent_info_start");
        agent_info_stop_ptr = so_get_function_sym(agent_info_module, "agent_info_stop");
        agent_info_cleanup_ptr = so_get_function_sym(agent_info_module, "agent_info_cleanup");
        agent_info_set_log_function_ptr = so_get_function_sym(agent_info_module, "agent_info_set_log_function");
        agent_info_set_report_function_ptr = so_get_function_sym(agent_info_module, "agent_info_set_report_function");
        agent_info_init_sync_protocol_ptr = so_get_function_sym(agent_info_module, "agent_info_init_sync_protocol");
        agent_info_set_query_module_function_ptr =
            so_get_function_sym(agent_info_module, "agent_info_set_query_module_function");
        agent_info_set_is_shutting_down_function_ptr =
            so_get_function_sym(agent_info_module, "agent_info_set_is_shutting_down_function");
        agent_info_set_cluster_name_ptr = so_get_function_sym(agent_info_module, "agent_info_set_cluster_name");
        agent_info_set_agent_groups_ptr = so_get_function_sym(agent_info_module, "agent_info_set_agent_groups");
        agent_info_set_query_handshake_function_ptr =
            so_get_function_sym(agent_info_module, "agent_info_set_query_handshake_function");

        // Durable task_id registry function pointers
        agent_info_task_registry_init_ptr = so_get_function_sym(agent_info_module, "agent_info_task_registry_init");
        agent_info_task_check_and_record_ptr =
            so_get_function_sym(agent_info_module, "agent_info_task_check_and_record");

        // Durable VD feed offset / pending-rescan function pointers
        agent_info_vd_offset_observe_ptr = so_get_function_sym(agent_info_module, "agent_info_vd_offset_observe");
        agent_info_vd_offset_clear_pending_ptr =
            so_get_function_sym(agent_info_module, "agent_info_vd_offset_clear_pending");
        agent_info_vd_offset_get_state_ptr = so_get_function_sym(agent_info_module, "agent_info_vd_offset_get_state");

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

        // Let the implementation know when a shutdown is in progress so it can demote
        // expected shutdown-time sync/coordination failures from WARNING to DEBUG.
        if (agent_info_set_is_shutting_down_function_ptr)
        {
            agent_info_set_is_shutting_down_function_ptr(wm_agent_info_is_shutting_down);
        }

        // Set the handshake query function so agent-info can re-query agentd for fresh
        // cluster_name/agent_groups on every metadata population cycle
        if (agent_info_set_query_handshake_function_ptr)
        {
            agent_info_set_query_handshake_function_ptr(wm_agent_info_query_agentd_handshake);
        }
    }
    else
    {
        merror("Can't get agent-info module handle for library: lib%s.so", AGENT_INFO_LIB_NAME);
        return NULL;
    }

    if (agent_info_init_sync_protocol_ptr)
    {
        agent_info_init_sync_protocol_ptr(AGENT_INFO_WM_NAME);
    }

    // Durable task_id registry: initialize before the handshake wait/coordinator
    // loop below, so it is ready the moment agentd's first /control dedup query can arrive.
    // Periodic cleanup runs automatically from within AgentInfoImpl::start()'s own loop
    // -- no separate thread spawned here anymore.
    if (agent_info_task_registry_init_ptr)
    {
        agent_info_task_registry_init_ptr(agent_info->task_registry.max_entries,
                                          agent_info->task_registry.ttl_s);
    }
    else
    {
        merror("agent_info_task_registry_init function not available; /control task dedup will "
               "fail closed (every task treated as non-dispatchable) until this is fixed.");
    }

    // Query agentd for handshake data (cluster_name, agent_groups) via agcom
    char cluster_name[256] = {0};
    char agent_groups[OS_SIZE_65536] = {0};
    bool handshake_success = false;

    while (!handshake_success && !wm_agent_info_is_shutting_down())
    {
        if (wm_agent_info_query_agentd_handshake(cluster_name,
                                                 sizeof(cluster_name),
                                                 agent_groups,
                                                 sizeof(agent_groups)))
        {
            handshake_success = true;
            if (cluster_name[0] != '\0' && agent_info_set_cluster_name_ptr)
            {
                agent_info_set_cluster_name_ptr(cluster_name);
                mdebug1("Cluster name received from agentd: %s", cluster_name);
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
            wm_sleep_interruptible(1);
        }
    }

    if (wm_agent_info_is_shutting_down())
    {
        mdebug1("Shutdown requested during handshake wait, exiting.");
        return NULL;
    }

    // Initialize the C++ implementation (this will create the AgentInfoImpl with the callbacks)
    // This call will populate the agent metadata and send it to the queue
    if (agent_info_start_ptr)
    {
        minfo(STARTUP_MSG, (int)getpid());
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

        if (agent_info_cleanup_ptr)
        {
            agent_info_cleanup_ptr();
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

        // Durable task_id registry values -- internal_options.conf tunables
        // (agent_info.max_entries/agent_info.ttl), not ossec.conf, but still worth
        // surfacing in the config dump for diagnostics.
        cJSON* task_registry = cJSON_CreateObject();
        cJSON_AddNumberToObject(task_registry, "max_entries", agent_info->task_registry.max_entries);
        cJSON_AddNumberToObject(task_registry, "ttl", agent_info->task_registry.ttl_s);

        cJSON_AddItemToObject(wm_agent_info, "task_registry", task_registry);
    }

    cJSON_AddItemToObject(root, "agent-info", wm_agent_info);
    return root;
}
