/*
 * Wazuh SYSCOLLECTOR
 * Copyright (C) 2015, Wazuh Inc.
 * November 11, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <stdlib.h>
#include "wmodules_def.h"
#include "syscollector.h"
#include "wmodules.h"
#include "module_query_errors.h"
#include "wm_syscollector.h"
#include "syscollector.h"
#include "sym_load.h"
#include "defs.h"
#include "mq_op.h"
#include "logging_helper.h"
#include "commonDefs.h"
#ifndef WIN32
#include "os_net.h"
#include <unistd.h>
#else
#include "agentd.h"
// Forward declaration - agcom_dispatch is available in the same process on Windows
extern size_t agcom_dispatch(char * command, char ** output);
#endif

#define SYS_SYNC_PROTOCOL_DB_PATH "queue/syscollector/db/syscollector_sync.db"
#define SYS_SYNC_PROTOCOL_VD_DB_PATH "queue/syscollector/db/syscollector_vd_sync.db"
#define SYS_SYNC_RETRIES 3

// Global flag to stop sync module
static volatile int sync_module_running = 0;

#ifdef WIN32
static DWORD WINAPI wm_sys_main(void* arg);         // Module main function. It won't return
static DWORD WINAPI wm_sync_module(__attribute__((unused)) void* args);
#else
static void* wm_sys_main(wm_sys_t* sys);        // Module main function. It won't return
static void* wm_sync_module(__attribute__((unused)) void* args);
#endif
static void wm_sys_destroy(wm_sys_t* data);      // Destroy data
static void wm_sys_stop(wm_sys_t* sys);         // Module stopper
const char* WM_SYS_LOCATION = "syscollector";   // Location field for event sending
cJSON* wm_sys_dump(const wm_sys_t* sys);
int wm_sync_message(const char* command, size_t command_len);
pthread_cond_t sys_stop_condition = PTHREAD_COND_INITIALIZER;
pthread_mutex_t sys_stop_mutex = PTHREAD_MUTEX_INITIALIZER;
bool need_shutdown_wait = false;
pthread_mutex_t sys_reconnect_mutex = PTHREAD_MUTEX_INITIALIZER;
bool shutdown_process_started = false;

static size_t wm_sys_query_handler(void* data, char* query, char** output); // Query handler

const wm_context WM_SYS_CONTEXT =
{
    .name = SYSCOLLECTOR_WM_NAME,
    .start = (wm_routine)wm_sys_main,
    .destroy = (void(*)(void*))wm_sys_destroy,
    .dump = (cJSON * (*)(const void*))wm_sys_dump,
    .sync = (int(*)(const char*, size_t))wm_sync_message,
    .stop = (void(*)(void*))wm_sys_stop,
    .query = wm_sys_query_handler,
};

void* syscollector_module = NULL;

syscollector_init_func syscollector_init_ptr = NULL;
syscollector_start_func syscollector_start_ptr = NULL;
syscollector_stop_func syscollector_stop_ptr = NULL;

// Sync protocol function pointers
syscollector_init_sync_func syscollector_init_sync_ptr = NULL;
syscollector_sync_module_func syscollector_sync_module_ptr = NULL;
syscollector_persist_diff_func syscollector_persist_diff_ptr = NULL;
syscollector_parse_response_func syscollector_parse_response_ptr = NULL;
syscollector_parse_response_vd_func syscollector_parse_response_vd_ptr = NULL;
syscollector_notify_data_clean_func syscollector_notify_data_clean_ptr = NULL;
syscollector_delete_database_func syscollector_delete_database_ptr = NULL;

// Query function pointer
typedef size_t (*syscollector_query_func)(const char* query, char** output);
syscollector_query_func syscollector_query_ptr = NULL;

// Mutex access function pointers
typedef void (*syscollector_lock_scan_mutex_func)();
typedef void (*syscollector_unlock_scan_mutex_func)();
syscollector_lock_scan_mutex_func syscollector_lock_scan_mutex_ptr = NULL;
syscollector_unlock_scan_mutex_func syscollector_unlock_scan_mutex_ptr = NULL;

typedef void (*syscollector_run_recovery_process_func)();
syscollector_run_recovery_process_func syscollector_run_recovery_process_ptr = NULL;

// agentd query function setter pointer (cross-platform)
typedef void (*syscollector_set_agentd_query_func_ptr)(agentd_query_func_t);
syscollector_set_agentd_query_func_ptr syscollector_set_agentd_query_func_setter = NULL;

unsigned int enable_synchronization = 1;     // Database synchronization enabled (default value)
uint32_t sync_interval = 300;                // Database synchronization interval (default value)
uint32_t sync_end_delay = 1;                 // Database synchronization end delay in seconds (default value)
uint32_t sync_response_timeout = 30;         // Database synchronization response timeout (default value)
long sync_max_eps = 50;                     // Database synchronization number of events per second (default value)
uint32_t integrity_interval = 86400;         // Integrity check interval in seconds (default value)

long syscollector_max_eps = 50;          // Number of events per second (default value)
int queue_fd = 0;                        // Output queue file descriptor

static bool is_shutdown_process_started()
{
    bool ret_val = shutdown_process_started;
    return ret_val;
}

bool wm_sys_query_agentd(const char* command, char* output_buffer, size_t buffer_size)
{
    if (!command || !output_buffer || buffer_size == 0)
    {
        return false;
    }

    // Temporary buffer for receiving full response (including "ok " or "err " prefix)
    char response_buffer[OS_MAXSTR];
    ssize_t response_length = 0;

#ifndef WIN32
    // Unix/Linux: Use socket communication to get response into buffer
    const char* AGENT_SOCKET = "queue/sockets/agent";
    const size_t MAX_RECV_SIZE = sizeof(response_buffer) - 1;

    // Connect to agent socket
    int sock = OS_ConnectUnixDomain(AGENT_SOCKET, SOCK_STREAM, MAX_RECV_SIZE);
    if (sock < 0)
    {
        mtdebug1(WM_SYS_LOGTAG, "Could not connect to agent socket: %s", strerror(errno));
        return false;
    }

    // Send request
    if (OS_SendSecureTCP(sock, strlen(command), command) != 0)
    {
        mterror(WM_SYS_LOGTAG, "Failed to send request to agent socket: %s", strerror(errno));
        close(sock);
        return false;
    }

    // Receive response (leave room for null terminator)
    memset(response_buffer, 0, sizeof(response_buffer));
    response_length = OS_RecvSecureTCP(sock, response_buffer, MAX_RECV_SIZE);
    close(sock);

    if (response_length <= 0)
    {
        if (response_length == 0)
        {
            mtdebug1(WM_SYS_LOGTAG, "Empty response from agent socket");
        }
        else if (response_length == -2)  // OS_SOCKTERR
        {
            mterror(WM_SYS_LOGTAG, "Maximum buffer length reached reading from agent socket");
        }
        else
        {
            mterror(WM_SYS_LOGTAG, "Failed to receive response from agent socket: %s", strerror(errno));
        }
        return false;
    }

    // Ensure null termination (response_length is guaranteed <= MAX_RECV_SIZE)
    response_buffer[response_length] = '\0';
#else
    // Windows: Use agcom_dispatch and copy response into buffer
    // agcom_dispatch() mutates the command buffer (it splits "cmd args" in-place).
    // Copy to a writable buffer since callers typically pass string literals.
    char command_buffer[OS_MAXSTR];
    strncpy(command_buffer, command, sizeof(command_buffer) - 1);
    command_buffer[sizeof(command_buffer) - 1] = '\0';

    char* output = NULL;
    size_t result = agcom_dispatch(command_buffer, &output);

    if (result == 0 || !output)
    {
        // Free output if allocated (defensive, in case agcom_dispatch allocated but failed)
        os_free(output);
        mtdebug1(WM_SYS_LOGTAG, "Failed to query agentd via agcom_dispatch");
        return false;
    }

    // Copy response to our temporary buffer (safely)
    size_t output_len = strlen(output);
    size_t max_copy = sizeof(response_buffer) - 1;
    if (output_len > max_copy)
    {
        mtwarn(WM_SYS_LOGTAG, "Response too large (%zu bytes), truncating to %zu bytes",
               output_len, max_copy);
        output_len = max_copy;
    }

    memcpy(response_buffer, output, output_len);
    response_buffer[output_len] = '\0';
    response_length = output_len;
    os_free(output);
#endif

    // Common response parsing (works for both platforms)
    mtdebug2(WM_SYS_LOGTAG, "Response from agentd: %s", response_buffer);

    // Check if response starts with "ok "
    if (response_length >= 3 && strncmp(response_buffer, "ok ", 3) == 0)
    {
        // Copy JSON part (after "ok ") to output buffer
        const char* json_start = response_buffer + 3;
        size_t json_len = strlen(json_start);

        if (json_len >= buffer_size)
        {
            mterror(WM_SYS_LOGTAG, "Output buffer too small (%zu bytes needed, %zu available)",
                    json_len + 1, buffer_size);
            return false;
        }

        strncpy(output_buffer, json_start, buffer_size - 1);
        output_buffer[buffer_size - 1] = '\0';
        return true;
    }
    else if (response_length >= 4 && strncmp(response_buffer, "err ", 4) == 0)
    {
        // Error response from agentd
        mtdebug1(WM_SYS_LOGTAG, "Agentd returned error: %s", response_buffer + 4);
        return false;
    }
    else
    {
        mterror(WM_SYS_LOGTAG, "Unexpected response format from agentd: %s", response_buffer);
        return false;
    }
}

static void wm_sys_send_message(const void* data, const char queue_id)
{
    if (!is_shutdown_process_started())
    {
        const int eps = 1000000 / syscollector_max_eps;

        if (wm_sendmsg_ex(eps, queue_fd, data, WM_SYS_LOCATION, queue_id, &is_shutdown_process_started) < 0)
        {
            mtdebug1(WM_SYS_LOGTAG, "Unable to send message to '%s'", DEFAULTQUEUE);

            // Since this method is beign called by multiple threads it's necessary this particular portion of code
            // to be mutually exclusive. When one thread is successfully reconnected, the other ones will make use of it.
            w_mutex_lock(&sys_reconnect_mutex);

            if (!is_shutdown_process_started() && wm_sendmsg_ex(eps, queue_fd, data, WM_SYS_LOCATION, queue_id, &is_shutdown_process_started) < 0)
            {
                if (queue_fd = MQReconnectPredicated(DEFAULTQUEUE, &is_shutdown_process_started), 0 <= queue_fd)
                {
                    mtinfo(WM_SYS_LOGTAG, "Successfully reconnected to '%s'", DEFAULTQUEUE);

                    if (wm_sendmsg_ex(eps, queue_fd, data, WM_SYS_LOCATION, queue_id, &is_shutdown_process_started) < 0)
                    {
                        mterror(WM_SYS_LOGTAG, "Unable to send message to '%s' after a successfull reconnection...", DEFAULTQUEUE);
                    }
                }
            }

            w_mutex_unlock(&sys_reconnect_mutex);
        }
    }
}

static void wm_sys_send_diff_message(const void* data)
{
    wm_sys_send_message(data, SYSCOLLECTOR_MQ);
}

static void wm_sys_persist_diff_message(const char* id, Operation_t operation, const char* index, const void* data, uint64_t version)
{
    if (enable_synchronization && syscollector_persist_diff_ptr)
    {
        const char* msg = (const char*)data;
        mtdebug2(WM_SYS_LOGTAG, "Persisting Inventory event: %s", msg);
        syscollector_persist_diff_ptr(id, operation, index, msg, version);
    }
    else
    {
        mtdebug2(WM_SYS_LOGTAG, "Inventory synchronization is disabled or function not available");
    }
}

static void wm_sys_log_config(wm_sys_t* sys)
{
    cJSON* config_json = wm_sys_dump(sys);

    if (config_json)
    {
        char* config_str = cJSON_PrintUnformatted(config_json);

        if (config_str)
        {
            mtdebug1(WM_SYS_LOGTAG, "%s", config_str);
            cJSON_free(config_str);
        }

        cJSON_Delete(config_json);
    }
}

static int wm_sys_startmq(const char* key, short type, short attempts)
{
    return StartMQPredicated(key, type, attempts, &is_shutdown_process_started);
}

static int wm_sys_send_binary_msg(int queue, const void* message, size_t message_len, const char* locmsg, char loc)
{
    return SendBinaryMSG(queue, message, message_len, locmsg, loc);
}

static void wm_handle_sys_disabled_and_notify_data_clean(wm_sys_t* sys)
{

    if (w_is_file(SYSCOLLECTOR_DB_DISK_PATH))
    {
        mtinfo(WM_SYS_LOGTAG, "Syscollector is disabled, Syscollector database file exists. Proceeding with data clean notification.");
    }
    else
    {
        mtinfo(WM_SYS_LOGTAG, "Syscollector is disabled, Syscollector database file does not exist. Skipping data clean notification.");
        return;
    }

    if (syscollector_module = so_get_module_handle("syscollector"), syscollector_module)
    {

        syscollector_init_ptr = so_get_function_sym(syscollector_module, "syscollector_init");

        // Get sync protocol function pointers
        syscollector_init_sync_ptr = so_get_function_sym(syscollector_module, "syscollector_init_sync");
        syscollector_parse_response_ptr = so_get_function_sym(syscollector_module, "syscollector_parse_response");
        syscollector_parse_response_vd_ptr = so_get_function_sym(syscollector_module, "syscollector_parse_response_vd");
        syscollector_notify_data_clean_ptr = so_get_function_sym(syscollector_module, "syscollector_notify_data_clean");
        syscollector_delete_database_ptr = so_get_function_sym(syscollector_module, "syscollector_delete_database");

        syscollector_init_ptr(sys->interval,
                              wm_sys_send_diff_message,
                              wm_sys_persist_diff_message,
                              taggedLogFunction,
                              SYSCOLLECTOR_DB_DISK_PATH,
                              SYSCOLLECTOR_NORM_CONFIG_DISK_PATH,
                              SYSCOLLECTOR_NORM_TYPE,
                              sys->flags.scan_on_start,
                              sys->flags.hwinfo,
                              sys->flags.osinfo,
                              sys->flags.netinfo,
                              sys->flags.programinfo,
                              sys->flags.portsinfo,
                              sys->flags.allports,
                              sys->flags.procinfo,
                              sys->flags.hotfixinfo,
                              sys->flags.groups,
                              sys->flags.users,
                              sys->flags.services,
                              sys->flags.browser_extensions,
                              sys->flags.notify_first_scan);

        MQ_Functions mq_funcs =
        {
            .start = wm_sys_startmq,
            .send_binary = wm_sys_send_binary_msg
        };
        syscollector_init_sync_ptr(WM_SYS_LOCATION, SYS_SYNC_PROTOCOL_DB_PATH, SYS_SYNC_PROTOCOL_VD_DB_PATH, &mq_funcs, sync_end_delay, sync_response_timeout, SYS_SYNC_RETRIES, sync_max_eps, integrity_interval);

        if (syscollector_notify_data_clean_ptr && syscollector_delete_database_ptr)
        {
            const char* indices[] =
            {
                SYSCOLLECTOR_SYNC_INDEX_SYSTEM,
                SYSCOLLECTOR_SYNC_INDEX_HARDWARE,
                SYSCOLLECTOR_SYNC_INDEX_HOTFIXES,
                SYSCOLLECTOR_SYNC_INDEX_PACKAGES,
                SYSCOLLECTOR_SYNC_INDEX_PROCESSES,
                SYSCOLLECTOR_SYNC_INDEX_PORTS,
                SYSCOLLECTOR_SYNC_INDEX_INTERFACES,
                SYSCOLLECTOR_SYNC_INDEX_PROTOCOLS,
                SYSCOLLECTOR_SYNC_INDEX_NETWORKS,
                SYSCOLLECTOR_SYNC_INDEX_USERS,
                SYSCOLLECTOR_SYNC_INDEX_GROUPS,
                SYSCOLLECTOR_SYNC_INDEX_SERVICES,
                SYSCOLLECTOR_SYNC_INDEX_BROWSER_EXTENSIONS,
                SYSCOLLECTOR_SYNC_INDEX_VULNERABILITIES
            };
            size_t indices_count = sizeof(indices) / sizeof(indices[0]);
            bool ret = false;

            while (!ret && !is_shutdown_process_started())
            {
                ret = syscollector_notify_data_clean_ptr(indices, indices_count);

                if (!ret)
                {
                    for (uint32_t i = 0; i < sync_interval && !is_shutdown_process_started(); i++)
                    {
                        sleep(1);
                    }
                }
                else
                {
                    mtdebug1(WM_SYS_LOGTAG, "Syscollector data clean notification sent successfully.");
                    syscollector_delete_database_ptr();
                }
            }
        }
        else
        {
            mtwarn(WM_SYS_LOGTAG, "Syscollector notify data clean functions not available.");
        }

    }
    else
    {
        mtwarn(WM_SYS_LOGTAG, "Failed to load Syscollector module for data clean notification.");
        return;
    }
}

#ifdef WIN32
DWORD WINAPI wm_sys_main(void* arg)
{
    wm_sys_t* sys = (wm_sys_t*)arg;
#else
void* wm_sys_main(wm_sys_t* sys)
{
#endif

    if (sys->flags.running)
    {
        // Already running
        return 0;
    }

    sys->flags.running = true;

    w_cond_init(&sys_stop_condition, NULL);
    w_mutex_init(&sys_stop_mutex, NULL);
    w_mutex_init(&sys_reconnect_mutex, NULL);

    if (!sys->flags.enabled)
    {
        wm_handle_sys_disabled_and_notify_data_clean(sys);
        mtinfo(WM_SYS_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }

#ifndef WIN32
    // Connect to socket
    queue_fd = StartMQPredicated(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS, &is_shutdown_process_started);

    if (queue_fd < 0)
    {
        mterror(WM_SYS_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }

#endif

    if (syscollector_module = so_get_module_handle("syscollector"), syscollector_module)
    {
        syscollector_init_ptr = so_get_function_sym(syscollector_module, "syscollector_init");
        syscollector_start_ptr = so_get_function_sym(syscollector_module, "syscollector_start");
        syscollector_stop_ptr = so_get_function_sym(syscollector_module, "syscollector_stop");

        // Get sync protocol function pointers
        syscollector_init_sync_ptr = so_get_function_sym(syscollector_module, "syscollector_init_sync");
        syscollector_sync_module_ptr = so_get_function_sym(syscollector_module, "syscollector_sync_module");
        syscollector_persist_diff_ptr = so_get_function_sym(syscollector_module, "syscollector_persist_diff");
        syscollector_parse_response_ptr = so_get_function_sym(syscollector_module, "syscollector_parse_response");
        syscollector_parse_response_vd_ptr = so_get_function_sym(syscollector_module, "syscollector_parse_response_vd");

        // Get query function pointer
        syscollector_query_ptr = so_get_function_sym(syscollector_module, "syscollector_query");

        // Get mutex access function pointers
        syscollector_lock_scan_mutex_ptr = so_get_function_sym(syscollector_module, "syscollector_lock_scan_mutex");
        syscollector_unlock_scan_mutex_ptr = so_get_function_sym(syscollector_module, "syscollector_unlock_scan_mutex");

        syscollector_run_recovery_process_ptr = so_get_function_sym(syscollector_module, "syscollector_run_recovery_process");

        // Get agentd query function setter pointer (cross-platform)
        syscollector_set_agentd_query_func_setter = so_get_function_sym(syscollector_module, "syscollector_set_agentd_query_func");
    } else {
        mterror(WM_SYS_LOGTAG, "Can't load syscollector.");
        pthread_exit(NULL);
    }

    if (syscollector_init_ptr && syscollector_start_ptr)
    {
        mtdebug1(WM_SYS_LOGTAG, "Starting Syscollector.");
        w_mutex_lock(&sys_stop_mutex);
        need_shutdown_wait = true;
        w_mutex_unlock(&sys_stop_mutex);

        enable_synchronization = sys->sync.enable_synchronization;

        if (enable_synchronization)
        {
            sync_interval = sys->sync.sync_interval;
            sync_end_delay = sys->sync.sync_end_delay;
            sync_response_timeout = sys->sync.sync_response_timeout;
            sync_max_eps = sys->sync.sync_max_eps;
            integrity_interval = sys->sync.integrity_interval;
        }

        if (sys->max_eps)
        {
            syscollector_max_eps = sys->max_eps;
        }

        wm_sys_log_config(sys);

        // Initialize syscollector FIRST to set up the logger callback
        syscollector_init_ptr(sys->interval,
                              wm_sys_send_diff_message,
                              wm_sys_persist_diff_message,
                              taggedLogFunction,
                              SYSCOLLECTOR_DB_DISK_PATH,
                              SYSCOLLECTOR_NORM_CONFIG_DISK_PATH,
                              SYSCOLLECTOR_NORM_TYPE,
                              sys->flags.scan_on_start,
                              sys->flags.hwinfo,
                              sys->flags.osinfo,
                              sys->flags.netinfo,
                              sys->flags.programinfo,
                              sys->flags.portsinfo,
                              sys->flags.allports,
                              sys->flags.procinfo,
                              sys->flags.hotfixinfo,
                              sys->flags.groups,
                              sys->flags.users,
                              sys->flags.services,
                              sys->flags.browser_extensions,
                              sys->flags.notify_first_scan);

        // Set agentd query function for communication (AFTER init, BEFORE start)
        // Syscollector will fetch document limits from agentd
        if (syscollector_set_agentd_query_func_setter)
        {
            syscollector_set_agentd_query_func_setter(wm_sys_query_agentd);
            mtdebug1(WM_SYS_LOGTAG, "Agentd query function configured for document limits.");
        }
        else
        {
            mtdebug1(WM_SYS_LOGTAG, "Agentd query function setter not available.");
        }

        // Initialize sync protocol AFTER init (so logger is available)
        if (enable_synchronization && syscollector_init_sync_ptr && syscollector_sync_module_ptr)
        {
            MQ_Functions mq_funcs =
            {
                .start = wm_sys_startmq,
                .send_binary = wm_sys_send_binary_msg
            };
            syscollector_init_sync_ptr(WM_SYS_LOCATION, SYS_SYNC_PROTOCOL_DB_PATH, SYS_SYNC_PROTOCOL_VD_DB_PATH, &mq_funcs, sync_end_delay, sync_response_timeout, SYS_SYNC_RETRIES, sync_max_eps, integrity_interval);
#ifndef WIN32
            // Launch inventory synchronization thread
            sync_module_running = 1;
            w_create_thread(wm_sync_module, NULL);
#else
            sync_module_running = 1;

            if (CreateThread(NULL, 0, wm_sync_module, NULL, 0, NULL) == NULL)
            {
                mterror(WM_SYS_LOGTAG, THREAD_ERROR);
            }

#endif
        }
        else
        {
            mtdebug1(WM_SYS_LOGTAG, "Inventory synchronization is disabled or function not available");
        }

        syscollector_start_ptr();
    }
    else
    {
        mterror(WM_SYS_LOGTAG, "Can't get syscollector_start_ptr.");
        pthread_exit(NULL);
    }

    syscollector_init_ptr = NULL;
    syscollector_start_ptr = NULL;
    syscollector_stop_ptr = NULL;

    if (queue_fd)
    {
        close(queue_fd);
        queue_fd = 0;
    }

    mtinfo(WM_SYS_LOGTAG, "Module finished.");
    w_mutex_lock(&sys_stop_mutex);
    need_shutdown_wait = false;
    w_cond_signal(&sys_stop_condition);
    w_mutex_unlock(&sys_stop_mutex);
    return 0;
}

void wm_sys_destroy(wm_sys_t* data)
{
    w_cond_destroy(&sys_stop_condition);
    w_mutex_destroy(&sys_stop_mutex);
    w_mutex_destroy(&sys_reconnect_mutex);

    free(data);
}

void wm_sys_stop(__attribute__((unused))wm_sys_t* data)
{
    if (!data->flags.running)
    {
        // Already stopped
        return;
    }

    data->flags.running = false;

    // Stop sync module
    sync_module_running = 0;

    mtinfo(WM_SYS_LOGTAG, "Stop received for Syscollector.");

    if (syscollector_stop_ptr)
    {
        shutdown_process_started = true;
        syscollector_stop_ptr();
    }
    w_mutex_lock(&sys_stop_mutex);
    while (need_shutdown_wait) {
        w_cond_wait(&sys_stop_condition, &sys_stop_mutex);
    }
    w_mutex_unlock(&sys_stop_mutex);
}

cJSON* wm_sys_dump(const wm_sys_t* sys)
{
    cJSON* root = cJSON_CreateObject();
    cJSON* wm_sys = cJSON_CreateObject();

    // System provider values
    if (sys->flags.enabled) cJSON_AddStringToObject(wm_sys, "disabled", "no");
    else cJSON_AddStringToObject(wm_sys, "disabled", "yes");

    if (sys->flags.scan_on_start) cJSON_AddStringToObject(wm_sys, "scan-on-start", "yes");
    else cJSON_AddStringToObject(wm_sys, "scan-on-start", "no");

    cJSON_AddNumberToObject(wm_sys, "interval", sys->interval);
    cJSON_AddNumberToObject(wm_sys, "max_eps", sys->max_eps);

    if (sys->flags.notify_first_scan) cJSON_AddStringToObject(wm_sys, "notify_first_scan", "yes");
    else cJSON_AddStringToObject(wm_sys, "notify_first_scan", "no");

    if (sys->flags.netinfo) cJSON_AddStringToObject(wm_sys, "network", "yes");
    else cJSON_AddStringToObject(wm_sys, "network", "no");

    if (sys->flags.osinfo) cJSON_AddStringToObject(wm_sys, "os", "yes");
    else cJSON_AddStringToObject(wm_sys, "os", "no");

    if (sys->flags.hwinfo) cJSON_AddStringToObject(wm_sys, "hardware", "yes");
    else cJSON_AddStringToObject(wm_sys, "hardware", "no");

    if (sys->flags.programinfo) cJSON_AddStringToObject(wm_sys, "packages", "yes");
    else cJSON_AddStringToObject(wm_sys, "packages", "no");

    if (sys->flags.portsinfo) cJSON_AddStringToObject(wm_sys, "ports", "yes");
    else cJSON_AddStringToObject(wm_sys, "ports", "no");

    if (sys->flags.allports) cJSON_AddStringToObject(wm_sys, "ports_all", "yes");
    else cJSON_AddStringToObject(wm_sys, "ports_all", "no");

    if (sys->flags.procinfo) cJSON_AddStringToObject(wm_sys, "processes", "yes");
    else cJSON_AddStringToObject(wm_sys, "processes", "no");

    if (sys->flags.groups) cJSON_AddStringToObject(wm_sys, "groups", "yes");
    else cJSON_AddStringToObject(wm_sys, "groups", "no");

    if (sys->flags.users) cJSON_AddStringToObject(wm_sys, "users", "yes");
    else cJSON_AddStringToObject(wm_sys, "users", "no");

    if (sys->flags.services) cJSON_AddStringToObject(wm_sys, "services", "yes");
    else cJSON_AddStringToObject(wm_sys, "services", "no");

    if (sys->flags.browser_extensions) cJSON_AddStringToObject(wm_sys, "browser_extensions", "yes");
    else cJSON_AddStringToObject(wm_sys, "browser_extensions", "no");

#ifdef WIN32

    if (sys->flags.hotfixinfo) cJSON_AddStringToObject(wm_sys, "hotfixes", "yes");
    else cJSON_AddStringToObject(wm_sys, "hotfixes", "no");

#endif

    // Database synchronization values
    cJSON* synchronization = cJSON_CreateObject();
    cJSON_AddStringToObject(synchronization, "enabled", sys->sync.enable_synchronization ? "yes" : "no");
    cJSON_AddNumberToObject(synchronization, "interval", sys->sync.sync_interval);
    cJSON_AddNumberToObject(synchronization, "max_eps", sys->sync.sync_max_eps);
    cJSON_AddNumberToObject(synchronization, "response_timeout", sys->sync.sync_response_timeout);
    cJSON_AddNumberToObject(synchronization, "sync_end_delay", sys->sync.sync_end_delay);
    cJSON_AddNumberToObject(synchronization, "integrity_interval", sys->sync.integrity_interval);

    cJSON_AddItemToObject(wm_sys, "synchronization", synchronization);

    cJSON_AddItemToObject(root, "syscollector", wm_sys);

    return root;
}

int wm_sync_message(const char* command, size_t command_len)
{
    if (enable_synchronization)
    {
        bool ret = false;
        size_t header_len;
        const uint8_t* data;
        size_t data_len;

        // Check if this is a VD message by looking for "_vd" in the command
        if (strstr(command, "_vd") != NULL)
        {
            // Route to VD parser with VD-specific header length
            header_len = strlen(SYSCOLECTOR_VD_SYNC_HEADER);
            data = (const uint8_t*)(command + header_len);
            data_len = command_len - header_len;

            if (syscollector_parse_response_vd_ptr)
            {
                mtdebug2(WM_SYS_LOGTAG, "Routing message to VD parser");
                ret = syscollector_parse_response_vd_ptr(data, data_len);
            }
            else
            {
                mtdebug1(WM_SYS_LOGTAG, "VD parser function not available");
                return -1;
            }
        }
        else
        {
            // Route to regular parser with regular header length
            header_len = strlen(SYSCOLECTOR_SYNC_HEADER);
            data = (const uint8_t*)(command + header_len);
            data_len = command_len - header_len;

            if (syscollector_parse_response_ptr)
            {
                mtdebug2(WM_SYS_LOGTAG, "Routing message to regular parser");
                ret = syscollector_parse_response_ptr(data, data_len);
            }
            else
            {
                mtdebug1(WM_SYS_LOGTAG, "Regular parser function not available");
                return -1;
            }
        }

        if (!ret)
        {
            mtdebug1(WM_SYS_LOGTAG, "Error syncing module");
            return -1;
        }

        return 0;
    }
    else
    {
        mtdebug1(WM_SYS_LOGTAG, "Inventory synchronization is disabled or function not available");
        return -1;
    }
}

#ifdef WIN32
DWORD WINAPI wm_sync_module(__attribute__((unused)) void* args)
{
#else
void* wm_sync_module(__attribute__((unused)) void* args)
{
#endif

    // Initial wait until syscollector is started
    for (uint32_t i = 0; i < sync_interval && sync_module_running; i++)
    {
        sleep(1);
    }

    while (sync_module_running) {
        if (syscollector_sync_module_ptr) {
            syscollector_lock_scan_mutex_ptr();

            bool sync_result = syscollector_sync_module_ptr(MODE_DELTA);

            if (sync_result) {
                syscollector_run_recovery_process_ptr();
            }

            syscollector_unlock_scan_mutex_ptr();
        } else {
            mtdebug1(WM_SYS_LOGTAG, "Sync function not available");
        }

        // Sleep in small intervals to allow responsive stopping
        for (uint32_t i = 0; i < sync_interval && sync_module_running; i++)
        {
            sleep(1);
        }
    }

#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}

static size_t wm_sys_query_handler(void* data, char* query, char** output)
{
    (void)data;  // Unused parameter

    if (!query || !output)
    {
        return 0;
    }

    // Call the C++ query function if available
    if (syscollector_query_ptr)
    {
        return syscollector_query_ptr(query, output);
    }
    else
    {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "{\"error\":%d,\"message\":\"%s\"}",
                 MQ_ERR_MODULE_NOT_RUNNING, MQ_MSG_MODULE_NOT_RUNNING);
        os_strdup(error_msg, *output);
        return strlen(*output);
    }
}
