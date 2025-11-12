/*
 * Wazuh Module for Security Configuration Assessment
 * Copyright (C) 2015, Wazuh Inc.
 * January 25, 2019.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules_def.h"

#include "wmodules.h"
#include "module_query_errors.h"
#include <os_net/os_net.h>
#include <sys/stat.h>
#include "os_crypto/sha256/sha256_op.h"
#include "expression.h"
#include "shared.h"
#include "sym_load.h"
#include "mq_op.h"
#include "atomic.h"
#include "defs.h"
#include "logging_helper.h"

#include "sca/include/sca.h"
#include "yaml2json.h"

#define SCA_SYNC_PROTOCOL_DB_PATH "queue/sca/db/sca_sync.db"
#define SCA_SYNC_RETRIES 3

// Global flag to stop sync module
static volatile int sca_sync_module_running = 0;

// SCA message queue variables
static int g_shutting_down = 0;
static int g_sca_queue = 0;
static long g_max_eps = 50;
static atomic_int_t g_n_msg_sent = ATOMIC_INT_INITIALIZER(0);

// SCA sync protocol variables
unsigned int sca_enable_synchronization = 1;     // Database synchronization enabled (default value)
uint32_t sca_sync_interval = 300;                // Database synchronization interval (default value)
uint32_t sca_sync_end_delay = 1;                 // Database synchronization end message delay in seconds (default value)
uint32_t sca_sync_response_timeout = 30;         // Database synchronization response timeout (default value)
long sca_sync_max_eps = 10;                      // Database synchronization number of events per second (default value)

// Forward declarations
static bool wm_sca_is_shutting_down(void);
static int wm_sca_send_stateless(const char* message);
static int wm_sca_persist_stateful(const char* id, Operation_t operation, const char* index, const char* message, uint64_t version);
static cJSON* wm_sca_yaml_to_cjson(const char* yaml_path);

#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...) _mtinfo(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mtwarn(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _mterror(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when testing */
#define static
#endif

#ifdef WIN32
static DWORD WINAPI wm_sca_main(void *arg);         // Module main function. It won't return
static DWORD WINAPI wm_sca_sync_module(__attribute__((unused)) void * args);
#else
static void * wm_sca_main(wm_sca_t * data);   // Module main function. It won't return
static void * wm_sca_sync_module(__attribute__((unused)) void * args);
#endif
static void wm_sca_destroy(wm_sca_t * data);  // Destroy data
static int wm_sca_start(wm_sca_t * data);  // Start
static void wm_sca_stop(wm_sca_t* data);   // Stop

cJSON *wm_sca_dump(const wm_sca_t * data);     // Read config

int wm_sca_sync_message(const char *command, size_t command_len); // Send sync message

static size_t wm_sca_query_handler(void *data, char *query, char **output); // Query handler

const wm_context WM_SCA_CONTEXT = {
    .name = SCA_WM_NAME,
    .start = (wm_routine)wm_sca_main,
    .destroy = (void(*)(void *))wm_sca_destroy,
    .dump = (cJSON * (*)(const void *))wm_sca_dump,
    .sync = (int(*)(const char*, size_t))wm_sca_sync_message,
    .stop = (void(*)(void *))wm_sca_stop,
    .query = wm_sca_query_handler,
};

void *sca_module = NULL;
sca_init_func sca_init_ptr = NULL;
sca_start_func sca_start_ptr = NULL;
sca_stop_func sca_stop_ptr = NULL;
sca_set_wm_exec_func sca_set_wm_exec_ptr = NULL;
sca_set_log_function_func sca_set_log_function_ptr = NULL;
sca_set_push_functions_func sca_set_push_functions_ptr = NULL;
sca_set_sync_parameters_func sca_set_sync_parameters_ptr = NULL;

// Sync protocol function pointers
sca_sync_module_func sca_sync_module_ptr = NULL;
sca_persist_diff_func sca_persist_diff_ptr = NULL;
sca_parse_response_func sca_parse_response_ptr = NULL;
sca_notify_data_clean_func sca_notify_data_clean_ptr = NULL;
sca_delete_database_func sca_delete_database_ptr = NULL;

// Query function pointer
typedef size_t (*sca_query_func)(const char* query, char** output);
sca_query_func sca_query_ptr = NULL;

// YAML to cJSON function pointer
sca_set_yaml_to_cjson_func_func sca_set_yaml_to_cjson_func_ptr = NULL;

// Logging callback function for SCA module
static void sca_log_callback(const modules_log_level_t level, const char* log, __attribute__((unused)) const char* tag) {
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

// SCA message queue functions
static int wm_sca_startmq(const char* key, short type, short attempts) {
    return StartMQ(key, type, attempts);
}

static int wm_sca_send_binary_msg(int queue, const void* message, size_t message_len, const char* locmsg, char loc) {
    return SendBinaryMSG(queue, message, message_len, locmsg, loc);
}

static void wm_handle_sca_disable_and_notify_data_clean()
{
    if (w_is_file(SCA_DB_DISK_PATH))
    {
        minfo("SCA is disabled, SCA database file exists. Proceeding with data clean notification.");
    }
    else
    {
        minfo("SCA is disabled, SCA database file does not exist. Skipping data clean notification.");
        return;
    }
    // Load the SCA module first
    if (sca_module = so_get_module_handle(SCA_WM_NAME), sca_module)
    {
        // Load required function pointers
        sca_set_log_function_ptr = so_get_function_sym(sca_module, "sca_set_log_function");
        sca_set_sync_parameters_ptr = so_get_function_sym(sca_module, "sca_set_sync_parameters");
        sca_parse_response_ptr = so_get_function_sym(sca_module, "sca_parse_response");
        sca_notify_data_clean_ptr = so_get_function_sym(sca_module, "sca_notify_data_clean");
        sca_delete_database_ptr = so_get_function_sym(sca_module, "sca_delete_database");

        // Set the logging function pointer in the SCA module
        if (sca_set_log_function_ptr)
        {
            sca_set_log_function_ptr(sca_log_callback);
        }

        // Set the sync protocol parameters
        if (sca_set_sync_parameters_ptr)
        {
            MQ_Functions mq_funcs = {.start = wm_sca_startmq, .send_binary = wm_sca_send_binary_msg};
            sca_set_sync_parameters_ptr(SCA_WM_NAME, SCA_SYNC_PROTOCOL_DB_PATH, &mq_funcs, sca_sync_end_delay, sca_sync_response_timeout, SCA_SYNC_RETRIES, sca_sync_max_eps);
        }

        sca_init_ptr = so_get_function_sym(sca_module, "sca_init");
        // Initialize the SCA module
        if (sca_init_ptr)
        {
            sca_init_ptr();
        }
        else
        {
            mwarn("Failed to load SCA module for data clean notification.");
            return;
        }
    }
    else
    {
        mwarn("Failed to load SCA module for data clean notification.");
        return;
    }

    if (sca_notify_data_clean_ptr && sca_delete_database_ptr)
    {
        const char* indices[] = {SCA_SYNC_INDEX};
        bool ret = false;
        while (!ret && !g_shutting_down)
        {
            ret = sca_notify_data_clean_ptr(indices, 1);
            if (!ret)
            {
                for (uint32_t i = 0; i < sca_sync_interval && !g_shutting_down; i++)
                {
                    sleep(1);
                }
            }
            else
            {
                mdebug1("SCA data clean notification sent successfully.");
                sca_delete_database_ptr();
            }
        }
    }
    else
    {
        mwarn("SCA notify data clean functions not available.");
    }
}

// Module main function. It won't return
#ifdef WIN32
DWORD WINAPI wm_sca_main(void *arg) {
    wm_sca_t *data = (wm_sca_t *)arg;
#else
void * wm_sca_main(wm_sca_t * data) {
#endif
    // If module is disabled, exit
    if (data->enabled) {
        minfo("SCA module enabled.");
    } else {
        wm_handle_sca_disable_and_notify_data_clean();
        minfo("SCA module disabled. Exiting.");
        pthread_exit(NULL);
    }

    if (sca_module = so_get_module_handle(SCA_WM_NAME), sca_module)
    {
        sca_start_ptr = so_get_function_sym(sca_module, "sca_start");
        sca_stop_ptr = so_get_function_sym(sca_module, "sca_stop");
        sca_set_wm_exec_ptr = so_get_function_sym(sca_module, "sca_set_wm_exec");
        sca_set_log_function_ptr = so_get_function_sym(sca_module, "sca_set_log_function");
        sca_set_push_functions_ptr = so_get_function_sym(sca_module, "sca_set_push_functions");
        sca_set_sync_parameters_ptr = so_get_function_sym(sca_module, "sca_set_sync_parameters");

        // Get sync protocol function pointers
        sca_sync_module_ptr = so_get_function_sym(sca_module, "sca_sync_module");
        sca_persist_diff_ptr = so_get_function_sym(sca_module, "sca_persist_diff");
        sca_parse_response_ptr = so_get_function_sym(sca_module, "sca_parse_response");

        // Get query function pointer
        sca_query_ptr = so_get_function_sym(sca_module, "sca_query");

        // Set the logging function pointer in the SCA module
        if (sca_set_log_function_ptr) {
            sca_set_log_function_ptr(sca_log_callback);
        }

        sca_set_yaml_to_cjson_func_ptr = so_get_function_sym(sca_module, "sca_set_yaml_to_cjson_func");

        // Set the wm_exec function pointer in the SCA module
        if (sca_set_wm_exec_ptr) {
            sca_set_wm_exec_ptr(wm_exec);
        }

        // Set the push functions for message handling
        if (sca_set_push_functions_ptr) {
            sca_set_push_functions_ptr(wm_sca_send_stateless, wm_sca_persist_stateful);
        }

        // Set synchronization parameters from config BEFORE setting sync protocol parameters
        sca_enable_synchronization = data->sync.enable_synchronization;
        if (sca_enable_synchronization) {
            sca_sync_interval = data->sync.sync_interval;
            sca_sync_end_delay = data->sync.sync_end_delay;
            sca_sync_response_timeout = data->sync.sync_response_timeout;
            sca_sync_max_eps = data->sync.sync_max_eps;
        }

        // Set the sync protocol parameters
        if (sca_set_sync_parameters_ptr) {
            MQ_Functions mq_funcs = {
                .start = wm_sca_startmq,
                .send_binary = wm_sca_send_binary_msg
            };
            sca_set_sync_parameters_ptr(SCA_WM_NAME, SCA_SYNC_PROTOCOL_DB_PATH, &mq_funcs, sca_sync_end_delay, sca_sync_response_timeout, SCA_SYNC_RETRIES, sca_sync_max_eps);
        }

        // Set the yaml to cjson function
        if (sca_set_yaml_to_cjson_func_ptr) {
            sca_set_yaml_to_cjson_func_ptr(wm_sca_yaml_to_cjson);
        }
    } else {
        merror("Can't get SCA module handle.");
        pthread_exit(NULL);
    }

    data->commands_timeout = getDefine_Int("sca", "commands_timeout", 1, 300);
#ifdef CLIENT
    data->remote_commands = getDefine_Int("sca", "remote_commands", 0, 1);
#else
    data->remote_commands = 1;  // Only agents require this setting. For manager it's always enabled.
#endif

    minfo("Starting SCA module...");

    wm_sca_start(data);

#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}

static int wm_sca_start(wm_sca_t *sca) {
    // Initialize message queue
    g_sca_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);
    if (g_sca_queue < 0) {
        merror("Cannot initialize SCA message queue.");
        return -1;
    }

    g_shutting_down = 0;
    atomic_int_set(&g_n_msg_sent, 0);

    minfo("SCA message queue initialized successfully.");

    if (sca->max_eps) {
        g_max_eps = sca->max_eps;
    }

    // Initialize sync protocol if enabled
    if (sca_enable_synchronization && sca_sync_module_ptr) {
        sca_sync_module_running = 1;
#ifndef WIN32
        // Launch SCA synchronization thread
        w_create_thread(wm_sca_sync_module, NULL);
#else
        if (CreateThread(NULL, 0, wm_sca_sync_module, NULL, 0, NULL) == NULL) {
            merror(THREAD_ERROR);
        }
#endif
    } else {
        mdebug1("SCA synchronization is disabled or function not available");
    }

    sca_start_ptr(sca);
    return 0;
}

// Destroy data
void wm_sca_destroy(wm_sca_t * data) {
    if (data) {
        os_free(data);
    }
}

// Stop
void wm_sca_stop(__attribute__((unused)) wm_sca_t* data)
{
    g_shutting_down = 1;
    sca_sync_module_running = 0;

    if (sca_stop_ptr) {
        sca_stop_ptr();
    }
}

cJSON *wm_sca_dump(const wm_sca_t * data) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();

    sched_scan_dump(&(data->scan_config), wm_wd);

    cJSON_AddStringToObject(wm_wd, "enabled", data->enabled ? "yes" : "no");
    cJSON_AddStringToObject(wm_wd, "scan_on_start", data->scan_on_start ? "yes" : "no");
    cJSON_AddNumberToObject(wm_wd, "max_eps", data->max_eps);

    if (data->policies && *data->policies) {
        cJSON *policies = cJSON_CreateArray();
        int i;
        for (i=0;data->policies[i];i++) {
            if(data->policies[i]->enabled == 1){
                cJSON_AddStringToObject(policies, "policy", data->policies[i]->policy_path);
            }
        }
        cJSON_AddItemToObject(wm_wd,"policies", policies);
    }

    // Database synchronization values
    cJSON * synchronization = cJSON_CreateObject();
    cJSON_AddStringToObject(synchronization, "enabled", data->sync.enable_synchronization ? "yes" : "no");
    cJSON_AddNumberToObject(synchronization, "sync_end_delay", data->sync.sync_end_delay);
    cJSON_AddNumberToObject(synchronization, "interval", data->sync.sync_interval);
    cJSON_AddNumberToObject(synchronization, "max_eps", data->sync.sync_max_eps);
    cJSON_AddNumberToObject(synchronization, "response_timeout", data->sync.sync_response_timeout);

    cJSON_AddItemToObject(wm_wd, "synchronization", synchronization);

    cJSON_AddItemToObject(root,"sca",wm_wd);

    return root;
}

static bool wm_sca_is_shutting_down(void) {
    return (bool)g_shutting_down;
}

static int wm_sca_send_stateless(const char* message) {
    if (!message) {
        return -1;
    }

    mdebug1("Sending SCA event: %s", message);

    if (SendMSGPredicated(g_sca_queue, message, "sca", SCA_MQ, wm_sca_is_shutting_down) < 0) {
        merror("Error sending message to queue");

        if ((g_sca_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0) {
            merror("Cannot restart SCA message queue");
            return -1;
        }

        // Try to send it again
        if (SendMSGPredicated(g_sca_queue, message, "sca", SCA_MQ, wm_sca_is_shutting_down) < 0) {
            merror("Error sending message to queue after restart");
            return -1;
        }
    }

    if (atomic_int_inc(&g_n_msg_sent) >= g_max_eps) {
        sleep(1);
        atomic_int_set(&g_n_msg_sent, 0);
    }

    return 0;
}

static int wm_sca_persist_stateful(const char* id, Operation_t operation, const char* index, const char* message, uint64_t version) {
    if (!message) {
        return -1;
    }

    if (sca_enable_synchronization && sca_persist_diff_ptr) {
        mdebug2("Persisting SCA event: %s", message);
        sca_persist_diff_ptr(id, operation, index, message, version);
    } else {
        mdebug2("SCA synchronization is disabled or function not available");
    }

    return 0;
}

int wm_sca_sync_message(const char *command, size_t command_len) {
    if (sca_enable_synchronization && sca_parse_response_ptr) {
        size_t header_len = strlen(SCA_SYNC_HEADER);
        const uint8_t *data = (const uint8_t *)(command + header_len);
        size_t data_len = command_len - header_len;

        bool ret = false;
        ret = sca_parse_response_ptr(data, data_len);

        if (!ret) {
            mdebug1("Error syncing module");
            return -1;
        }

        return 0;
    } else {
        mdebug1("SCA synchronization is disabled or function not available");
        return -1;
    }
}

#ifdef WIN32
DWORD WINAPI wm_sca_sync_module(__attribute__((unused)) void * args) {
#else
void * wm_sca_sync_module(__attribute__((unused)) void * args) {
#endif
    // Initial wait until SCA is started
    for (uint32_t i = 0; i < sca_sync_interval && sca_sync_module_running; i++) {
        sleep(1);
    }

    while (sca_sync_module_running) {
        minfo("Running SCA synchronization.");

        if (sca_sync_module_ptr) {
            sca_sync_module_ptr(MODE_DELTA);
        } else {
            mdebug1("Sync function not available");
        }

        minfo("SCA synchronization finished, waiting for %d seconds before next run.", sca_sync_interval);

        for (uint32_t i = 0; i < sca_sync_interval && sca_sync_module_running; i++) {
            sleep(1);
        }
    }

#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}

static size_t wm_sca_query_handler(void *data, char *query, char **output) {
    (void)data;  // Unused parameter

    if (!query || !output) {
        return 0;
    }

    // Call the C++ query function if available
    if (sca_query_ptr) {
        return sca_query_ptr(query, output);
    } else {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "{\"error\":%d,\"message\":\"%s\"}",
                 MQ_ERR_MODULE_NOT_RUNNING, MQ_MSG_MODULE_NOT_RUNNING);
        os_strdup(error_msg, *output);
        return strlen(*output);
    }
}

static cJSON* wm_sca_yaml_to_cjson(const char* yaml_path)
{
    yaml_document_t document;
    cJSON* json_object = NULL;

    memset(&document, 0, sizeof(document));

    if (yaml_parse_file(yaml_path, &document) == 0)
    {
        json_object = yaml2json(&document, 1);

        if (!json_object)
        {
            mwarn("Failed to convert YAML document to JSON for file: %s", yaml_path);
        }

        yaml_document_delete(&document);

    }
    else
    {
        mwarn("Failed to parse YAML file: %s", yaml_path);
    }

    return json_object;
}
