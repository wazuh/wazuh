/*
 * Wazuh Integration with Osquery Wazuh fork
 * Copyright (C) 2015-2020, Wazuh Inc.
 * April 5, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include <dlfcn.h>
#include <pthread.h>
#include "osquery_interface.h"
#include "dbsync.h"
#include "cJSON.h"

#ifdef WIN32
#define OSQUERYD_LIB    "osqueryd.dll"
#define DBSYNC_LIB      "dbsync.dll"
#else
#define OSQUERYD_LIB    "libosqueryd.so"
#define DBSYNC_LIB      "libdbsync.so"
#endif

#define OSQUERY_FILE_DB "osquery.db"

#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...) _mtinfo(WM_OSQUERYMONITOR_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mtwarn(WM_OSQUERYMONITOR_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _mterror(WM_OSQUERYMONITOR_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_OSQUERYMONITOR_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_OSQUERYMONITOR_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

static void* wm_osquery_native_main(wm_osquery_native_t* osquery_monitor);
static void* wm_osquery_native_destroy(wm_osquery_native_t* osquery_monitor);
cJSON* wm_osquery_native_dump(const wm_osquery_native_t* osquery_monitor);

const wm_context WM_OSQUERYNATIVE_CONTEXT = {
    "osquery_native",
    (wm_routine)wm_osquery_native_main,
    (wm_routine)wm_osquery_native_destroy,
    (cJSON* (*)(const void *))wm_osquery_native_dump
};

pthread_cond_t schedule_cv = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t host_thread = 0;
bool module_initialized = false;
bool run_mainloop = true;


typedef int (*osquery_initialize_native)(const char *, InitType, void *, void *);
osquery_initialize_native osquery_init_imp = NULL;
typedef void (*osquery_teardown_native)(void);
osquery_teardown_native osquery_teardown_imp = NULL;
typedef int (*osquery_execute_query_native)(const char *, char **);
osquery_execute_query_native osquery_execute_query_imp = NULL;
typedef int (*osquery_free_query_results_native)(char **);
osquery_free_query_results_native osquery_free_query_results_imp = NULL;
typedef int (*osquery_init_event_sub_module_native)(const unsigned int, void *, const size_t);
osquery_init_event_sub_module_native osquery_init_event_sub_module_imp = NULL;
typedef int (*osquery_get_table_create_statement_native)(const char*, char**);
osquery_get_table_create_statement_native osquery_get_table_create_statement_imp = NULL;


typedef int (*dbsync_initialize_native)(const HostType, const DbEngineType, const char*, const char*);
dbsync_initialize_native dbsync_initialize_imp = NULL;
typedef void (*dbsync_teardown_native)(void);
dbsync_teardown_native dbsync_teardown_imp = NULL;
typedef int (*dbsync_insert_data_native)(const unsigned long long, const cJSON *);
dbsync_insert_data_native dbsync_insert_data_imp = NULL;
typedef int (*dbsync_update_with_snapshot_native)(const unsigned long long, const cJSON *, cJSON **);
dbsync_update_with_snapshot_native dbsync_update_with_snapshot_imp = NULL;

void remote_ondemand_call(
    const char *query, 
    char **result)
{
    pthread_mutex_lock(&mutex);
    if(module_initialized)
    {
        if (NULL != osquery_execute_query_imp &&
            NULL != osquery_free_query_results_imp)
        {
            if (-1 != osquery_execute_query_imp(query, &*result))
            {
                minfo("osquery result: %s\n", *result);
                osquery_free_query_results_imp(&*result);
            }
        }
    }
    pthread_mutex_unlock(&mutex);
}

void scheduled_callback(const char *result, void *context)
{
    pthread_mutex_lock(&mutex);
    wm_osquery_native_t *osquery_context = context;
    minfo("osquery result: %s\n", result);
    if (wm_sendmsg(osquery_context->msg_delay, osquery_context->queue_fd, result, "osquery_native", LOCALFILE_MQ) < 0) {
        mterror(WM_OSQUERYMONITOR_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
    } 
    pthread_mutex_unlock(&mutex);
}

bool initialize_osquery_modules(
    wm_osquery_native_t *osquery_native_context,
#ifndef WIN32
    void *handle_osquery, void *handle_dbsync)
#else
    HMODULE handle_osquery, MODULE handle_dbsync)
#endif
{
    char *error;
#ifndef WIN32  
    *(void **)(&osquery_init_imp) = dlsym(handle_osquery, "osquery_initialize");
    if ((error = dlerror()) != NULL) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of osquery_initialize function.");
        return false;
    }

    *(void **)(&osquery_teardown_imp) = dlsym(handle_osquery, "osquery_teardown");
    if ((error = dlerror()) != NULL) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of osquery_teardown function.");
        return false;
    }

    *(void **)(&osquery_execute_query_imp) = dlsym(handle_osquery, "osquery_execute_query");
    if ((error = dlerror()) != NULL) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of osquery_execute_query function.");
        return false;
    }

    *(void **)(&osquery_free_query_results_imp) = dlsym(handle_osquery, "osquery_free_results");
    if ((error = dlerror()) != NULL) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of osquery_free_query_results function.");
        return false;
    }

    *(void **)(&osquery_init_event_sub_module_imp) = dlsym(handle_osquery, "osquery_init_event_sub_module");
    if ((error = dlerror()) != NULL) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of osquery_init_event_sub_module function.");
        return false;
    }

    *(void **)(&osquery_get_table_create_statement_imp) = dlsym(handle_osquery, "osquery_get_table_create_statement");
    if ((error = dlerror()) != NULL) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of osquery_get_table_create_statement function.");
        return false;
    }


    *(void **)(&dbsync_teardown_imp) = dlsym(handle_dbsync, "dbsync_teardown");
    if ((error = dlerror()) != NULL) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of dbsync_teardown function.");
        return false;
    }

    *(void **)(&dbsync_initialize_imp) = dlsym(handle_dbsync, "dbsync_initialize");
    if ((error = dlerror()) != NULL) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of dbsync_initialize function.");
        return false;
    }

    *(void **)(&dbsync_insert_data_imp) = dlsym(handle_dbsync, "dbsync_insert_data");
    if ((error = dlerror()) != NULL) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of dbsync_insert_data function.");
        return false;
    }

    *(void **)(&dbsync_update_with_snapshot_imp) = dlsym(handle_dbsync, "dbsync_update_with_snapshot");
    if ((error = dlerror()) != NULL) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of dbsync_update_with_snapshot function.");
        return false;
    }
#else
    osquery_init_imp = GetProcAddress(handle_osquery, "osquery_initialize");
    if (NULL != osquery_init_imp) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of initialize function.");
        return false;
    }

    osquery_teardown_imp = GetProcAddress(handle_osquery, "osquery_teardown");
    if (NULL != osquery_teardown_imp) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of teardown function.");
        return false;
    }

    osquery_execute_query_imp = GetProcAddress(handle_osquery, "osquery_execute_query");
    if (NULL != osquery_execute_query_imp) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of execute_query function.");
        return false;
    }

    osquery_free_query_results_imp = GetProcAddress(handle_osquery, "osquery_free_query_results");
    if (NULL != osquery_free_query_results_imp) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of free_query_results function.");
        return false;
    }

    osquery_init_event_sub_module_imp = GetProcAddress(handle_osquery, "osquery_init_event_sub_module");
    if (NULL != osquery_init_event_sub_module_imp) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of init_event_sub_module function.");
        return false;
    }

     dbsync_teardown_imp = GetProcAddress(handle_dbsync, "dbsync_teardown");
    if (NULL != dbsync_teardown_imp) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of dbsync_teardown function.");
        return false;
    }

    dbsync_initialize_imp = GetProcAddress(handle_dbsync, "dbsync_initialize");
    if (NULL != dbsync_initialize_imp) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of dbsync_initialize function.");
        return false;
    }

    dbsync_insert_data_imp = GetProcAddress(handle_dbsync, "dbsync_insert_data");
    if (NULL != dbsync_insert_data_imp) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of dbsync_insert_data function.");
        return false;
    }

    dbsync_update_with_snapshot_imp = GetProcAddress(handle_dbsync, "dbsync_update_with_snapshot");
    if (NULL != dbsync_update_with_snapshot_imp) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of dbsync_update_with_snapshot function.");
        return false;
    }

#endif
    osquery_native_context->remote_ondemand_call = &remote_ondemand_call;
    return true;
}
bool write_dbsync_results(const char* table, const unsigned long long db_sync_handler, const char* result_data) {
    bool ret_val = false;
    if (NULL != result_data) {
        cJSON* root = cJSON_CreateObject();
        if(NULL != root) {
            cJSON_AddStringToObject(root, "table", table);
            cJSON_AddItemToObject(root, "data", cJSON_Parse(result_data));
            cJSON* result;
            (*dbsync_update_with_snapshot_imp)(db_sync_handler, root, &result);
            cJSON_Delete(root);
            if(NULL != result) {
                cJSON_Delete(result);
            }
        }
    }
    return ret_val;
}
void execute_queries(task_osquery_t * head, const unsigned long long db_sync_handler) {
    task_osquery_t* current = head->next;
    time_t current_time = time(NULL);
	while (NULL != current) {
		if (current_time >= current->last_refresh.tv_sec + current->refresh_rate) {
            int result = 0;
            char * result_data;
            if(result = (*osquery_execute_query_imp)(current->sql_string, &result_data), result == 0) {
                write_dbsync_results(current->table, db_sync_handler, result_data);
                (*osquery_free_query_results_imp)(&result_data);
            } else {
                mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot execute query %d.", result);
            }
            current->last_refresh.tv_sec = time(NULL);
        }
		current = current->next;
	}
}
time_t get_wait_time_to_next_query(task_osquery_t * head){
    task_osquery_t* current = head->next;
    time_t current_time = time(NULL);
    time_t ret_val = INT_MAX;

	while (NULL != current) {
        time_t task_left_time = (current->refresh_rate+current->last_refresh.tv_sec) - current_time;
        ret_val = task_left_time < ret_val ? task_left_time : ret_val;
        if (ret_val <= 0)
            ret_val = 1;
        current = current->next;
    }
    
    return ret_val;
}
void* instance_osquery(
    wm_osquery_native_t *osquery_native_context)
{
    pthread_mutex_lock(&mutex);

#ifndef WIN32
    void *handle_osquery = dlopen(OSQUERYD_LIB, RTLD_LAZY);
    void *handle_dbsync = dlopen(DBSYNC_LIB, RTLD_LAZY);
#else
    HMODULE handle_osquery = LoadLibrary(OSQUERYD_LIB);
    HMODULE handle_dbsync = LoadLibrary(DBSYNC_LIB);
#endif
    if (NULL != handle_osquery && 
        NULL != handle_dbsync) {
        if(initialize_osquery_modules(osquery_native_context, handle_osquery, handle_dbsync)) {
            if (0 == (*osquery_init_imp)(ARGV0, SYNC_QUERIES, NULL, NULL)){
                char * create_sql_statement = NULL;
                if (0 == (*osquery_get_table_create_statement_imp)(ALL_TABLES, &create_sql_statement)) {
                    unsigned long long db_sync_handler = 0;
                    if (db_sync_handler = (*dbsync_initialize_imp)(AGENT, SQLITE3, OSQUERY_FILE_DB, create_sql_statement), 0 != db_sync_handler) {
                        struct timespec wait_time;
                
                        clock_gettime(CLOCK_REALTIME, &wait_time);
                        wait_time.tv_sec += get_wait_time_to_next_query(osquery_native_context->task_list);
                        execute_queries(osquery_native_context->task_list, db_sync_handler);
                        while (run_mainloop) {  
                            int ret = pthread_cond_timedwait(&schedule_cv, &mutex, &wait_time);
                            if (ETIMEDOUT == ret) {
                                execute_queries(osquery_native_context->task_list, db_sync_handler);
                            }
                            clock_gettime(CLOCK_REALTIME, &wait_time);
                            wait_time.tv_sec += get_wait_time_to_next_query(osquery_native_context->task_list);
                        }
                        (*dbsync_teardown_imp)();
                    }else {
                        merror("Error during the initialization of DBSync.");
                    }
                    (*osquery_free_query_results_imp)(&create_sql_statement);
                } else {
                    merror("Error when try to get schema query.");
                }

                (*osquery_teardown_imp)();

            }else {
                merror("Error to initialize osquery native.");
            }
        } else {
            merror("Error when try to recognize symbols on libraries.");
        }
    }else {
        merror("Error loading modules.");
    }

    if (NULL != handle_osquery) {
#ifndef WIN32
        dlclose(handle_osquery);
#else
        FreeLibrary(handle_osquery);
#endif
    }
    if (NULL != handle_dbsync) {
#ifndef WIN32
        dlclose(handle_dbsync);
#else
        FreeLibrary(handle_dbsync);
#endif
    }
    task_osquery_delete_list(osquery_native_context->task_list);
    pthread_mutex_unlock(&mutex);
    return NULL;
}

void* wm_osquery_native_main(
    wm_osquery_native_t *osquery_native_context)
{
    if (osquery_native_context->disable) {
        minfo("Module disabled. Exiting...");
        return NULL;
    }

    osquery_native_context->msg_delay = 1000000 / wm_max_eps;

#ifndef WIN32
    int i;

    // Connect to queue
    for (i = 0; i < WM_MAX_ATTEMPTS && (osquery_native_context->queue_fd = StartMQ(DEFAULTQPATH, WRITE), osquery_native_context->queue_fd < 0); i++) {
        // Trying to connect to queue
        sleep(WM_MAX_WAIT);
    }

    if (i == WM_MAX_ATTEMPTS) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Can't connect to queue. Closing module.");
        return NULL;
    }
#endif

    if( pthread_create(&host_thread, NULL, (void *)&instance_osquery, osquery_native_context) != 0){
        merror("Error while creating Execute_Osquery thread.");
        return NULL;
    }

    minfo("Module started.");
    return NULL;
}


void* wm_osquery_native_destroy(
    wm_osquery_native_t *osquery_native_context)
{
    if (NULL != osquery_native_context) {
        run_mainloop = false;
        pthread_cond_signal(&schedule_cv);
        pthread_join(host_thread, NULL); 
        free(osquery_native_context->bin_path);
        free(osquery_native_context->config_path);
        free(osquery_native_context);
    }
    return NULL;
}


// Get read data
cJSON *wm_osquery_native_dump(
    const wm_osquery_native_t* osquery_native_context) {

    cJSON *root = cJSON_CreateObject();
    cJSON *wm_osq = cJSON_CreateObject();

    if(NULL != osquery_native_context)
    {
        cJSON_AddStringToObject(wm_osq, "disabled", osquery_native_context->disable ? "yes" : "no"); 

        if (osquery_native_context->bin_path) 
            cJSON_AddStringToObject(wm_osq, "bin_path", osquery_native_context->bin_path);
        if (osquery_native_context->config_path) 
            cJSON_AddStringToObject(wm_osq, "config_path", osquery_native_context->config_path);

        cJSON_AddItemToObject(root, "osquery", wm_osq);
    }
    return root;
}