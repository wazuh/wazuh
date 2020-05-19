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

#ifdef WIN32
#define OSQUERYD_LIB "osqueryd.dll"
#else
#define OSQUERYD_LIB "libosqueryd.so"
#endif

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

pthread_cond_t shutdown_cv = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t host_thread = 0;
bool module_initialized = 0;

typedef int (*initialize_osquery_native)(const char *, InitType, void *, void *);
initialize_osquery_native init_osquery = NULL;
typedef void (*teardown_osquery_native)(void);
teardown_osquery_native teardown_osquery = NULL;
typedef int (*execute_query_osquery_native)(const char *, char **);
execute_query_osquery_native execute_query_osquery = NULL;
typedef int (*free_query_results_osquery_native)(char **);
free_query_results_osquery_native free_query_results_osquery = NULL;
typedef int (*init_event_sub_module_osquery_native)(const unsigned int, void *, const size_t);
init_event_sub_module_osquery_native init_event_sub_module_osquery = NULL;



void remote_ondemand_call(
    const char *query, 
    char **result)
{
    pthread_mutex_lock(&mutex);
    if(module_initialized)
    {
        if (NULL != execute_query_osquery &&
            NULL != free_query_results_osquery)
        {
            if (-1 != execute_query_osquery(query, &*result))
            {
            minfo("osquery result: %s\n", *result);
            free_query_results_osquery(&*result);
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

bool initialize_osquery(
    wm_osquery_native_t *osquery_native_context,
#ifndef WIN32
    void *handle)
#else
    HMODULE handle)
#endif
{
    char *error;
#ifndef WIN32  
    *(void **)(&init_osquery) = dlsym(handle, "initialize");
    if ((error = dlerror()) != NULL) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of initialize function.");
        return false;
    }

    *(void **)(&teardown_osquery) = dlsym(handle, "teardown");
    if ((error = dlerror()) != NULL) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of teardown function.");
        return false;
    }

    *(void **)(&execute_query_osquery) = dlsym(handle, "execute_query");
    if ((error = dlerror()) != NULL) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of execute_query function.");
        return false;
    }

    *(void **)(&free_query_results_osquery) = dlsym(handle, "free_query_results");
    if ((error = dlerror()) != NULL) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of free_query_results function.");
        return false;
    }

    *(void **)(&init_event_sub_module_osquery) = dlsym(handle, "init_event_sub_module");
    if ((error = dlerror()) != NULL) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of init_event_sub_module function.");
        return false;
    }
#else
    init_osquery = GetProcAddress(handle, "initialize");
    if (NULL != init_osquery) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of initialize function.");
        return false;
    }

    teardown_osquery = GetProcAddress(handle, "teardown");
    if (NULL != teardown_osquery) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of teardown function.");
        return false;
    }

    execute_query_osquery = GetProcAddress(handle, "execute_query");
    if (NULL != execute_query_osquery) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of execute_query function.");
        return false;
    }

    free_query_results_osquery = GetProcAddress(handle, "free_query_results");
    if (NULL != free_query_results_osquery) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of free_query_results function.");
        return false;
    }

    init_event_sub_module_osquery = GetProcAddress(handle, "init_event_sub_module");
    if (NULL != init_event_sub_module_osquery) {
        mterror(WM_OSQUERYNATIVE_LOGTAG, "Cannot get the address of init_event_sub_module function.");
        return false;
    }

#endif
    osquery_native_context->remote_ondemand_call = &remote_ondemand_call;
    return true;
}
 
void* instance_osquery(
    wm_osquery_native_t *osquery_native_context)
{
    pthread_mutex_lock(&mutex);
#ifndef WIN32
    void *handle = dlopen(OSQUERYD_LIB, RTLD_LAZY);
#else
    HMODULE handle = LoadLibrary(OSQUERYD_LIB);
#endif
    if (NULL != handle) {
        if(initialize_osquery(osquery_native_context, handle) &&
           0 == (*init_osquery)(ARGV0, SYNC_QUERIES, NULL, NULL)) 
        {
            pthread_cond_wait(&shutdown_cv, &mutex);
            (*teardown_osquery)();
        }
        else
        {
            merror("Error to initialize osquery native...");
        }
#ifndef WIN32
        dlclose(handle);
#else
        FreeLibrary(handle);
#endif
    }
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

    if (osquery_native_context->run_daemon) {
        if( pthread_create(&host_thread, NULL, (void *)&instance_osquery, osquery_native_context) != 0){
            merror("Error while creating Execute_Osquery thread.");
            return NULL;
        }
    } else {
        minfo("run_daemon disabled, finding detached osquery process results.");
    }
    minfo("Module started.");
    return NULL;
}


void* wm_osquery_native_destroy(
    wm_osquery_native_t *osquery_native_context)
{
    if (NULL != osquery_native_context) {
        pthread_cond_signal(&shutdown_cv);
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