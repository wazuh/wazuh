/*
 * Wazuh Container Instances Security Module
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#if defined(__linux__)

#include "agentd_query.h"
#include "container_instances.h"
#include "sym_load.h"
#include "wmodules.h"
#include "wm_container_instances.h"
#include <cJSON.h>

static void* wm_container_instances_main(wm_container_instances_t* data);
static void wm_container_instances_destroy(wm_container_instances_t* data);
static void wm_container_instances_stop(wm_container_instances_t* data);
static cJSON* wm_container_instances_dump(const wm_container_instances_t* data);

static void* container_instances_module = NULL;
static container_instances_start_func container_instances_start_ptr = NULL;
static container_instances_stop_func container_instances_stop_ptr = NULL;

const wm_context WM_CONTAINER_INSTANCES_CONTEXT = {
    .name = CONTAINER_INSTANCES_WM_NAME,
    .start = (wm_routine)wm_container_instances_main,
    .destroy = (void (*)(void*))wm_container_instances_destroy,
    .dump = (cJSON * (*)(const void*)) wm_container_instances_dump,
    .sync = NULL,
    .stop = (void (*)(void*))wm_container_instances_stop,
    .query = NULL,
};

static cJSON* wm_container_instances_build_config(const wm_container_instances_t* data)
{
    cJSON* config = cJSON_CreateObject();

    if (data->kubernetes_present)
    {
        cJSON* kubernetes = cJSON_CreateObject();
        cJSON_AddStringToObject(kubernetes,
                                "kubeconfig",
                                data->kubernetes.kubeconfig ? data->kubernetes.kubeconfig
                                                            : WM_CONTAINER_INSTANCES_DEF_KUBECONFIG);
        cJSON_AddStringToObject(kubernetes,
                                "node_name",
                                data->kubernetes.node_name ? data->kubernetes.node_name
                                                           : WM_CONTAINER_INSTANCES_DEF_NODE_NAME);
        cJSON_AddNumberToObject(kubernetes, "ownership_poll_interval", data->kubernetes.ownership_poll_interval);
        cJSON_AddBoolToObject(kubernetes, "insecure_skip_tls_verify", data->kubernetes.insecure_skip_tls_verify);
        cJSON_AddItemToObject(config, "kubernetes", kubernetes);
    }
    if (data->docker_present)
    {
        cJSON* docker = cJSON_CreateObject();
        cJSON_AddStringToObject(docker,
                                "socket_path",
                                data->docker_socket_path ? data->docker_socket_path
                                                         : WM_CONTAINER_INSTANCES_DEF_DOCKER_SOCKET);
        cJSON_AddItemToObject(config, "docker", docker);
    }

    return config;
}

/* How many containers may report to the manager (#37532).
 *
 * Read here rather than inside the module because this is modulesd, where
 * w_query_agentd already lives; the module itself is a shared object loaded by
 * symbol and would otherwise need its own link against the agent's query
 * socket for one integer.
 *
 * Returns 0 (unlimited) when the answer is not available. Waiting for it would
 * hold container discovery behind the manager handshake, and a cap nobody has
 * configured is the default anyway. A limit that CHANGES restarts the agent --
 * module_limits_changed() drives that -- so this value is re-read at the only
 * moment it can differ.
 */
static int wm_container_instances_sync_limit(void)
{
    char json_buffer[OS_MAXSTR] = {0};

    if (!w_query_agentd(WM_CONTAINER_INSTANCES_LOGTAG, "getdoclimits containers", json_buffer, sizeof(json_buffer)))
    {
        mtdebug1(WM_CONTAINER_INSTANCES_LOGTAG,
                 "Document limits are not available yet; every container may report.");
        return 0;
    }

    cJSON* root = cJSON_Parse(json_buffer);
    if (!root)
    {
        mtdebug1(WM_CONTAINER_INSTANCES_LOGTAG, "Could not parse the getdoclimits containers reply.");
        return 0;
    }

    int limit = 0;
    cJSON* synced = cJSON_GetObjectItem(root, "synced");
    if (synced && cJSON_IsNumber(synced))
    {
        const double value = cJSON_GetNumberValue(synced);
        if (value >= 0)
        {
            limit = (int)value;
        }
    }

    cJSON_Delete(root);
    return limit;
}

void* wm_container_instances_main(wm_container_instances_t* data)
{
    if (!data || !data->enabled)
    {
        mtinfo(WM_CONTAINER_INSTANCES_LOGTAG, "Module disabled. Exiting.");
        return NULL;
    }

    mtinfo(WM_CONTAINER_INSTANCES_LOGTAG, "Starting container_instances module.");

    if (container_instances_module = so_get_module_handle("container_instances"), container_instances_module)
    {
        container_instances_start_ptr = so_get_function_sym(container_instances_module, "container_instances_start");
        container_instances_stop_ptr = so_get_function_sym(container_instances_module, "container_instances_stop");
    }

    if (container_instances_start_ptr)
    {
        cJSON* config = wm_container_instances_build_config(data);
        cJSON_AddNumberToObject(config, "synced_container_limit", wm_container_instances_sync_limit());
        container_instances_start_ptr(mtLoggingFunctionsWrapper, config);
        cJSON_Delete(config);
    }
    else
    {
        mtwarn(WM_CONTAINER_INSTANCES_LOGTAG, "Unable to load container_instances module.");
    }

    return NULL;
}

void wm_container_instances_stop(__attribute__((unused)) wm_container_instances_t* data)
{
    mtinfo(WM_CONTAINER_INSTANCES_LOGTAG, "Module finished.");
    if (container_instances_stop_ptr)
    {
        container_instances_stop_ptr();
    }
}

void wm_container_instances_destroy(wm_container_instances_t* data)
{
    if (data)
    {
        os_free(data->kubernetes.kubeconfig);
        os_free(data->kubernetes.node_name);
        os_free(data->docker_socket_path);
        os_free(data);
    }
}

cJSON* wm_container_instances_dump(const wm_container_instances_t* data)
{
    cJSON* root = cJSON_CreateObject();
    cJSON* wm = cJSON_CreateObject();

    cJSON_AddStringToObject(wm, "enabled", data->enabled ? "yes" : "no");
    if (data->kubernetes_present)
    {
        cJSON* kubernetes = cJSON_CreateObject();
        if (data->kubernetes.kubeconfig)
        {
            cJSON_AddStringToObject(kubernetes, "kubeconfig", data->kubernetes.kubeconfig);
        }
        if (data->kubernetes.node_name)
        {
            cJSON_AddStringToObject(kubernetes, "node_name", data->kubernetes.node_name);
        }
        cJSON_AddNumberToObject(kubernetes, "ownership_poll_interval", data->kubernetes.ownership_poll_interval);
        cJSON_AddStringToObject(
            kubernetes, "insecure_skip_tls_verify", data->kubernetes.insecure_skip_tls_verify ? "yes" : "no");
        cJSON_AddItemToObject(wm, "kubernetes", kubernetes);
    }
    if (data->docker_present)
    {
        cJSON* docker = cJSON_CreateObject();
        cJSON_AddStringToObject(docker,
                                "socket_path",
                                data->docker_socket_path ? data->docker_socket_path
                                                         : WM_CONTAINER_INSTANCES_DEF_DOCKER_SOCKET);
        cJSON_AddItemToObject(wm, "docker", docker);
    }

    cJSON_AddItemToObject(root, CONTAINER_INSTANCES_WM_NAME, wm);
    return root;
}

#endif /* __linux__ */
