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

#include "container_instances.h"
#include "sym_load.h"
#include "wmodules.h"
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
