/*
 * Wazuh Module for routing messages.
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wm_router.h"
#include "external/cJSON/cJSON.h"
#include "router.h"
#include "sym_load.h"

static void wm_router_destroy();
cJSON* wm_router_dump();
static void wm_router_stop();
static void* wm_router_main();

void* router_module = NULL;

router_initialize_func router_initialize_ptr = NULL;
router_start_func router_start_ptr = NULL;
router_stop_func router_stop_ptr = NULL;

const wm_context WM_ROUTER_CONTEXT = {
    .name = "router",
    .start = (wm_routine)wm_router_main,
    .destroy = (void (*)(void*))wm_router_destroy,
    .dump = (cJSON * (*)(const void*)) wm_router_dump,
    .sync = NULL,
    .stop = (void (*)(void*))wm_router_stop,
    .query = NULL,
};

void* wm_router_main()
{
    mtinfo(WM_ROUTER_LOGTAG, "Starting router module.");
    if (router_module = so_get_module_handle("router"), router_module)
    {
        router_start_ptr = so_get_function_sym(router_module, "router_start");
        router_stop_ptr = so_get_function_sym(router_module, "router_stop");
        router_initialize_ptr = so_get_function_sym(router_module, "router_initialize");

        if (router_initialize_ptr)
        {
            router_initialize_ptr(taggedLogFunction);
        }
        else
        {
            mtwarn(WM_ROUTER_LOGTAG, "Unable to initialize router module.");
            return NULL;
        }

        if (router_start_ptr)
        {
            router_start_ptr();
        }
        else
        {
            mtwarn(WM_ROUTER_LOGTAG, "Unable to start router module.");
            return NULL;
        }
    }
    else
    {
        mtwarn(WM_ROUTER_LOGTAG, "Unable to load router module.");
        return NULL;
    }

    return NULL;
}

void wm_router_destroy() {}

void wm_router_stop()
{
    mtinfo(WM_ROUTER_LOGTAG, "Stopping router module.");
    if (router_stop_ptr)
    {
        router_stop_ptr();
    }
    else
    {
        mtwarn(WM_ROUTER_LOGTAG, "Unable to stop router module.");
    }
}

wmodule* wm_router_read()
{
    wmodule* module;

    os_calloc(1, sizeof(wmodule), module);
    module->context = &WM_ROUTER_CONTEXT;
    module->tag = strdup(module->context->name);
    mtinfo(WM_ROUTER_LOGTAG, "Loaded router module.");
    return module;
}

cJSON* wm_router_dump()
{
    cJSON* root = cJSON_CreateObject();
    cJSON* wm_wd = cJSON_CreateObject();
    cJSON_AddStringToObject(wm_wd, "enabled", "yes");
    cJSON_AddItemToObject(root, "wazuh_control", wm_wd);
    return root;
}
