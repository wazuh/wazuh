/*
 * Wazuh Module for content updates.
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wm_content_manager.h"
#include "content_manager.h"
#include "external/cJSON/cJSON.h"
#include "logging_helper.h"
#include "sym_load.h"

static void wm_content_manager_destroy();
cJSON* wm_content_manager_dump();
static void wm_content_manager_stop();
static void* wm_content_manager_main();

void* content_manager_module = NULL;
content_manager_start_func content_manager_start_ptr = NULL;
content_manager_stop_func content_manager_stop_ptr = NULL;

const wm_context WM_CONTENT_MANAGER_CONTEXT = {
    .name = "content_manager",
    .start = (wm_routine)wm_content_manager_main,
    .destroy = (void (*)(void*))wm_content_manager_destroy,
    .dump = (cJSON * (*)(const void*)) wm_content_manager_dump,
    .sync = NULL,
    .stop = (void (*)(void*))wm_content_manager_stop,
    .query = NULL,
};

void* wm_content_manager_main()
{
    mtinfo(WM_CONTENT_MANAGER_LOGTAG, "Starting content_manager module.");

    if (content_manager_module = so_get_module_handle("content_manager"), content_manager_module)
    {
        content_manager_start_ptr = so_get_function_sym(content_manager_module, "content_manager_start");
        content_manager_stop_ptr = so_get_function_sym(content_manager_module, "content_manager_stop");

        if (content_manager_start_ptr)
        {
            content_manager_start_ptr(mtLoggingFunctionsWrapper);
        }
        else
        {
            mtwarn(WM_CONTENT_MANAGER_LOGTAG, "Unable to start content manager.");
        }
    }
    else
    {
        mtwarn(WM_CONTENT_MANAGER_LOGTAG, "Unable to load content_manager module.");
    }

    return NULL;
}

void wm_content_manager_destroy() {}

void wm_content_manager_stop()
{
    mtinfo(WM_CONTENT_MANAGER_LOGTAG, "Stopping content_manager module.");

    if (content_manager_stop_ptr)
    {
        content_manager_stop_ptr();
    }
    else
    {
        mtwarn(WM_CONTENT_MANAGER_LOGTAG, "Unable to stop content manager.");
    }
}

wmodule* wm_content_manager_read()
{
    wmodule* module;

    os_calloc(1, sizeof(wmodule), module);
    module->context = &WM_CONTENT_MANAGER_CONTEXT;
    module->tag = strdup(module->context->name);

    mtinfo(WM_CONTENT_MANAGER_LOGTAG, "Loaded content_manager module.");
    return module;
}

cJSON* wm_content_manager_dump()
{
    cJSON* root = cJSON_CreateObject();
    cJSON* wm_wd = cJSON_CreateObject();
    cJSON_AddStringToObject(wm_wd, "enabled", "yes");
    cJSON_AddItemToObject(root, "wazuh_control", wm_wd);
    return root;
}

