/*
 * Wazuh Module for the keystore server (UDS at queue/sockets/keystore)
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wm_keystore_server.h"
#include "keystore_server.h"
#include "sym_load.h"
#include <cJSON.h>

static void* wm_keystore_server_main(wm_keystore_server_t* data);
static void wm_keystore_server_destroy(wm_keystore_server_t* data);
static void wm_keystore_server_stop(wm_keystore_server_t* data);
cJSON* wm_keystore_server_dump(wm_keystore_server_t* data);

void* keystore_server_module = NULL;
keystore_server_start_func keystore_server_start_ptr = NULL;
keystore_server_stop_func keystore_server_stop_ptr = NULL;

const wm_context WM_KEYSTORE_SERVER_CONTEXT = {
    .name = "keystore_server",
    .start = (wm_routine)wm_keystore_server_main,
    .destroy = (void (*)(void*))wm_keystore_server_destroy,
    .dump = (cJSON * (*)(const void*)) wm_keystore_server_dump,
    .sync = NULL,
    .stop = (void (*)(void*))wm_keystore_server_stop,
    .query = NULL,
};

void* wm_keystore_server_main(wm_keystore_server_t* data)
{
    (void)data;

    mtinfo(WM_KEYSTORE_SERVER_LOGTAG, STARTUP_MSG, (int)getpid());

    if (keystore_server_module = so_get_module_handle("keystore_server"), keystore_server_module)
    {
        keystore_server_start_ptr = so_get_function_sym(keystore_server_module, "keystore_server_start");
        keystore_server_stop_ptr = so_get_function_sym(keystore_server_module, "keystore_server_stop");

        if (keystore_server_start_ptr)
        {
            /* NULL socket path -> the module's fixed production default. The Python framework's
             * KeystoreClient hardcodes the path, so there is nothing to configure. */
            if (keystore_server_start_ptr(mtLoggingFunctionsWrapper, NULL) != 0)
            {
                /* An unbindable keystore socket means the manager API silently loses its indexer
                 * credentials -- a manager that looks healthy while its API cannot reach the
                 * indexer is worse than one that refuses to run. */
                mterror_exit(WM_KEYSTORE_SERVER_LOGTAG,
                             "The keystore server cannot bind its socket; see the preceding error. Not running "
                             "without keystore access.");
            }
        }
        else
        {
            mterror_exit(WM_KEYSTORE_SERVER_LOGTAG,
                         "libkeystore_server.so does not export keystore_server_start; the installation is broken.");
        }
    }
    else
    {
        mterror_exit(WM_KEYSTORE_SERVER_LOGTAG, "Unable to load libkeystore_server.so; the installation is broken.");
    }

    /* start() is non-blocking (the socket server owns its epoll thread), so this routine returns
     * and modulesd's thread for it exits immediately. Teardown goes through the .stop callback. */
    return NULL;
}

void wm_keystore_server_destroy(wm_keystore_server_t* data)
{
    free(data);
}

void wm_keystore_server_stop(__attribute__((unused)) wm_keystore_server_t* data)
{
    if (keystore_server_stop_ptr)
    {
        keystore_server_stop_ptr();
    }
    else
    {
        mtwarn(WM_KEYSTORE_SERVER_LOGTAG, "Unable to stop keystore_server module.");
    }
    mtinfo(WM_KEYSTORE_SERVER_LOGTAG, "Module finished.");
}

wmodule* wm_keystore_server_read()
{
    wmodule* module;
    wm_keystore_server_t* data;

    os_calloc(1, sizeof(wmodule), module);
    os_calloc(1, sizeof(wm_keystore_server_t), data);

    module->context = &WM_KEYSTORE_SERVER_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = data;

    mtdebug1(WM_KEYSTORE_SERVER_LOGTAG, "Loaded keystore server module.");
    return module;
}

cJSON* wm_keystore_server_dump(wm_keystore_server_t* data)
{
    (void)data;

    /* Nothing to report: no tunables, a fixed socket path, and the keystore contents are secrets
     * by definition. The object exists so `getconfig wmodules` lists the module as present. */
    cJSON* root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "keystore_server", cJSON_CreateObject());
    return root;
}
