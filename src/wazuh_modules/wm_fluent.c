/*
 * Wazuh Module for Fluent Forwarder
 * Copyright (C) 2015-2019, Wazuh Inc.
 * January 25, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include <os_net/os_net.h>
#include "os_crypto/md5/md5_op.h"
#include "shared.h"


#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...) _mtinfo(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mtwarn(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _mterror(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_FLUENT_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

static void * wm_fluent_main(wm_fluent_t * data);   // Module main function. It won't return
static void wm_fluent_destroy(wm_fluent_t * data);  // Destroy data
cJSON *wm_fluent_dump(const wm_fluent_t * data);     // Read config

const wm_context WM_FLUENT_CONTEXT = {
    FLUENT_WM_NAME,
    (wm_routine)wm_fluent_main,
    (wm_routine)wm_fluent_destroy,
    (cJSON * (*)(const void *))wm_fluent_dump
};


// Module main function. It won't return
void * wm_fluent_main(wm_fluent_t * data) {
    // If module is disabled, exit
    if (data->enabled) {
        minfo("Module started.");
    } else {
        minfo("Module disabled. Exiting.");
        pthread_exit(NULL);
    }

    return NULL;
}

// Destroy data
void wm_fluent_destroy(wm_fluent_t * data) {
    os_free(data);
}


cJSON *wm_fluent_dump(const wm_fluent_t *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();

    cJSON_AddStringToObject(wm_wd, "enabled", data->enabled ? "yes" : "no");
    if (data->tag) cJSON_AddStringToObject(wm_wd, "tag", data->tag);
    if (data->socket_path)cJSON_AddStringToObject(wm_wd, "socket_path", data->socket_path);
    if (data->address) cJSON_AddStringToObject(wm_wd, "address", data->address);
    if (data->port) cJSON_AddNumberToObject(wm_wd, "port", data->port);
    if (data->shared_key) cJSON_AddStringToObject(wm_wd, "shared_key", data->shared_key);
    if (data->ca_file) cJSON_AddStringToObject(wm_wd, "ca_file", data->ca_file);
    if (data->user) cJSON_AddStringToObject(wm_wd, "user", data->user);
    if (data->password) cJSON_AddStringToObject(wm_wd, "password", data->password);

    cJSON_AddItemToObject(root,"fluent_forwarder",wm_wd);

    return root;
}
