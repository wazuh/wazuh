/*
 * Wazuh Module for Kubernetes container monitoring connector — C glue
 *
 * This file is the thin C bridge between wazuh-modulesd and the C++
 * libcontainer_connector.so library. All runtime logic lives in the C++ side;
 * this file only registers the wm_context, dispatches log messages, and
 * forwards lifecycle calls to the lib's C API (cc_*).
 *
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32

#include "wmodules.h"
#include "container_connector.h"

static void *wm_container_connector_main(wm_container_connector_t *cfg);
static void  wm_container_connector_destroy(wm_container_connector_t *cfg);
static cJSON *wm_container_connector_dump(const wm_container_connector_t *cfg);

const wm_context WM_CONTAINER_CONNECTOR_CONTEXT = {
    .name = "container-connector",
    .start = (wm_routine)wm_container_connector_main,
    .destroy = (void(*)(void *))wm_container_connector_destroy,
    .dump = (cJSON *(*)(const void *))wm_container_connector_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

/* Routes log messages emitted by the C++ lib through the modulesd logging macros. */
static void wm_cc_log_dispatch(modules_log_level_t level, const char *log, const char *tag)
{
    (void)tag;  /* The lib already tags with WM_CONTAINER_CONNECTOR_LOGTAG via the wrapper. */

    switch (level) {
        case LOG_DEBUG_VERBOSE:
            mtdebug2(WM_CONTAINER_CONNECTOR_LOGTAG, "%s", log);
            break;
        case LOG_DEBUG:
            mtdebug1(WM_CONTAINER_CONNECTOR_LOGTAG, "%s", log);
            break;
        case LOG_INFO:
            mtinfo(WM_CONTAINER_CONNECTOR_LOGTAG, "%s", log);
            break;
        case LOG_WARNING:
            mtwarn(WM_CONTAINER_CONNECTOR_LOGTAG, "%s", log);
            break;
        case LOG_ERROR:
        case LOG_ERROR_EXIT:
            mterror(WM_CONTAINER_CONNECTOR_LOGTAG, "%s", log);
            break;
        default:
            mtinfo(WM_CONTAINER_CONNECTOR_LOGTAG, "%s", log);
            break;
    }
}

static void *wm_container_connector_main(wm_container_connector_t *cfg)
{
    if (cfg == NULL) {
        mterror(WM_CONTAINER_CONNECTOR_LOGTAG, "Null configuration. Exiting.");
        return NULL;
    }

    if (!cfg->kubernetes.enabled) {
        mtinfo(WM_CONTAINER_CONNECTOR_LOGTAG, "Module disabled. Exiting.");
        return NULL;
    }

    cc_config_t lib_cfg;
    memset(&lib_cfg, 0, sizeof(lib_cfg));
    lib_cfg.kubernetes.enabled    = cfg->kubernetes.enabled ? 1 : 0;
    lib_cfg.kubernetes.api_server = cfg->kubernetes.api_server;
    lib_cfg.kubernetes.ca_bundle  = cfg->kubernetes.ca_bundle;
    lib_cfg.kubernetes.token_path = cfg->kubernetes.token_path;
    lib_cfg.kubernetes.node_name  = cfg->kubernetes.node_name;

    cc_set_log_function(wm_cc_log_dispatch);
    cc_init(&lib_cfg);
    cc_start();

    /* Tick every second. The wm_shutdown_requested flag has priority: when it
     * is set, we abandon any in-progress wait and proceed to a clean stop. */
    while (!wm_shutdown_requested) {
        wm_sleep_interruptible(1);
    }

    cc_stop();

    mtinfo(WM_CONTAINER_CONNECTOR_LOGTAG, "Module finished.");
    return NULL;
}

static cJSON *wm_container_connector_dump(const wm_container_connector_t *cfg)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *obj  = cJSON_CreateObject();
    cJSON *k8s  = cJSON_CreateObject();

    cJSON_AddStringToObject(k8s, "enabled", cfg->kubernetes.enabled ? "yes" : "no");
    if (cfg->kubernetes.api_server) cJSON_AddStringToObject(k8s, "api_server", cfg->kubernetes.api_server);
    if (cfg->kubernetes.ca_bundle)  cJSON_AddStringToObject(k8s, "ca_bundle",  cfg->kubernetes.ca_bundle);
    if (cfg->kubernetes.token_path) cJSON_AddStringToObject(k8s, "token_path", cfg->kubernetes.token_path);
    if (cfg->kubernetes.node_name)  cJSON_AddStringToObject(k8s, "node_name",  cfg->kubernetes.node_name);
    cJSON_AddItemToObject(obj, "kubernetes", k8s);

    cJSON_AddItemToObject(root, "container_connector", obj);
    return root;
}

static void wm_container_connector_destroy(wm_container_connector_t *cfg)
{
    /* The main loop already called cc_stop() before exiting; calling it again
     * is idempotent and protects against odd shutdown orderings (e.g. config
     * reload teardown invoked before the main thread observed
     * wm_shutdown_requested). */
    cc_stop();

    if (cfg == NULL) {
        return;
    }

    os_free(cfg->kubernetes.api_server);
    os_free(cfg->kubernetes.ca_bundle);
    os_free(cfg->kubernetes.token_path);
    os_free(cfg->kubernetes.node_name);
    free(cfg);
}

#endif /* !WIN32 */
