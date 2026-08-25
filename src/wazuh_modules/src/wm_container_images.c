/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <signal.h>

#include "wm_container_images.h"

#include "wmodules.h"
#include "shared.h"
#include "sym_load.h"
#include "logging_helper.h"
#include "container_images.h"

#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...) _mtinfo(WM_CONTAINER_IMAGES_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mtwarn(WM_CONTAINER_IMAGES_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _mterror(WM_CONTAINER_IMAGES_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_CONTAINER_IMAGES_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_CONTAINER_IMAGES_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

#ifdef WAZUH_UNIT_TESTING
#define static
#endif

#ifdef WIN32
static DWORD WINAPI wm_container_images_main(void *arg);
#else
static void *wm_container_images_main(wm_container_images_t *data);
#endif
static void wm_container_images_destroy(wm_container_images_t *data);
static void wm_container_images_stop(wm_container_images_t *data);
cJSON *wm_container_images_dump(const wm_container_images_t *data);

const wm_context WM_CONTAINER_IMAGES_CONTEXT = {
    .name = "container_images",
    .start = (wm_routine)wm_container_images_main,
    .destroy = (void(*)(void *))wm_container_images_destroy,
    .dump = (cJSON * (*)(const void *))wm_container_images_dump,
    .sync = NULL,
    .stop = (void(*)(void *))wm_container_images_stop,
    .query = NULL,
};

static void *container_images_module = NULL;
static container_images_set_log_function_func container_images_set_log_function_ptr = NULL;
static container_images_init_func container_images_init_ptr = NULL;
static container_images_start_func container_images_start_ptr = NULL;
static container_images_stop_func container_images_stop_ptr = NULL;
static container_images_release_resources_func container_images_release_resources_ptr = NULL;

// volatile sig_atomic_t, not a plain int: this is written from wm_container_images_stop(),
// which on POSIX runs inside the SIGTERM handler (wm_handler, wazuh_modules/src/main.c),
// and read from the module thread below. Same idiom as syscollector's
// shutdown_process_started (wm_syscollector.c); the name is module-qualified because
// WAZUH_UNIT_TESTING undefines `static` and the two would otherwise collide at link time.
static volatile sig_atomic_t container_images_shutdown_started = 0;

static void wm_container_images_log_callback(const modules_log_level_t level, const char *log, __attribute__((unused)) const char *tag) {
    switch (level) {
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

static void wm_container_images_log_config(const wm_container_images_t *data) {
    minfo("Configuration loaded: enabled=%s, scan_on_start=%s, interval=%u, local references=%d.",
          data->enabled ? "yes" : "no",
          data->scan_on_start ? "yes" : "no",
          data->interval,
          data->local_paths_count);

    for (int i = 0; i < data->local_paths_count; i++) {
        mdebug1("Local reference configured: '%s'.", data->local_paths[i]);
    }
}

#ifdef WIN32
DWORD WINAPI wm_container_images_main(void *arg) {
    wm_container_images_t *data = (wm_container_images_t *)arg;
#else
void *wm_container_images_main(wm_container_images_t *data) {
#endif
    if (!data->enabled) {
        mdebug1("Module disabled. Exiting.");
        pthread_exit(NULL);
    }

    if (container_images_shutdown_started) {
        // A stop arrived while this thread was still starting up. The shutdown loop
        // signals every module before joining any of them, so this window is real.
        mdebug1("Shutdown requested before the module started. Skipping startup.");
        pthread_exit(NULL);
    }

    if (container_images_module = so_get_module_handle("container_images"), container_images_module) {
        container_images_set_log_function_ptr = so_get_function_sym(container_images_module, "container_images_set_log_function");
        container_images_init_ptr = so_get_function_sym(container_images_module, "container_images_init");
        container_images_start_ptr = so_get_function_sym(container_images_module, "container_images_start");
        container_images_stop_ptr = so_get_function_sym(container_images_module, "container_images_stop");
        container_images_release_resources_ptr = so_get_function_sym(container_images_module, "container_images_release_resources");
    } else {
        // This is the only load path for the library: unlike its peers, container_images
        // is not link-time linked, so this message is the only diagnostic the user gets.
#ifdef WIN32
        merror("Can't get container_images module handle: %s", win_strerror(GetLastError()));
#else
        const char *load_error = dlerror();
        merror("Can't get container_images module handle: %s", load_error ? load_error : "unknown error");
#endif
        pthread_exit(NULL);
    }

    if (!container_images_set_log_function_ptr || !container_images_init_ptr ||
        !container_images_start_ptr || !container_images_stop_ptr ||
        !container_images_release_resources_ptr) {
        merror("Can't get required container_images module symbols.");
        pthread_exit(NULL);
    }

    container_images_set_log_function_ptr(wm_container_images_log_callback);

    container_images_init_ptr(data->interval, data->scan_on_start, data->enabled,
                              (const char**)data->local_paths, (unsigned int)data->local_paths_count);

    wm_container_images_log_config(data);

    if (container_images_shutdown_started) {
        mdebug1("Shutdown requested while the module was starting. Skipping the scan loop.");
    } else {
        minfo(STARTUP_MSG, (int)getpid());
        container_images_start_ptr();
    }

    container_images_release_resources_ptr();
    container_images_release_resources_ptr = NULL;

#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}

void wm_container_images_stop(__attribute__((unused)) wm_container_images_t *data) {
    // Record the stop before anything else: container_images_stop_ptr stays NULL until
    // the module thread resolves the symbols, so without this latch a stop that lands in
    // that window is dropped and the module scans on through the shutdown.
    container_images_shutdown_started = 1;

    if (container_images_stop_ptr) {
        container_images_stop_ptr();
    } else {
        mdebug1("Stop received before the container_images module finished loading.");
    }
}

void wm_container_images_destroy(wm_container_images_t *data) {
    if (data) {
        if (data->local_paths) {
            for (int i = 0; i < data->local_paths_count; i++) {
                os_free(data->local_paths[i]);
            }
            os_free(data->local_paths);
        }
        os_free(data);
    }
}

cJSON *wm_container_images_dump(const wm_container_images_t *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();

    cJSON_AddStringToObject(wm_wd, "enabled", data->enabled ? "yes" : "no");
    cJSON_AddStringToObject(wm_wd, "scan_on_start", data->scan_on_start ? "yes" : "no");
    cJSON_AddNumberToObject(wm_wd, "interval", data->interval);

    if (data->local_paths && data->local_paths_count > 0) {
        cJSON *references = cJSON_CreateArray();
        for (int i = 0; i < data->local_paths_count; i++) {
            cJSON_AddItemToArray(references, cJSON_CreateString(data->local_paths[i]));
        }
        cJSON_AddItemToObject(wm_wd, "local", references);
    }

    cJSON_AddItemToObject(root, "container_images", wm_wd);

    return root;
}
