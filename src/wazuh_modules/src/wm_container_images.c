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
static container_images_set_registry_options_func container_images_set_registry_options_ptr = NULL;
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
    minfo("Configuration loaded: enabled=%s, scan_on_start=%s, interval=%u, references=%d.",
          data->enabled ? "yes" : "no",
          data->scan_on_start ? "yes" : "no",
          data->interval,
          data->references_count);

    for (int i = 0; i < data->references_count; i++) {
        mdebug1("Reference configured: <%s>%s.", data->references[i].type, data->references[i].value);
    }

    // The host and the key names, never the values: the values are read from the
    // credential store at scan time and must not reach a log line at any level.
    for (int i = 0; i < data->registries_count; i++) {
        mdebug1("Registry credentials configured for '%s': user key '%s', passkey key '%s'.",
                data->registries[i].host, data->registries[i].user_key, data->registries[i].passkey_key);
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
        container_images_set_registry_options_ptr = so_get_function_sym(container_images_module, "container_images_set_registry_options");
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
        !container_images_set_registry_options_ptr ||
        !container_images_start_ptr || !container_images_stop_ptr ||
        !container_images_release_resources_ptr) {
        merror("Can't get required container_images module symbols.");
        pthread_exit(NULL);
    }

    container_images_set_log_function_ptr(wm_container_images_log_callback);

    // The bridge takes the entry types and the values as two parallel arrays, so the
    // struct layout stays on this side of the library boundary.
    const char **reference_types = NULL;
    const char **reference_values = NULL;

    if (data->references_count > 0) {
        os_calloc((size_t)data->references_count, sizeof(char *), reference_types);
        os_calloc((size_t)data->references_count, sizeof(char *), reference_values);

        for (int i = 0; i < data->references_count; i++) {
            reference_types[i] = data->references[i].type;
            reference_values[i] = data->references[i].value;
        }
    }

    // Registry options are handed over before initialization, so the configuration is
    // complete by the time the module builds its implementation.
    const char **registry_hosts = NULL;
    const char **registry_user_keys = NULL;
    const char **registry_passkey_keys = NULL;

    if (data->registries_count > 0) {
        os_calloc((size_t)data->registries_count, sizeof(char *), registry_hosts);
        os_calloc((size_t)data->registries_count, sizeof(char *), registry_user_keys);
        os_calloc((size_t)data->registries_count, sizeof(char *), registry_passkey_keys);

        for (int i = 0; i < data->registries_count; i++) {
            registry_hosts[i] = data->registries[i].host;
            registry_user_keys[i] = data->registries[i].user_key;
            registry_passkey_keys[i] = data->registries[i].passkey_key;
        }
    }

    container_images_set_registry_options_ptr(registry_hosts, registry_user_keys, registry_passkey_keys,
                                              (unsigned int)data->registries_count, data->ca_bundle);

    os_free(registry_hosts);
    os_free(registry_user_keys);
    os_free(registry_passkey_keys);

    container_images_init_ptr(data->interval, data->scan_on_start, data->enabled,
                              reference_types, reference_values, (unsigned int)data->references_count);

    os_free(reference_types);
    os_free(reference_values);

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
        if (data->references) {
            for (int i = 0; i < data->references_count; i++) {
                os_free(data->references[i].type);
                os_free(data->references[i].value);
            }
            os_free(data->references);
        }
        if (data->registries) {
            for (int i = 0; i < data->registries_count; i++) {
                os_free(data->registries[i].host);
                os_free(data->registries[i].user_key);
                os_free(data->registries[i].passkey_key);
            }
            os_free(data->registries);
        }
        os_free(data->ca_bundle);
        os_free(data);
    }
}

cJSON *wm_container_images_dump(const wm_container_images_t *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();

    cJSON_AddStringToObject(wm_wd, "enabled", data->enabled ? "yes" : "no");
    cJSON_AddStringToObject(wm_wd, "scan_on_start", data->scan_on_start ? "yes" : "no");
    cJSON_AddNumberToObject(wm_wd, "interval", data->interval);

    if (data->references && data->references_count > 0) {
        cJSON *references = cJSON_CreateObject();

        // One array per entry type, so the dump mirrors the configuration block.
        for (int i = 0; i < data->references_count; i++) {
            cJSON *entries = cJSON_GetObjectItem(references, data->references[i].type);

            if (!entries) {
                entries = cJSON_CreateArray();
                cJSON_AddItemToObject(references, data->references[i].type, entries);
            }

            cJSON_AddItemToArray(entries, cJSON_CreateString(data->references[i].value));
        }

        cJSON_AddItemToObject(wm_wd, "references", references);
    }

    if (data->registries && data->registries_count > 0) {
        cJSON *registry_auth = cJSON_CreateArray();

        // Key names only. The dump is readable through the configuration API, so a
        // credential value here would put the secret back where the store exists to
        // keep it out of.
        for (int i = 0; i < data->registries_count; i++) {
            cJSON *registry = cJSON_CreateObject();
            cJSON_AddStringToObject(registry, "host", data->registries[i].host);
            cJSON_AddStringToObject(registry, "user_keystore_key", data->registries[i].user_key);
            cJSON_AddStringToObject(registry, "passkey_keystore_key", data->registries[i].passkey_key);
            cJSON_AddItemToArray(registry_auth, registry);
        }

        cJSON_AddItemToObject(wm_wd, "registry_auth", registry_auth);
    }

    if (data->ca_bundle) {
        cJSON_AddStringToObject(wm_wd, "ca_bundle", data->ca_bundle);
    }

    cJSON_AddItemToObject(root, "container_images", wm_wd);

    return root;
}
