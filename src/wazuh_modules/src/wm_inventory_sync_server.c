/*
 * Wazuh Module for the inventory sync server (HTTP over Unix domain socket)
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wm_inventory_sync_server.h"
#include "indexer-config.h"
#include "inventory_sync_server.h"
#include "sym_load.h"
#include <cJSON.h>

static void* wm_inventory_sync_server_main(wm_inventory_sync_server_t* data);
static void wm_inventory_sync_server_destroy(wm_inventory_sync_server_t* data);
static void wm_inventory_sync_server_stop(wm_inventory_sync_server_t* data);
cJSON* wm_inventory_sync_server_dump(wm_inventory_sync_server_t* data);

void* inventory_sync_server_module = NULL;
inventory_sync_server_start_func inventory_sync_server_start_ptr = NULL;
inventory_sync_server_stop_func inventory_sync_server_stop_ptr = NULL;

const wm_context WM_INVENTORY_SYNC_SERVER_CONTEXT = {
    .name = "inventory_sync_server",
    .start = (wm_routine)wm_inventory_sync_server_main,
    .destroy = (void (*)(void*))wm_inventory_sync_server_destroy,
    .dump = (cJSON * (*)(const void*)) wm_inventory_sync_server_dump,
    .sync = NULL,
    .stop = (void (*)(void*))wm_inventory_sync_server_stop,
    .query = NULL,
};

/* Secrets-free: only the socket, the limits and the shape of the indexer block. The indexer's own
 * credentials live inside indexer_config and are deliberately never rendered here. */
static void wm_inventory_sync_server_log_config(const inventory_sync_server_config_t* config)
{
    mtdebug1(WM_INVENTORY_SYNC_SERVER_LOGTAG,
             "socket_path='%s', io_threads=%d, max_body_size=%d, max_parallel_connections=%d, "
             "max_inflight_bytes=%lld, cluster='%s'",
             config->socket_path,
             config->io_threads,
             config->max_body_size,
             config->max_parallel_connections,
             config->max_inflight_bytes,
             config->cluster_name);

    /* The rest of the transport, so every tunable is observable here at debug level; the module's
     * own startup INFO carries the effective values. None of them is a secret. */
    mtdebug1(WM_INVENTORY_SYNC_SERVER_LOGTAG,
             "transport: concurrent_accepts=%d, buffer_size=%d, max_url_size=%d, max_header_name_size=%d, "
             "max_header_value_size=%d",
             config->concurrent_accepts,
             config->buffer_size,
             config->max_url_size,
             config->max_header_name_size,
             config->max_header_value_size);
    mtdebug1(WM_INVENTORY_SYNC_SERVER_LOGTAG,
             "timeouts (s): header=%d, body=%d, response=%d, write=%d, drain=%d",
             config->header_timeout,
             config->body_timeout,
             config->response_timeout,
             config->write_timeout,
             config->drain_timeout);

    mtdebug1(WM_INVENTORY_SYNC_SERVER_LOGTAG,
             "sync pipeline: sync_workers=%d, sync_queue_bytes=%lld, vd_feed_retry_after_seconds=%d, vd_workers=%d, "
             "vd_scan_queue_slots=%d",
             config->sync_workers,
             config->sync_queue_bytes,
             config->vd_feed_retry_after_seconds,
             config->vd_workers,
             config->vd_scan_queue_slots);

    /* Split from the line above so the two indexer families stay visually distinct in the log, the
     * same way they are in the configuration: their key names are NOT interchangeable. */
    mtdebug1(WM_INVENTORY_SYNC_SERVER_LOGTAG,
             "indexer sync: max_bulk_size=%d, flush_interval_seconds=%d, max_retry_delay_seconds=%d",
             config->indexer_sync_max_bulk_size,
             config->indexer_sync_flush_interval_seconds,
             config->indexer_sync_max_retry_delay_seconds);
    mtdebug1(WM_INVENTORY_SYNC_SERVER_LOGTAG,
             "indexer async: bulk_max_bytes=%d, flush_interval_seconds=%d, max_retry_delay_seconds=%d, "
             "max_queue_bytes=%lld, logger_queue_size=%d, logger_threads=%d",
             config->indexer_async_bulk_max_bytes,
             config->indexer_async_flush_interval_seconds,
             config->indexer_async_max_retry_delay_seconds,
             config->indexer_async_max_queue_bytes,
             config->indexer_async_logger_queue_size,
             config->indexer_async_logger_threads);
}

/**
 * @brief Reads every internal option into @p config.
 *
 * Called from wm_inventory_sync_server_read(), i.e. from inside wm_config(), which runs BEFORE
 * `wazuh-modulesd -t` returns and before goDaemon(). That placement is the point:
 * getDefine_Int_default() calls merror_exit() -- exit(1) for the whole daemon -- when a value is
 * present but out of range, so reading these here means a bad value is caught by the config test and
 * makes `wazuh-manager-control start` fail, instead of killing modulesd from a module thread seconds
 * after the init script already printed "Started".
 */
static void wm_inventory_sync_server_read_tunables(inventory_sync_server_config_t* config)
{
    /* Every numeric fallback below is 0, which the module reads as "use my default". That is
     * deliberate: it keeps ONE copy of each default, in the module, instead of a second copy
     * here that could silently drift. The socket path is left empty for the same reason -- and stays
     * that way: it is NOT configurable, since internal options cannot carry strings.
     *
     * `socket_mode` and `max_header_count` are deliberately absent; see inventory_sync_server.h for why
     * each is fixed rather than tunable. */
    config->io_threads = getDefine_Int_default("wazuh_modules", "inventory_sync_server_io_threads", 0, 128, 0);
    config->concurrent_accepts =
        getDefine_Int_default("wazuh_modules", "inventory_sync_server_concurrent_accepts", 0, 64, 0);
    config->buffer_size = getDefine_Int_default("wazuh_modules", "inventory_sync_server_buffer_size", 0, 1048576, 0);
    config->max_body_size =
        getDefine_Int_default("wazuh_modules", "inventory_sync_server_max_body_size", 0, 536870912, 0);
    config->max_url_size = getDefine_Int_default("wazuh_modules", "inventory_sync_server_max_url_size", 0, 65536, 0);
    config->max_header_name_size =
        getDefine_Int_default("wazuh_modules", "inventory_sync_server_max_header_name_size", 0, 65536, 0);
    config->max_header_value_size =
        getDefine_Int_default("wazuh_modules", "inventory_sync_server_max_header_value_size", 0, 1048576, 0);
    config->header_timeout = getDefine_Int_default("wazuh_modules", "inventory_sync_server_header_timeout", 0, 3600, 0);
    config->body_timeout = getDefine_Int_default("wazuh_modules", "inventory_sync_server_body_timeout", 0, 3600, 0);
    /* Max 3600, not 86400: this timer is the LEAK BACKSTOP for a handler that lost its responder, and
     * a backstop measured in days bounds nothing. */
    config->response_timeout =
        getDefine_Int_default("wazuh_modules", "inventory_sync_server_response_timeout", 0, 3600, 0);
    config->write_timeout = getDefine_Int_default("wazuh_modules", "inventory_sync_server_write_timeout", 0, 3600, 0);
    /* Max 10, not 30: modulesd gives the WHOLE daemon 30 s to shut down, so letting one module's drain
     * window alone consume all of it defeats the budget this value exists to respect. */
    config->drain_timeout = getDefine_Int_default("wazuh_modules", "inventory_sync_server_drain_timeout", 0, 10, 0);
    config->max_parallel_connections =
        getDefine_Int_default("wazuh_modules", "inventory_sync_server_max_parallel_connections", 0, 65536, 0);
    /* Read with a fallback of -1 to tell "absent" from an explicit 0, then translated to the C-ABI's
     * encoding. 0 is documented as "disable the byte budget", but the option's own range starts at 0, so
     * with a fallback of 0 an absent key looked exactly like an operator asking for unlimited -- and the
     * module had to read 0 as "use my default", leaving the documented off switch unreachable.
     * getDefine_Int_default returns the fallback WITHOUT range-checking it and the parser rejects a
     * leading '-', so -1 is a value an operator cannot produce: it means "absent" unambiguously.
     *
     * Translating HERE keeps 0 meaning "no opinion" across the C-ABI, so a zero-filled config still
     * resolves to every default. */
    const int inflight =
        getDefine_Int_default("wazuh_modules", "inventory_sync_server_max_inflight_bytes", 0, 2147483647, -1);
    if (inflight < 0)
    {
        config->max_inflight_bytes = 0; /* absent -> the module default */
    }
    else if (inflight == 0)
    {
        config->max_inflight_bytes = -1; /* the operator asked for unlimited */
    }
    else
    {
        config->max_inflight_bytes = (long long)inflight;
    }

    /* Not a tunable of this module, but the ceiling that makes max_parallel_connections meaningful:
     * every live connection and every deferred reply costs a descriptor, out of a limit shared by all of
     * modulesd. Configuring more connections than descriptors guarantees EMFILE long before the cap is
     * reached. Same key and range as wm_setup() so the two cannot disagree. */
    const int nofile = getDefine_Int_default("wazuh_modules", "rlimit_nofile", 8192, 1048576, 8192);
    if (config->max_parallel_connections > nofile)
    {
        mtwarn(WM_INVENTORY_SYNC_SERVER_LOGTAG,
               "'inventory_sync_server_max_parallel_connections' is %d but modulesd's descriptor limit "
               "('wazuh_modules.rlimit_nofile') is %d, and that limit is shared with every other module. "
               "Connections will fail with 'too many open files' well before the configured cap.",
               config->max_parallel_connections,
               nofile);
    }

    /* ---- Sync pipeline (the POST /stateful ingestion path). sync_workers keeps the 0 sentinel
     * (0 -> half the cores, resolved by the module); the other two carry real defaults because
     * their zero would be ambiguous: a 0 queue cap would mean "shed everything" and a 0
     * Retry-After tells the agent to hammer the endpoint. */
    config->sync_workers = getDefine_Int_default("wazuh_modules", "inventory_sync_server_sync_workers", 0, 64, 0);
    config->sync_queue_bytes =
        (long long)getDefine_Int_default("wazuh_modules",
                                         "inventory_sync_server_sync_queue_bytes",
                                         1048576,
                                         1073741824,
                                         64 * 1024 * 1024);
    config->vd_feed_retry_after_seconds =
        getDefine_Int_default("wazuh_modules", "inventory_sync_server_vd_feed_retry_after_seconds", 10, 1800, 60);
    config->vd_workers = getDefine_Int_default("wazuh_modules", "inventory_sync_server_vd_workers", 0, 16, 0);
    config->vd_scan_queue_slots =
        getDefine_Int_default("wazuh_modules", "inventory_sync_server_vd_scan_queue_slots", 0, 256, 0);

    /* ---- Indexer connector tunables. Unlike the transport options above these carry real
     * ranges and defaults rather than the 0 sentinel, because they are forwarded to a shared
     * library whose own defaults we mirror here. Each one names the connector key it maps to.
     *
     * The two families are deliberately separate: IndexerConnectorSync reads `max_bulk_size`
     * while IndexerConnectorAsync reads `bulk_max_bytes` for the same concept, and handing
     * either the other's key is ignored silently. Keep the `indexer_sync_`/`indexer_async_`
     * prefixes intact.
     *
     * Note the minimum of 1 on both `max_retry_delay_seconds`: the connector constructors reject
     * anything below their base retry delay of 1. Combined with the module's `<=0 means use the
     * connector default` sentinel, that makes a rejecting value unreachable from configuration
     * -- the minimum here turns an operator's 0 into a rejected configuration instead of a
     * silent fallback to the default. ---- */
    config->indexer_sync_max_bulk_size =
        getDefine_Int_default("wazuh_modules",
                              "inventory_sync_server_indexer_sync_max_bulk_size", /* -> max_bulk_size */
                              4096,
                              100 * 1024 * 1024,
                              10 * 1024 * 1024);
    config->indexer_sync_flush_interval_seconds = getDefine_Int_default(
        "wazuh_modules",
        "inventory_sync_server_indexer_sync_flush_interval_seconds", /* -> flush_interval_seconds */
        1,
        3600,
        20);
    config->indexer_sync_max_retry_delay_seconds = getDefine_Int_default(
        "wazuh_modules",
        "inventory_sync_server_indexer_sync_max_retry_delay_seconds", /* -> max_retry_delay_seconds */
        1,
        3600,
        15);

    config->indexer_async_bulk_max_bytes =
        getDefine_Int_default("wazuh_modules",
                              "inventory_sync_server_indexer_async_bulk_max_bytes", /* -> bulk_max_bytes */
                              4096,
                              100 * 1024 * 1024,
                              4 * 1024 * 1024);
    config->indexer_async_flush_interval_seconds = getDefine_Int_default(
        "wazuh_modules",
        "inventory_sync_server_indexer_async_flush_interval_seconds", /* -> flush_interval_seconds */
        1,
        3600,
        20);
    config->indexer_async_max_retry_delay_seconds = getDefine_Int_default(
        "wazuh_modules",
        "inventory_sync_server_indexer_async_max_retry_delay_seconds", /* -> max_retry_delay_seconds */
        1,
        3600,
        15);
    config->indexer_async_logger_queue_size =
        getDefine_Int_default("wazuh_modules",
                              "inventory_sync_server_indexer_async_logger_queue_size", /* -> logger_queue_size */
                              1,
                              65536,
                              8);
    config->indexer_async_logger_threads =
        getDefine_Int_default("wazuh_modules",
                              "inventory_sync_server_indexer_async_logger_threads", /* -> logger_threads */
                              1,
                              64,
                              1);
    /* Minimum 0, NOT 1: 0 is the connector's own legitimate "unlimited", and
     * getDefine_Int_default() calls merror_exit() on an out-of-range value, so a minimum of 1
     * would turn that documented setting into a fatal abort. The shipped default is bounded
     * (64 MiB, the same value the engine uses for this key) because an unbounded queue is the
     * only unbounded allocation this module can be configured to make. */
    config->indexer_async_max_queue_bytes =
        (long long)getDefine_Int_default("wazuh_modules",
                                         "inventory_sync_server_indexer_async_max_queue_bytes", /* -> max_queue_bytes */
                                         0,
                                         2147483647,
                                         64 * 1024 * 1024);
}

void* wm_inventory_sync_server_main(wm_inventory_sync_server_t* data)
{
    mtinfo(WM_INVENTORY_SYNC_SERVER_LOGTAG, STARTUP_MSG, (int)getpid());

    if (!data || !data->config)
    {
        mterror(WM_INVENTORY_SYNC_SERVER_LOGTAG, "Started without configuration; not starting the module.");
        return NULL;
    }

    if (inventory_sync_server_module = so_get_module_handle("inventory_sync_server"), inventory_sync_server_module)
    {
        inventory_sync_server_start_ptr =
            so_get_function_sym(inventory_sync_server_module, "inventory_sync_server_start");
        inventory_sync_server_stop_ptr =
            so_get_function_sym(inventory_sync_server_module, "inventory_sync_server_stop");

        if (inventory_sync_server_start_ptr)
        {
            /* start() launches a worker thread and returns at once; the socket is bound from that
             * thread, with a retry every 60 s. Said here because this is the last line under this
             * tag on the happy path -- progress and failures continue under the module's own tag. */
            mtinfo(WM_INVENTORY_SYNC_SERVER_LOGTAG,
                   "Dispatching start; the module binds its socket asynchronously and reports under its own tag.");
            /* The tunables were read -- and validated -- at configuration time; only the values that
             * come from the XML configuration are resolved here, where their parse order is settled. */
            inventory_sync_server_config_t config = *data->config;

            char* cluster_name = get_cluster_name();
            if (cluster_name)
            {
                snprintf(config.cluster_name, sizeof(config.cluster_name), "%s", cluster_name);
                os_free(cluster_name);
            }

            /* Borrowed for the call only: the module deep-copies what it needs, and
             * inventory_sync_server.h documents that contract, so this duplicate can be freed as
             * soon as start() returns. indexer_config is already populated by the time any module
             * thread runs -- wm_config() reads the configuration before main() creates them. */
            cJSON* indexer_json = indexer_config ? cJSON_Duplicate(indexer_config, TRUE) : cJSON_CreateObject();
            config.indexer = indexer_json;

            wm_inventory_sync_server_log_config(&config);
            const int status = inventory_sync_server_start_ptr(mtLoggingFunctionsWrapper, &config);
            cJSON_Delete(indexer_json);

            if (status != 0)
            {
                /* The module reported a condition its retry loop cannot fix: an unbindable socket
                 * path, or an exception before the worker thread existed. Inventory ingress would
                 * then be silently absent for the life of the daemon, so refuse to run instead.
                 *
                 * This is post-fork (module threads are created after goDaemon()), so
                 * `wazuh-manager-control start` will already have reported success and the failure
                 * shows up in `status` and the log. The internal options, by contrast, are validated
                 * in wm_inventory_sync_server_read(), which is pre-fork and visible to `-t`. */
                mterror_exit(WM_INVENTORY_SYNC_SERVER_LOGTAG,
                             "Inventory sync server cannot start; see the preceding error. Not running without "
                             "inventory ingress.");
            }
        }
        else
        {
            /* Same terminality as a failed start: without the entry point this module is absent for
             * the daemon's whole life, and a manager that looks healthy while quietly losing
             * inventory is worse than one that refuses to run. Points at packaging, the one thing an
             * operator can act on. */
            mterror_exit(WM_INVENTORY_SYNC_SERVER_LOGTAG,
                         "libinventory_sync_server.so does not export inventory_sync_server_start; the "
                         "installation is broken. Not running without inventory ingress.");
        }
    }
    else
    {
        mterror_exit(WM_INVENTORY_SYNC_SERVER_LOGTAG,
                     "Unable to load libinventory_sync_server.so; the installation is broken. Not running "
                     "without inventory ingress.");
    }

    /* start() is non-blocking -- the module owns its own worker thread -- so this routine returns
     * and modulesd's thread for it exits immediately. Teardown goes through the .stop callback. */
    return NULL;
}

void wm_inventory_sync_server_destroy(wm_inventory_sync_server_t* data)
{
    if (data)
    {
        os_free(data->config);
    }
    free(data);
}

void wm_inventory_sync_server_stop(__attribute__((unused)) wm_inventory_sync_server_t* data)
{
    if (inventory_sync_server_stop_ptr)
    {
        inventory_sync_server_stop_ptr();
    }
    else
    {
        mtwarn(WM_INVENTORY_SYNC_SERVER_LOGTAG, "Unable to stop inventory_sync_server module.");
    }
    /* After the stop, not before: stop() drains in-flight requests and joins the worker, so a
     * "finished" printed first would be a lie for those seconds -- exactly the ones an operator
     * stares at during a hung shutdown. */
    mtinfo(WM_INVENTORY_SYNC_SERVER_LOGTAG, "Module finished.");
}

wmodule* wm_inventory_sync_server_read()
{
    wmodule* module;
    wm_inventory_sync_server_t* data;

    os_calloc(1, sizeof(wmodule), module);
    os_calloc(1, sizeof(wm_inventory_sync_server_t), data);
    os_calloc(1, sizeof(inventory_sync_server_config_t), data->config);

    /* Read HERE, not in the module's thread: this runs inside wm_config(), so an out-of-range value
     * fails `wazuh-modulesd -t` and aborts the start before goDaemon(). See the function's comment. */
    wm_inventory_sync_server_read_tunables(data->config);

    module->context = &WM_INVENTORY_SYNC_SERVER_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = data;

    mtdebug1(WM_INVENTORY_SYNC_SERVER_LOGTAG, "Loaded Inventory sync server module.");
    return module;
}

cJSON* wm_inventory_sync_server_dump(wm_inventory_sync_server_t* data)
{
    cJSON* root = cJSON_CreateObject();

    if (!data || !data->config)
    {
        return root;
    }

    /* Reported so `getconfig wmodules` can answer what this module is actually running with.
     * Secrets-free by construction: the <indexer> block, the only part of the configuration that
     * can carry credentials, is deliberately excluded. */
    cJSON* config = cJSON_CreateObject();
    cJSON_AddNumberToObject(config, "io_threads", data->config->io_threads);
    cJSON_AddNumberToObject(config, "concurrent_accepts", data->config->concurrent_accepts);
    cJSON_AddNumberToObject(config, "buffer_size", data->config->buffer_size);
    cJSON_AddNumberToObject(config, "max_body_size", data->config->max_body_size);
    cJSON_AddNumberToObject(config, "max_url_size", data->config->max_url_size);
    cJSON_AddNumberToObject(config, "max_header_name_size", data->config->max_header_name_size);
    cJSON_AddNumberToObject(config, "max_header_value_size", data->config->max_header_value_size);
    cJSON_AddNumberToObject(config, "header_timeout", data->config->header_timeout);
    cJSON_AddNumberToObject(config, "body_timeout", data->config->body_timeout);
    cJSON_AddNumberToObject(config, "response_timeout", data->config->response_timeout);
    cJSON_AddNumberToObject(config, "write_timeout", data->config->write_timeout);
    cJSON_AddNumberToObject(config, "drain_timeout", data->config->drain_timeout);
    cJSON_AddNumberToObject(config, "max_parallel_connections", data->config->max_parallel_connections);
    cJSON_AddNumberToObject(config, "max_inflight_bytes", (double)data->config->max_inflight_bytes);
    cJSON_AddNumberToObject(config, "sync_workers", data->config->sync_workers);
    cJSON_AddNumberToObject(config, "sync_queue_bytes", (double)data->config->sync_queue_bytes);
    cJSON_AddNumberToObject(config, "vd_feed_retry_after_seconds", data->config->vd_feed_retry_after_seconds);
    cJSON_AddNumberToObject(config, "vd_workers", data->config->vd_workers);
    cJSON_AddNumberToObject(config, "vd_scan_queue_slots", data->config->vd_scan_queue_slots);
    cJSON_AddNumberToObject(config, "indexer_sync_max_bulk_size", data->config->indexer_sync_max_bulk_size);
    cJSON_AddNumberToObject(
        config, "indexer_sync_flush_interval_seconds", data->config->indexer_sync_flush_interval_seconds);
    cJSON_AddNumberToObject(
        config, "indexer_sync_max_retry_delay_seconds", data->config->indexer_sync_max_retry_delay_seconds);
    cJSON_AddNumberToObject(config, "indexer_async_bulk_max_bytes", data->config->indexer_async_bulk_max_bytes);
    cJSON_AddNumberToObject(
        config, "indexer_async_flush_interval_seconds", data->config->indexer_async_flush_interval_seconds);
    cJSON_AddNumberToObject(
        config, "indexer_async_max_retry_delay_seconds", data->config->indexer_async_max_retry_delay_seconds);
    cJSON_AddNumberToObject(config, "indexer_async_logger_queue_size", data->config->indexer_async_logger_queue_size);
    cJSON_AddNumberToObject(config, "indexer_async_logger_threads", data->config->indexer_async_logger_threads);
    cJSON_AddNumberToObject(
        config, "indexer_async_max_queue_bytes", (double)data->config->indexer_async_max_queue_bytes);

    cJSON_AddItemToObject(root, "inventory_sync_server", config);
    return root;
}
