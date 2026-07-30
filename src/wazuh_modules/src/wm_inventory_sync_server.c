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
             "max_inflight_bytes=%lld, cluster='%s', node='%s'",
             config->socket_path,
             config->io_threads,
             config->max_body_size,
             config->max_parallel_connections,
             config->max_inflight_bytes,
             config->cluster_name,
             config->node_name);

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

void* wm_inventory_sync_server_main(__attribute__((unused)) wm_inventory_sync_server_t* data)
{
    mtinfo(WM_INVENTORY_SYNC_SERVER_LOGTAG, STARTUP_MSG, (int)getpid());

    if (inventory_sync_server_module = so_get_module_handle("inventory_sync_server"), inventory_sync_server_module)
    {
        inventory_sync_server_start_ptr =
            so_get_function_sym(inventory_sync_server_module, "inventory_sync_server_start");
        inventory_sync_server_stop_ptr =
            so_get_function_sym(inventory_sync_server_module, "inventory_sync_server_stop");

        if (inventory_sync_server_start_ptr)
        {
            inventory_sync_server_config_t config = {0};

            char* cluster_name = get_cluster_name();
            if (cluster_name)
            {
                snprintf(config.cluster_name, sizeof(config.cluster_name), "%s", cluster_name);
                os_free(cluster_name);
            }

            char* manager_node_name = get_node_name();
            if (manager_node_name)
            {
                snprintf(config.node_name, sizeof(config.node_name), "%s", manager_node_name);
                os_free(manager_node_name);
            }

            /* Every numeric fallback below is 0, which the module reads as "use my default". That is
             * deliberate: it keeps ONE copy of each default, in the module, instead of a second copy
             * here that could silently drift. The socket path is left empty for the same reason. */
            config.io_threads = getDefine_Int_default("wazuh_modules", "inventory_sync_server_io_threads", 0, 128, 0);
            config.concurrent_accepts =
                getDefine_Int_default("wazuh_modules", "inventory_sync_server_concurrent_accepts", 0, 64, 0);
            config.buffer_size =
                getDefine_Int_default("wazuh_modules", "inventory_sync_server_buffer_size", 0, 1048576, 0);
            config.max_body_size =
                getDefine_Int_default("wazuh_modules", "inventory_sync_server_max_body_size", 0, 536870912, 0);
            config.max_url_size =
                getDefine_Int_default("wazuh_modules", "inventory_sync_server_max_url_size", 0, 65536, 0);
            config.max_header_name_size =
                getDefine_Int_default("wazuh_modules", "inventory_sync_server_max_header_name_size", 0, 65536, 0);
            config.max_header_value_size =
                getDefine_Int_default("wazuh_modules", "inventory_sync_server_max_header_value_size", 0, 1048576, 0);
            config.max_header_count =
                getDefine_Int_default("wazuh_modules", "inventory_sync_server_max_header_count", 0, 1024, 0);
            config.header_timeout =
                getDefine_Int_default("wazuh_modules", "inventory_sync_server_header_timeout", 0, 3600, 0);
            config.body_timeout =
                getDefine_Int_default("wazuh_modules", "inventory_sync_server_body_timeout", 0, 3600, 0);
            config.response_timeout =
                getDefine_Int_default("wazuh_modules", "inventory_sync_server_response_timeout", 0, 86400, 0);
            config.write_timeout =
                getDefine_Int_default("wazuh_modules", "inventory_sync_server_write_timeout", 0, 3600, 0);
            config.drain_timeout =
                getDefine_Int_default("wazuh_modules", "inventory_sync_server_drain_timeout", 0, 30, 0);
            config.max_parallel_connections =
                getDefine_Int_default("wazuh_modules", "inventory_sync_server_max_parallel_connections", 0, 65536, 0);
            config.max_inflight_bytes = (long long)getDefine_Int_default(
                "wazuh_modules", "inventory_sync_server_max_inflight_bytes", 0, 2147483647, 0);
            config.socket_mode = getDefine_Int_default("wazuh_modules", "inventory_sync_server_socket_mode", 0, 511, 0);

            /* ---- Indexer connector tunables. Unlike the transport options above these carry real
             * ranges and defaults rather than the 0 sentinel, because they are forwarded to a shared
             * library whose own defaults we mirror here so `wazuh-modulesd -t` can reject a bad value
             * up front. Each one names the connector key it maps to.
             *
             * The two families are deliberately separate: IndexerConnectorSync reads `max_bulk_size`
             * while IndexerConnectorAsync reads `bulk_max_bytes` for the same concept, and handing
             * either the other's key is ignored silently. Keep the `indexer_sync_`/`indexer_async_`
             * prefixes intact.
             *
             * Note the minimum of 1 on both `max_retry_delay_seconds`: the connector constructors reject
             * anything below their base retry delay of 1. Combined with the module's `<=0 means use the
             * connector default` sentinel, that makes a rejecting value unreachable from configuration
             * -- the minimum here turns an operator's 0 into a startup-time complaint instead of a
             * silent fallback to the default. ---- */
            config.indexer_sync_max_bulk_size =
                getDefine_Int_default("wazuh_modules",
                                      "inventory_sync_server_indexer_sync_max_bulk_size", /* -> max_bulk_size */
                                      4096,
                                      100 * 1024 * 1024,
                                      10 * 1024 * 1024);
            config.indexer_sync_flush_interval_seconds = getDefine_Int_default(
                "wazuh_modules",
                "inventory_sync_server_indexer_sync_flush_interval_seconds", /* -> flush_interval_seconds */
                1,
                3600,
                20);
            config.indexer_sync_max_retry_delay_seconds = getDefine_Int_default(
                "wazuh_modules",
                "inventory_sync_server_indexer_sync_max_retry_delay_seconds", /* -> max_retry_delay_seconds */
                1,
                3600,
                15);

            config.indexer_async_bulk_max_bytes =
                getDefine_Int_default("wazuh_modules",
                                      "inventory_sync_server_indexer_async_bulk_max_bytes", /* -> bulk_max_bytes */
                                      4096,
                                      100 * 1024 * 1024,
                                      4 * 1024 * 1024);
            config.indexer_async_flush_interval_seconds = getDefine_Int_default(
                "wazuh_modules",
                "inventory_sync_server_indexer_async_flush_interval_seconds", /* -> flush_interval_seconds */
                1,
                3600,
                20);
            config.indexer_async_max_retry_delay_seconds = getDefine_Int_default(
                "wazuh_modules",
                "inventory_sync_server_indexer_async_max_retry_delay_seconds", /* -> max_retry_delay_seconds */
                1,
                3600,
                15);
            config.indexer_async_logger_queue_size = getDefine_Int_default(
                "wazuh_modules",
                "inventory_sync_server_indexer_async_logger_queue_size", /* -> logger_queue_size */
                1,
                65536,
                8);
            config.indexer_async_logger_threads =
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
            config.indexer_async_max_queue_bytes = (long long)getDefine_Int_default(
                "wazuh_modules",
                "inventory_sync_server_indexer_async_max_queue_bytes", /* -> max_queue_bytes */
                0,
                2147483647,
                64 * 1024 * 1024);

            /* Borrowed for the call only: the module deep-copies what it needs, and
             * inventory_sync_server.h documents that contract, so this duplicate can be freed as
             * soon as start() returns. indexer_config is already populated by the time any module
             * thread runs -- wm_config() reads the configuration before main() creates them. */
            cJSON* indexer_json = indexer_config ? cJSON_Duplicate(indexer_config, TRUE) : cJSON_CreateObject();
            config.indexer = indexer_json;

            wm_inventory_sync_server_log_config(&config);
            inventory_sync_server_start_ptr(mtLoggingFunctionsWrapper, &config);
            cJSON_Delete(indexer_json);
        }
        else
        {
            mtwarn(WM_INVENTORY_SYNC_SERVER_LOGTAG, "Unable to start inventory_sync_server module.");
            return NULL;
        }
    }
    else
    {
        mtwarn(WM_INVENTORY_SYNC_SERVER_LOGTAG, "Unable to load inventory_sync_server module.");
        return NULL;
    }

    /* start() is non-blocking -- the module owns its own worker thread -- so this routine returns
     * and modulesd's thread for it exits immediately. Teardown goes through the .stop callback. */
    return NULL;
}

void wm_inventory_sync_server_destroy(wm_inventory_sync_server_t* data)
{
    free(data);
}

void wm_inventory_sync_server_stop(__attribute__((unused)) wm_inventory_sync_server_t* data)
{
    mtinfo(WM_INVENTORY_SYNC_SERVER_LOGTAG, "Module finished.");
    if (inventory_sync_server_stop_ptr)
    {
        inventory_sync_server_stop_ptr();
    }
    else
    {
        mtwarn(WM_INVENTORY_SYNC_SERVER_LOGTAG, "Unable to stop inventory_sync_server module.");
    }
}

wmodule* wm_inventory_sync_server_read()
{
    wmodule* module;

    os_calloc(1, sizeof(wmodule), module);
    module->context = &WM_INVENTORY_SYNC_SERVER_CONTEXT;
    module->tag = strdup(module->context->name);
    mtdebug1(WM_INVENTORY_SYNC_SERVER_LOGTAG, "Loaded Inventory sync server module.");
    return module;
}

cJSON* wm_inventory_sync_server_dump(__attribute__((unused)) wm_inventory_sync_server_t* data)
{
    cJSON* root = cJSON_CreateObject();

    return root;
}
