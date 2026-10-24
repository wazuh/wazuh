/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_INDEXER_CONNECTOR_CONFIG_HPP
#define _INVSYNC_INDEXER_CONNECTOR_CONFIG_HPP

#include "inventory_sync_server.h"

#include <json.hpp>

namespace invsync::indexer
{

    /*
     * One builder per indexer_connector (v1) receiver, and each emits ONLY the keys its own receiver
     * actually reads: an unknown key is ignored silently, with no throw and no log, and the built-in
     * default applies instead, so a key meant for another receiver is indistinguishable from a typo.
     * The "does NOT contain the other's keys" unit tests keep it that way.
     *
     * The sync half has no overlay any more: it runs on indexer_client, whose `inventory` bucket is
     * built from the `indexer_sync_*` fields by inventoryBucketSpec() (indexerClientSyncAdapter.hpp).
     *
     * Both mirror the module's convention for config-building free functions (see
     * http_server/udsHttpServerConfig.hpp's buildServerConfig()) rather than being facade methods, so
     * they can be tested in isolation without a running server.
     */

    /**
     * @brief Overlays the ASYNC connector's tunables onto the raw <indexer> block.
     *
     * Emits `bulk_max_bytes`, `flush_interval_seconds`, `max_retry_delay_seconds`, `max_queue_bytes`,
     * `logger_queue_size`, `logger_threads` and `request_timeout_seconds` -- the seven keys
     * IndexerConnectorAsync reads. `hosts` and `ssl.*` pass through untouched.
     *
     * @param indexerConfig The raw <indexer> block (unmodified; the return value is a copy).
     * @param config The module's C-ABI configuration; only the `indexer_async_*` fields are read.
     * @return The config ready to hand to IndexerConnectorAsync's constructor.
     */
    nlohmann::json buildAsyncConnectorConfig(const nlohmann::json& indexerConfig,
                                             const inventory_sync_server_config_t& config);

    /**
     * @brief Overlays the SHARED SESSION's tunables onto the raw <indexer> block.
     *
     * Emits `monitoring_interval_seconds` -- the one key IndexerSession reads beyond `hosts` and
     * `ssl.*`, which pass through untouched. Session-level and NOT emitted by the async connector
     * builder above: in session mode the connector adopts the session's already-built monitor, so
     * the key would be dead weight in its config.
     *
     * @param indexerConfig The raw <indexer> block (unmodified; the return value is a copy).
     * @param config The module's C-ABI configuration; only `indexer_monitoring_interval_seconds` is
     *               read.
     * @return The config ready to hand to IndexerSession's constructor.
     */
    nlohmann::json buildSessionConfig(const nlohmann::json& indexerConfig,
                                      const inventory_sync_server_config_t& config);

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_CONNECTOR_CONFIG_HPP
