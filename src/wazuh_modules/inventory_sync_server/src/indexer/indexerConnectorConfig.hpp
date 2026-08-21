/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 29, 2026.
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
     * One builder per receiver, and each emits ONLY the keys its own receiver actually reads.
     *
     * IndexerConnectorSync reads `max_bulk_size`; IndexerConnectorAsync reads `bulk_max_bytes` for the
     * same concept. Neither validates the other's key -- an unknown key is ignored silently, with no
     * throw and no log, and the built-in default applies instead. A single builder emitting both would
     * hand each connector one key it uses and one it quietly discards, which is indistinguishable from
     * a typo. Emitting only the receiving connector's keys makes "wrong key name" structurally
     * impossible, and the "does NOT contain the other's keys" unit tests keep it that way.
     *
     * Both mirror the module's convention for config-building free functions (see
     * http_server/udsHttpServerConfig.hpp's buildServerConfig()) rather than being facade methods, so
     * they can be tested in isolation without a running server.
     */

    /**
     * @brief Overlays the SYNC connector's tunables onto the raw <indexer> block.
     *
     * Emits `max_bulk_size`, `flush_interval_seconds`, `max_retry_delay_seconds` and
     * `request_timeout_seconds` -- the four keys IndexerConnectorSync reads. `hosts` and `ssl.*`
     * pass through untouched.
     *
     * @param indexerConfig The raw <indexer> block (unmodified; the return value is a copy).
     * @param config The module's C-ABI configuration; only the `indexer_sync_*` fields are read.
     * @return The config ready to hand to IndexerConnectorSync's constructor.
     */
    nlohmann::json buildSyncConnectorConfig(const nlohmann::json& indexerConfig,
                                            const inventory_sync_server_config_t& config);

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
     * `ssl.*`, which pass through untouched. Session-level and NOT emitted by the two connector
     * builders above: in session mode the connectors adopt the session's already-built monitor, so
     * the key would be dead weight in their configs.
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
