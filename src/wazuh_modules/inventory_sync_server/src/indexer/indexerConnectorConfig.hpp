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

    /**
     * @brief Overlays this module's two indexer tunables onto the raw <indexer> block.
     *
     * Mirrors the module's own convention for config-building free functions (see
     * http_server/udsHttpServerConfig.hpp's buildServerConfig()) rather than a facade method, so it
     * can be tested in isolation without a running server.
     *
     * `indexer_bulk_size_bytes` -> `max_bulk_size`, `indexer_flush_interval` ->
     * `flush_interval_seconds` -- the same two keys `inventory_sync` overlays onto its own
     * IndexerConnectorSync config (both modules use the same connector class). Values `<=0` leave
     * the key untouched, so the connector's own built-in default applies.
     *
     * @param indexerConfig The raw <indexer> block (unmodified; the return value is a copy).
     * @param config The module's C-ABI configuration, read only for the two tunables above.
     * @return The config ready to hand to IndexerConnectorSync's constructor.
     */
    nlohmann::json buildConnectorConfig(const nlohmann::json& indexerConfig,
                                        const inventory_sync_server_config_t& config);

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_CONNECTOR_CONFIG_HPP
