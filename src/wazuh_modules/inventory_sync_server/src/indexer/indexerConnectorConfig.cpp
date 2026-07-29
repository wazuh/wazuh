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

#include "indexerConnectorConfig.hpp"

namespace invsync::indexer
{

    nlohmann::json buildConnectorConfig(const nlohmann::json& indexerConfig,
                                        const inventory_sync_server_config_t& config)
    {
        nlohmann::json result = indexerConfig;

        if (config.indexer_bulk_size_bytes > 0)
        {
            result["max_bulk_size"] = static_cast<std::size_t>(config.indexer_bulk_size_bytes);
        }
        if (config.indexer_flush_interval > 0)
        {
            result["flush_interval_seconds"] = static_cast<std::size_t>(config.indexer_flush_interval);
        }

        return result;
    }

} // namespace invsync::indexer
