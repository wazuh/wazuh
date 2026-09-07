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

#include <cstddef>

namespace invsync::indexer
{
    namespace
    {
        /**
         * @brief The ONLY way this file writes a numeric key. Do not assign to `target[key]` directly.
         *
         * `value` is taken signed because every numeric field of the C-ABI is `int` or `long long`, so
         * the sentinel test happens BEFORE the widening -- a negative must mean "no opinion", not
         * SIZE_MAX. What gets stored is always a `std::size_t`, i.e. always an unsigned JSON number.
         *
         * That single cast is load-bearing. IndexerConnectorAsync gates `max_queue_bytes` on
         * `is_number_unsigned()`, unlike every other key, which uses `is_number_integer()`. A SIGNED
         * JSON integer there is IGNORED SILENTLY -- no throw, no log, the queue simply stays unbounded.
         * Funnelling every numeric write through here means that trap cannot be reintroduced one key
         * at a time. `EveryOverlaidNumericKeyIsAnUnsignedJsonNumber` pins it.
         *
         * @param target Object to write into.
         * @param key Connector key name.
         * @param value Value from the C-ABI config; `<=0` leaves the key absent so the connector's own
         *              default applies.
         */
        void setIfPositive(nlohmann::json& target, const char* key, long long value)
        {
            if (value > 0)
            {
                target[key] = static_cast<std::size_t>(value);
            }
        }

        /**
         * @brief Writes a numeric key including 0, for the keys whose 0 is a real setting rather
         * than "no opinion".
         *
         * setIfPositive() drops a 0 so the connector's own default applies. The retry-budget bounds
         * instead read 0 as "disable this bound", so a dropped 0 would silently restore the default
         * cap rather than remove it. Those keys funnel through here so their 0 reaches the connector
         * verbatim. The cast to `std::size_t` is the same load-bearing widening setIfPositive() pins.
         *
         * @param target Object to write into.
         * @param key Connector key name.
         * @param value Value from the C-ABI config; `<0` leaves the key absent so the connector's
         *              own default applies.
         */
        void setIfNonNegative(nlohmann::json& target, const char* key, long long value)
        {
            if (value >= 0)
            {
                target[key] = static_cast<std::size_t>(value);
            }
        }
    } // namespace

    nlohmann::json buildSyncConnectorConfig(const nlohmann::json& indexerConfig,
                                            const inventory_sync_server_config_t& config)
    {
        nlohmann::json result = indexerConfig;

        // NOT indexer_sync_max_bulk_size: that option is the ingestion pipeline's group-commit
        // threshold and stays out of the connector, whose own request cap this key is.
        setIfPositive(result, "max_bulk_size", config.indexer_sync_connector_max_bulk_size);
        setIfPositive(result, "flush_interval_seconds", config.indexer_sync_flush_interval_seconds);
        setIfPositive(result, "max_retry_delay_seconds", config.indexer_sync_max_retry_delay_seconds);
        setIfPositive(result, "request_timeout_seconds", config.indexer_sync_request_timeout_seconds);
        setIfNonNegative(result, "max_retry_attempts", config.indexer_sync_max_retry_attempts);
        setIfNonNegative(result, "max_retry_duration_seconds", config.indexer_sync_max_retry_duration_seconds);

        return result;
    }

    nlohmann::json buildAsyncConnectorConfig(const nlohmann::json& indexerConfig,
                                             const inventory_sync_server_config_t& config)
    {
        nlohmann::json result = indexerConfig;

        setIfPositive(result, "bulk_max_bytes", config.indexer_async_bulk_max_bytes);
        setIfPositive(result, "flush_interval_seconds", config.indexer_async_flush_interval_seconds);
        setIfPositive(result, "max_retry_delay_seconds", config.indexer_async_max_retry_delay_seconds);
        setIfPositive(result, "max_queue_bytes", config.indexer_async_max_queue_bytes);
        setIfPositive(result, "logger_queue_size", config.indexer_async_logger_queue_size);
        setIfPositive(result, "logger_threads", config.indexer_async_logger_threads);
        setIfPositive(result, "request_timeout_seconds", config.indexer_async_request_timeout_seconds);

        return result;
    }

    nlohmann::json buildSessionConfig(const nlohmann::json& indexerConfig, const inventory_sync_server_config_t& config)
    {
        nlohmann::json result = indexerConfig;

        setIfPositive(result, "monitoring_interval_seconds", config.indexer_monitoring_interval_seconds);

        return result;
    }

} // namespace invsync::indexer
