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

#ifndef _INVSYNC_INDEXER_CONNECTOR_ADAPTER_HPP
#define _INVSYNC_INDEXER_CONNECTOR_ADAPTER_HPP

#include "IIndexerConnector.hpp"

#include <indexerConnector.hpp>

#include <json.hpp>
#include <utility>

namespace invsync::indexer
{

    /**
     * @brief Wraps the real `IndexerConnectorSync` behind IIndexerConnector.
     *
     * Deliberately `IndexerConnectorSync`, not `IndexerConnectorAsync`: this is the same connector
     * class the older `inventory_sync` module uses, and the whole point of this module is to
     * eventually replace it -- reusing its class means reusing its config keys (`max_bulk_size`,
     * `flush_interval_seconds`) and its richer write/lock API (`bulkIndex`, `bulkDelete`,
     * `scopeLock`, `flush`, `registerNotify`), which the real sync pipeline will need once it lands.
     *
     * Only `isAvailable()` is forwarded today; nothing else is called yet. `m_inner` is held by
     * value in the member-init-list, so a constructor failure (bad host config, missing CA file, an
     * unreasonable `max_retry_delay_seconds`) throws out of THIS constructor too -- which is exactly
     * the signal the facade's startup gate is built on.
     */
    class IndexerConnectorAdapter final : public IIndexerConnector
    {
    public:
        IndexerConnectorAdapter(const nlohmann::json& config, LoggingContext logging)
            : m_inner {config, std::move(logging)}
        {
        }

        bool isAvailable() const override
        {
            return m_inner.isAvailable();
        }

    private:
        IndexerConnectorSync m_inner;
    };

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_CONNECTOR_ADAPTER_HPP
