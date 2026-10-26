// SPDX-License-Identifier: AGPL-3.0-or-later
// Frozen copy of the write half of src/engine/source/wiconnector/src/windexerconnector.cpp at 163d95c9ac (see the
// header). Kept in its own translation unit, as the production wrapper was, so that nothing inlines across it.
#include "frozenV1Connector.hpp"

#include <mutex>
#include <stdexcept>

#include <base/logging.hpp>

namespace stagebench::frozenv1
{

FrozenV1Connector::FrozenV1Connector(std::shared_ptr<IndexerConnectorAsync> connector)
{
    if (!connector)
    {
        throw std::runtime_error("IndexerConnectorAsync instance cannot be null");
    }
    m_indexerConnectorAsync = std::make_unique<IndexerConnectorAsyncAdapter>(std::move(connector));
}

FrozenV1Connector::~FrozenV1Connector() = default;

void FrozenV1Connector::shutdown()
{
    LOG_INFO("[indexer-connector] Shutdown initiated");
    std::unique_lock lock(m_mutex);
    m_indexerConnectorAsync.reset();
}

uint64_t FrozenV1Connector::getQueueSize()
{
    std::shared_lock lock(m_mutex);
    if (!m_indexerConnectorAsync)
    {
        return 0;
    }
    return m_indexerConnectorAsync->getQueueSize();
}

uint64_t FrozenV1Connector::getDroppedEvents()
{
    std::shared_lock lock(m_mutex);
    if (!m_indexerConnectorAsync)
    {
        return 0;
    }
    return m_indexerConnectorAsync->getDroppedEvents();
}

double FrozenV1Connector::getQueueUsagePercent()
{
    return 0.0;
}

// 163d95c9ac: void WIndexerConnector::index(std::string_view index, std::string_view data), same body.
void FrozenV1Connector::index(std::string index, std::string data)
{
    std::shared_lock lock(m_mutex);
    if (m_indexerConnectorAsync)
    {
        try
        {
            m_indexerConnectorAsync->indexDataStream(index, data);
        }
        catch (const IndexerConnectorException& e)
        {
            LOG_WARNING("[indexer-connector] Error indexing data: %s", e.what());
            return;
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("[indexer-connector] Error indexing data: %s", e.what());
            return;
        }
    }
    else
    {
        LOG_DEBUG("[indexer-connector] IndexerConnectorAsync shutdown, cannot index data");
    }
}

json::Json FrozenV1Connector::getEngineRemoteConfig()
{
    throw std::runtime_error("not part of the stage benchmark");
}

} // namespace stagebench::frozenv1
