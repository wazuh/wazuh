// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef WI_INDEXER_CONNECTOR_ASYNC_ADAPTER_HPP
#define WI_INDEXER_CONNECTOR_ASYNC_ADAPTER_HPP

#include <memory>
#include <utility>

#include <indexerConnector.hpp>

#include <wiconnector/iindexerConnectorAsync.hpp>

namespace wiconnector
{

/**
 * @brief Production implementation of IIndexerConnectorAsync that forwards every call to
 *        an IndexerConnectorAsync instance.
 *
 * Holds it shared: the Engine runs one connector, which the content registrations use too (D1 of the
 * content manager).
 */
class IndexerConnectorAsyncAdapter final : public IIndexerConnectorAsync
{
private:
    std::shared_ptr<IndexerConnectorAsync> m_inner;

public:
    explicit IndexerConnectorAsyncAdapter(std::shared_ptr<IndexerConnectorAsync> inner)
        : m_inner(std::move(inner))
    {
    }

    void indexDataStream(std::string_view index, std::string_view data) override
    {
        m_inner->indexDataStream(index, data);
    }

    uint64_t getQueueSize() const override { return m_inner->getQueueSize(); }
    uint64_t getDroppedEvents() const override { return m_inner->getDroppedEvents(); }

    nlohmann::json search(std::string_view index,
                          std::size_t size,
                          const nlohmann::json& query,
                          const std::optional<nlohmann::json>& source = std::nullopt) override
    {
        return m_inner->search(index, size, query, source);
    }
};

} // namespace wiconnector

#endif // WI_INDEXER_CONNECTOR_ASYNC_ADAPTER_HPP
