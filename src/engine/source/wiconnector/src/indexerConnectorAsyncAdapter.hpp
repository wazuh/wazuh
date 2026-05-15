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
 *        an owned IndexerConnectorAsync instance.
 */
class IndexerConnectorAsyncAdapter final : public IIndexerConnectorAsync
{
private:
    std::unique_ptr<IndexerConnectorAsync> m_inner;

public:
    explicit IndexerConnectorAsyncAdapter(std::unique_ptr<IndexerConnectorAsync> inner)
        : m_inner(std::move(inner))
    {
    }

    void indexDataStream(std::string_view index, std::string_view data) override
    {
        m_inner->indexDataStream(index, data);
    }

    uint64_t getQueueSize() const override { return m_inner->getQueueSize(); }
    uint64_t getDroppedEvents() const override { return m_inner->getDroppedEvents(); }

    PointInTime createPointInTime(const std::vector<std::string>& indices,
                                  std::string_view keepAlive,
                                  bool expandWildcards) override
    {
        return m_inner->createPointInTime(indices, keepAlive, expandWildcards);
    }

    void deletePointInTime(const PointInTime& pit) override { m_inner->deletePointInTime(pit); }

    nlohmann::json search(const PointInTime& pit,
                          std::size_t size,
                          const nlohmann::json& query,
                          const nlohmann::json& sort,
                          const std::optional<nlohmann::json>& searchAfter = std::nullopt,
                          const std::optional<nlohmann::json>& source = std::nullopt) override
    {
        return m_inner->search(pit, size, query, sort, searchAfter, source);
    }

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
