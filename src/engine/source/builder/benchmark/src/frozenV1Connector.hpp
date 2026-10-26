// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _BUILDER_BENCHMARK_FROZEN_V1_CONNECTOR_HPP
#define _BUILDER_BENCHMARK_FROZEN_V1_CONNECTOR_HPP

// Side A of the stage benchmark (plan 18, E10b, I198): a frozen copy of the engine's v1 write path as it was at
// 163d95c9ac — WIndexerConnector over IndexerConnectorAsyncAdapter over IndexerConnectorAsync
// (src/engine/source/wiconnector/{src/windexerconnector.cpp, src/indexerConnectorAsyncAdapter.hpp,
// include/wiconnector/iindexerConnectorAsync.hpp}). Only the write half is kept: the reads went to indexer_client in
// E10a and are not measured. The one change is the signature of index(), which takes the strings by value to implement
// today's IWIndexerConnector (the body is then handed on as a view, as before). Never edit it to follow the
// production wrapper: it is the baseline.

#include <cstdint>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <utility>

#include <indexerConnector.hpp>
#include <json.hpp>

#include <wiconnector/iwindexerconnector.hpp>

namespace stagebench::frozenv1
{

/// Copy of wiconnector::IIndexerConnectorAsync at 163d95c9ac.
class IIndexerConnectorAsync
{
public:
    virtual ~IIndexerConnectorAsync() = default;

    virtual void indexDataStream(std::string_view index, std::string_view data) = 0;

    virtual uint64_t getQueueSize() const = 0;
    virtual uint64_t getDroppedEvents() const = 0;

    virtual nlohmann::json search(std::string_view index,
                                  std::size_t size,
                                  const nlohmann::json& query,
                                  const std::optional<nlohmann::json>& source = std::nullopt) = 0;
};

/// Copy of wiconnector::IndexerConnectorAsyncAdapter at 163d95c9ac.
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

/// The write half of wiconnector::WIndexerConnector at 163d95c9ac (constructor from a shared IndexerConnectorAsync).
class FrozenV1Connector final : public wiconnector::IWIndexerConnector
{
public:
    explicit FrozenV1Connector(std::shared_ptr<IndexerConnectorAsync> connector);
    ~FrozenV1Connector() override;

    void shutdown();
    void index(std::string index, std::string data) override;
    json::Json getEngineRemoteConfig() override;
    uint64_t getQueueSize() override;
    uint64_t getDroppedEvents() override;
    /// The v1 had no such metric: always 0.
    double getQueueUsagePercent() override;

private:
    std::shared_mutex m_mutex;
    std::unique_ptr<IIndexerConnectorAsync> m_indexerConnectorAsync;
};

} // namespace stagebench::frozenv1

#endif // _BUILDER_BENCHMARK_FROZEN_V1_CONNECTOR_HPP
