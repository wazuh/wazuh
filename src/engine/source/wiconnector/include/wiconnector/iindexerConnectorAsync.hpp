#ifndef WI_IINDEXER_CONNECTOR_ASYNC_HPP
#define WI_IINDEXER_CONNECTOR_ASYNC_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <indexerConnector.hpp>
#include <json.hpp>

namespace wiconnector
{

/**
 * @brief Thin interface that mirrors the subset of IndexerConnectorAsync used by WIndexerConnector.
 *
 * Exists exclusively for testing purpose
 */
class IIndexerConnectorAsync
{
public:
    virtual ~IIndexerConnectorAsync() = default;

    virtual void indexDataStream(std::string_view index, std::string_view data) = 0;

    virtual uint64_t getQueueSize() const = 0;
    virtual uint64_t getDroppedEvents() const = 0;

    virtual PointInTime
    createPointInTime(const std::vector<std::string>& indices, std::string_view keepAlive, bool expandWildcards) = 0;
    virtual void deletePointInTime(const PointInTime& pit) = 0;

    virtual nlohmann::json search(const PointInTime& pit,
                                  std::size_t size,
                                  const nlohmann::json& query,
                                  const nlohmann::json& sort,
                                  const std::optional<nlohmann::json>& searchAfter = std::nullopt,
                                  const std::optional<nlohmann::json>& source = std::nullopt) = 0;

    virtual nlohmann::json search(std::string_view index,
                                  std::size_t size,
                                  const nlohmann::json& query,
                                  const std::optional<nlohmann::json>& source = std::nullopt) = 0;
};

} // namespace wiconnector

#endif // WI_IINDEXER_CONNECTOR_ASYNC_HPP
