#ifndef _IWINDEXER_CONNECTOR_HPP
#define _IWINDEXER_CONNECTOR_HPP

#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <base/json.hpp>

/**
 * @brief Interface for connecting to and indexing data in a wazuh-indexer.
 *
 * The IWIndexerConnector interface provides a contract for implementing
 * indexer connector classes that can send/recive data to wazuh-indexer.
 */
namespace wiconnector
{

/// @brief Consumer document ID for the standard ruleset in `.wazuh-cti-consumers`
constexpr std::string_view STANDARD_RULESET_CONSUMER_ID = "cti:catalog:consumer:ruleset";

/// @brief Consumer document ID for the IOC enrichment data in `.wazuh-cti-consumers`
constexpr std::string_view IOC_ENRICHMENT_CONSUMER_ID = "cti:catalog:consumer:iocs";

class IWIndexerConnector
{

public:
    virtual ~IWIndexerConnector() = default;

    /**
     * @brief Indexes the given data into the specified index.
     *
     * @param index The name of the index where the data will be stored
     * @param data The data content to be indexed as a string view (JSON format)
     */
    virtual void index(std::string_view index, std::string_view data) = 0;

    /**
     * @brief Checks if a policy exists for the specified space.
     *
     * Queries the wazuh-threatintel-policies index to determine if at least one policy
     * exists for the given space name.
     *
     * @param space The name of the space to check
     * @return true if at least one policy exists, false otherwise
     * @throws std::invalid_argument if the space name is empty
     * @throws IndexerConnectorException if there is an error during the query
     */
    virtual bool existsPolicy(std::string_view space) = 0;

    /**
     * @brief Checks if IOC index data is available in the indexer.
     *
     * @return true if IOC index is available, false otherwise
     */
    virtual bool existsIocDataIndex() = 0;

    /**
     * @brief Pre-flight check: is the consumer ready for synchronization?
     *
     * Queries `.wazuh-cti-consumers` for the specified consumer document and verifies
     * two conditions:
     *   1. `status` == `"ready"` — the indexer is not actively updating data.
     *   2. `local_offset` != 0 — the consumer has received at least one CTI update,
     *      so hash/data documents actually exist in the data indices.
     *
     * This is a lightweight, non-PIT check intended to be called **before** requesting
     * hashes or data, to avoid unnecessary network calls when the consumer has no data yet.
     *
     * @param consumerId The `_id` of the consumer document (e.g. `STANDARD_RULESET_CONSUMER_ID`).
     * @return true if the consumer is ready and has a non-zero local_offset; false otherwise
     *         (including on any error — safe default to skip sync).
     */
    virtual bool isConsumerReadyForSync(std::string_view consumerId) = 0;

    /**
     * @brief Retrieves remote engine runtime configuration from wazuh-indexer.
     *
     * Queries `.wazuh-settings` with `size=1`, requests only the `engine` section,
     * and returns the normalized engine settings object, for example:
     * { "index_raw_events": false }
     *
     * @return json::Json Engine settings object.
     * @throws std::exception on transport, not-found, or payload validation errors.
     */
    virtual json::Json getEngineRemoteConfig() = 0;

    /**
     * @brief Gets the current size of the indexer queue.
     *
     * Returns the number of bytes pending to be sent to the indexer.
     *
     * @return The number of bytes in the queue
     */
    virtual uint64_t getQueueSize() = 0;

    /**
     * @brief Gets the number of events dropped by the indexer.
     *
     * Returns the number of events that were dropped and not sent to the indexer.
     *
     * @return The number of dropped events
     */
    virtual uint64_t getDroppedEvents() = 0;
};

} // namespace wiconnector
#endif // _IINDEXER_CONNECTOR_HPP
