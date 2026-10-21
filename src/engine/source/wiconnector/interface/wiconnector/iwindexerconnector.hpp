// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _IWINDEXER_CONNECTOR_HPP
#define _IWINDEXER_CONNECTOR_HPP

#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <base/json.hpp>

namespace wiconnector
{

/**
 * @brief The Engine's write path to the wazuh-indexer, and its one settings read.
 *
 * Content downloads (rulesets, IOCs) do not go through here: they use the same connector through
 * the content manager (cmcontent).
 */
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
#endif // _IWINDEXER_CONNECTOR_HPP
