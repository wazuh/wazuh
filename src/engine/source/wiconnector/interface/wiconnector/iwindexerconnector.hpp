#ifndef _IWINDEXER_CONNECTOR_HPP
#define _IWINDEXER_CONNECTOR_HPP

#include <functional>
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

/**
 * @brief Structure to hold policy resources retrieved from the indexer.
 *
 * This structure encapsulates the various components of a policy,
 * including KVDBs, decoders, integration decoders, and the policy itself.
 */
struct PolicyResources
{
    std::vector<json::Json> kvdbs {};       ///< List of KVDB
    std::vector<json::Json> decoders {};    ///< List of decoder
    std::vector<json::Json> integration {}; ///< List of integration decoder
    json::Json policy {};                   ///< The policy
};

class IWIndexerConnector
{

public:
    using IocRecordCallback = std::function<void(const std::string&, const std::string&)>;

    virtual ~IWIndexerConnector() = default;

    /**
     * @brief Indexes the given data into the specified index.
     *
     * @param index The name of the index where the data will be stored
     * @param data The data content to be indexed as a string view (JSON format)
     */
    virtual void index(std::string_view index, std::string_view data) = 0;

    /**
     * @brief Retrieves policy resources associated with the specified space.
     *
     * @param space The name of the space from which to retrieve policy resources
     * @return A PolicyResources structure containing the retrieved resources
     * @throws std::invalid_argument if the space name is empty or invalid
     * @throws IndexerConnectorException if there is an error during retrieval
     * @throws std::exception for other unexpected errors
     */
    virtual PolicyResources getPolicy(std::string_view space) = 0;

    /**
     * @brief Retrieves the policy hash and enabled status for the specified space.
     *
     * Queries the .cti-policies index to retrieve the SHA-256 hash stored in
     * the space.hash.sha256 field and the enabled status from document.enabled
     * for the given space name.
     *
     * @param space The name of the space to retrieve the information for
     * @return A pair containing the SHA-256 hash as a string and a boolean indicating if the policy is enabled
     * @throws std::invalid_argument if the space name is empty
     * @throws IndexerConnectorException if the query returns zero or more than one result, or if required fields are
     * missing
     * @throws std::exception for other unexpected errors
     */
    virtual std::pair<std::string, bool> getPolicyHashAndEnabled(std::string_view space) = 0;

    /**
     * @brief Checks if a policy exists for the specified space.
     *
     * Queries the .cti-policies index to determine if at least one policy
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
     * @brief Retrieves per-type IOC hashes from the IOC hashes manifest.
     *
     * Reads `__ioc_type_hashes__` from `.cti-iocs` and returns all available
     * `hash.sha256` values for the supported IOC types.
     *
     * @return Map(type -> sha256 hash)
     * @throws IndexerConnectorException if the manifest is missing or invalid
     */
    virtual std::unordered_map<std::string, std::string> getIocTypeHashes() = 0;

    /**
     * @brief Streams IOC documents for a specific IOC type.
     *
     * The connector handles query creation and pagination. For each valid
     * IOC record, it invokes `onIoc` with key (`document.name`) and serialized
     * value (`document` JSON).
     *
     * @param iocType IOC type (e.g. connection, url_domain, url_full, hash_md5, hash_sha1, hash_sha256)
     * @param batchSize Number of documents requested per page
     * @param onIoc Callback invoked for each valid IOC record
     * @return Number of IOC documents delivered to the callback
     * @throws IndexerConnectorException if there is an indexer/query error
     */
    virtual std::size_t
    streamIocsByType(std::string_view iocType, std::size_t batchSize, const IocRecordCallback& onIoc) = 0;

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
     * Returns the number of events pending to be sent to the indexer.
     * This includes events that were persisted from previous sessions.
     *
     * @return The number of events in the queue
     */
    virtual uint64_t getQueueSize() = 0;
};

} // namespace wiconnector
#endif // _IINDEXER_CONNECTOR_HPP
