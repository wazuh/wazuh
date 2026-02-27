#ifndef _IWINDEXER_CONNECTOR_HPP
#define _IWINDEXER_CONNECTOR_HPP

#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
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
     * @brief Retrieves the policy hash for the specified space.
     *
     * Queries the .cti-policies index to retrieve the SHA-256 hash stored in
     * the space.hash.sha256 field for the given space name.
     *
     * @param space The name of the space to retrieve the hash for
     * @return The SHA-256 hash as a string
     * @throws std::invalid_argument if the space name is empty
     * @throws IndexerConnectorException if the query returns zero or more than one result
     * @throws std::exception for other unexpected errors
     */
    virtual std::string getPolicyHash(std::string_view space) = 0;

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
     * @brief Retrieves the default IOC types handled by IOC sync.
     *
     * @return List of default IOC types
     */
    virtual std::vector<std::string> getDefaultIocTypes() = 0;

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
     * @param iocType IOC type (e.g. ipv4-addr, domain-name, url, file)
     * @param batchSize Number of documents requested per page
     * @param onIoc Callback invoked for each valid IOC record
     * @return Number of IOC documents delivered to the callback
     * @throws IndexerConnectorException if there is an indexer/query error
     */
    virtual std::size_t
    streamIocsByType(std::string_view iocType, std::size_t batchSize, const IocRecordCallback& onIoc) = 0;
};

} // namespace wiconnector
#endif // _IINDEXER_CONNECTOR_HPP
