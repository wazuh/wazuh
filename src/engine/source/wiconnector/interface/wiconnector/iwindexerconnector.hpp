#ifndef _IWINDEXER_CONNECTOR_HPP
#define _IWINDEXER_CONNECTOR_HPP

#include <string>
#include <string_view>
#include <vector>

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
 * All resources are stored as strings.
 */
struct PolicyResources
{
    std::vector<std::string> kvdbs;       ///< List of KVDB
    std::vector<std::string> decoders;    ///< List of decoder
    std::vector<std::string> integration; ///< List of integration decoder
    std::string policy;                   ///< The policy
};

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
     * @brief Retrieves policy resources associated with the specified space.
     *
     * @param space The name of the space from which to retrieve policy resources
     * @return A PolicyResources structure containing the retrieved resources
     * @throws std::invalid_argument if the space name is empty or invalid
     * @throws IndexerConnectorException if there is an error during retrieval
     * @throws std::exception for other unexpected errors
     */
    virtual PolicyResources getPolicy(std::string_view space) = 0;
};

} // namespace wiconnector
#endif // _IINDEXER_CONNECTOR_HPP
