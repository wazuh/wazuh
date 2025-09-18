#ifndef _WINDEXER_CONNECTOR_HPP
#define _WINDEXER_CONNECTOR_HPP

#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <wiconnector/iwindexerconnector.hpp>

// Forward declaration
class IndexerConnectorAsync;

namespace wiconnector
{

using LogFunctionType =
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>;

struct Config
{
    std::vector<std::string> hosts; ///< The list of hosts to connect to. i.e. ["https://localhost:9200"]
    std::string username;           ///< The username to authenticate with OpenSearch, admin by default.
    std::string password;           ///< The password to authenticate with OpenSearch, admin by default.

    struct
    {
        std::vector<std::string> cacert; ///< Path to the CA bundle file. '/certificate_authorities'
        std::string cert;                ///< The certificate to connect to OpenSearch. '/certificate'
        std::string key;                 ///< The key to connect to OpenSearch.'/key'
    } ssl;                               ///< SSL options. '/ssl'

    std::string toJson() const;
};

/**
 * @brief Concrete implementation of the WIndexer connector interface.
 *
 * This class provides a thread-safe wrapper around an asynchronous indexer connector,
 * implementing the IWIndexerConnector interface to handle document indexing operations.
 * It manages the lifecycle of the underlying async connector and ensures thread safety
 * through a shared mutex.
 *
 * The connector supports initialization through either a Config object with logging
 * function or a JSON OSSEC configuration string. It provides indexing capabilities
 * and proper shutdown functionality.
 *
 */
class WIndexerConnector : public IWIndexerConnector
{

private:
    std::unique_ptr<IndexerConnectorAsync> m_indexerConnectorAsync;
    std::shared_mutex m_mutex;

public:
    WIndexerConnector() = delete;
    ~WIndexerConnector();

    /**
     * @brief Constructs a WIndexerConnector instance with the specified configuration and logging function.
     *
     * @param config The configuration object containing settings for the indexer connector
     * @param logFunction The logging function to be used for output and error reporting
     */
    WIndexerConnector(const Config&, const LogFunctionType& logFunction);

    /**
     * @brief Constructs a WIndexerConnector instance using a JSON OSSEC configuration string.
     *
     * @param jsonOssecConfig The JSON string containing the OSSEC configuration for the indexer connector
     */
    WIndexerConnector(std::string_view jsonOssecConfig);

    /**
     * @brief Indexes data into the specified index.
     *
     * @param index The name of the index where the data will be stored
     * @param data The data content to be indexed as a string view
     *
     * @throws std::invalid_argument If index name is empty or invalid
     */
    void index(std::string_view index, std::string_view data) override;

    /**
     * @brief Shuts down the indexer connector, releasing resources and stopping operations.
     *
     * This method ensures that the underlying asynchronous indexer connector is properly
     * shut down and that all associated resources are released.
     */
    void shutdown();
};
}; // namespace wiconnector

#endif // _WINDEXER_CONNECTOR_HPP
