#ifndef _WQUICKWIT_CONNECTOR_HPP
#define _WQUICKWIT_CONNECTOR_HPP

#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <wiconnector/iwindexerconnector.hpp>

// Forward declaration
class QuickwitConnectorAsync;

namespace wiconnector
{

using LogFunctionType =
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>;

struct QuickwitConfig
{
    std::vector<std::string> hosts; ///< The list of Quickwit hosts. i.e. ["http://localhost:7280"]
    std::string username;           ///< Username for authentication (optional).
    std::string password;           ///< Password for authentication (optional).

    struct
    {
        std::vector<std::string> cacert; ///< Path to the CA bundle file. '/certificate_authorities'
        std::string cert;                ///< The certificate to connect to Quickwit. '/certificate'
        std::string key;                 ///< The key to connect to Quickwit.'/key'
    } ssl;                               ///< SSL options. '/ssl'

    std::string toJson() const;
};

/**
 * @brief Concrete implementation of the WIndexer connector interface for Quickwit.
 *
 * This class provides a thread-safe wrapper around an asynchronous Quickwit connector,
 * implementing the IWIndexerConnector interface to handle document indexing operations
 * for Quickwit, a cloud-native search engine optimized for logs and traces.
 *
 * The connector supports initialization through either a QuickwitConfig object with logging
 * function or a JSON OSSEC configuration string. It provides indexing capabilities
 * and proper shutdown functionality.
 *
 */
class WQuickwitConnector : public IWIndexerConnector
{

private:
    std::unique_ptr<QuickwitConnectorAsync> m_quickwitConnectorAsync;
    std::shared_mutex m_mutex;

public:
    WQuickwitConnector() = delete;
    ~WQuickwitConnector();

    /**
     * @brief Constructs a WQuickwitConnector instance with the specified configuration and logging function.
     *
     * @param config The configuration object containing settings for the Quickwit connector
     * @param logFunction The logging function to be used for output and error reporting
     */
    WQuickwitConnector(const QuickwitConfig& config, const LogFunctionType& logFunction);

    /**
     * @brief Constructs a WQuickwitConnector instance using a JSON OSSEC configuration string.
     *
     * @param jsonOssecConfig The JSON string containing the OSSEC configuration for the Quickwit connector
     */
    WQuickwitConnector(std::string_view jsonOssecConfig);

    /**
     * @brief Indexes data into the specified Quickwit index.
     *
     * @param index The name of the index where the data will be stored
     * @param data The data content to be indexed as a string view (JSON format)
     *
     * @throws std::invalid_argument If index name is empty or invalid
     */
    void index(std::string_view index, std::string_view data) override;

    /**
     * @brief Shuts down the Quickwit connector, releasing resources and stopping operations.
     *
     * This method ensures that the underlying asynchronous Quickwit connector is properly
     * shut down and that all associated resources are released.
     */
    void shutdown();
};
}; // namespace wiconnector

#endif // _WQUICKWIT_CONNECTOR_HPP
