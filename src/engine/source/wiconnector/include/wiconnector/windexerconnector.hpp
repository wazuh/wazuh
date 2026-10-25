// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _WINDEXER_CONNECTOR_HPP
#define _WINDEXER_CONNECTOR_HPP

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <indexer_client/client.hpp>
#include <wiconnector/iindexerConnectorAsync.hpp>
#include <wiconnector/iwindexerconnector.hpp>

namespace wiconnector
{

using LogFunctionType =
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>;

struct Config
{
    std::vector<std::string> hosts;   ///< The list of hosts to connect to. i.e. ["https://localhost:9200"]
    size_t maxQueueBytes {0};         ///< Maximum bytes in the indexer queue. 0 means unlimited.
    size_t maxRetryDelaySeconds {15}; ///< Maximum delay in seconds for indexer retry backoff.

    struct
    {
        std::vector<std::string> cacert; ///< Path to the CA bundle file. '/certificate_authorities'
        std::string cert;                ///< The certificate to connect to OpenSearch. '/certificate'
        std::string key;                 ///< The key to connect to OpenSearch.'/key'
    } ssl;                               ///< SSL options. '/ssl'

    std::string toJson() const;
};

/**
 * @brief Build the Engine's indexer connector from a JSON OSSEC configuration string.
 *
 * The one place it is built, so the instance shared by @ref WIndexerConnector and the content
 * registrations is configured exactly as the JSON constructor configures its own.
 *
 * @param jsonOssecConfig The JSON string containing the OSSEC configuration for the indexer connector
 * @return The connector.
 * @throws std::runtime_error if the JSON configuration is invalid or empty
 */
std::shared_ptr<IndexerConnectorAsync> makeIndexerConnectorAsync(std::string_view jsonOssecConfig);

/**
 * @brief Thread-safe wrapper around the asynchronous indexer connector.
 *
 * Implements IWIndexerConnector over an IIndexerConnectorAsync, guarding its lifecycle with a shared
 * mutex so @ref shutdown can release it while other threads are indexing.
 */
class WIndexerConnector : public IWIndexerConnector
{

private:
    std::unique_ptr<IIndexerConnectorAsync> m_indexerConnectorAsync;
    /// The engine's Client for the reads (E10a); null with the v1-only constructors.
    std::shared_ptr<indexer_client::IClient> m_reader;
    std::chrono::milliseconds m_requestTimeout {60000};
    std::shared_mutex m_mutex;

public:
    WIndexerConnector() = delete;
    ~WIndexerConnector();

    /**
     * @brief Constructs a WIndexerConnector instance with the specified configuration and logging function.
     *
     * @param config The configuration object containing settings for the indexer connector
     * @param logFunction The logging function to be used for output and error reporting
     * @throws std::runtime_error if the configuration is invalid or if the indexer connector fails to initialize
     */
    WIndexerConnector(const Config&, const LogFunctionType& logFunction);

    /**
     * @brief Constructs a WIndexerConnector instance using a JSON OSSEC configuration string.
     *
     * @param jsonOssecConfig The JSON string containing the OSSEC configuration for the indexer connector
     * @throws std::runtime_error if the JSON configuration is invalid or empty
     */
    explicit WIndexerConnector(std::string_view jsonOssecConfig);

    /**
     * @brief Constructs a WIndexerConnector over a connector the caller already built.
     *
     * The Engine builds one connector (@ref makeIndexerConnectorAsync) and shares it between this
     * class and the content registrations, so the process runs one health monitor and reports an
     * indexer outage once (D1 of the content manager). @ref shutdown releases this class's
     * reference only; the connector is destroyed when its last holder lets go.
     *
     * @param connector The shared connector. Must not be null.
     * @throws std::runtime_error if @p connector is null
     */
    explicit WIndexerConnector(std::shared_ptr<IndexerConnectorAsync> connector);

    /**
     * @brief Writes through the v1 connector, reads through the engine's indexer_client Client (E10a, I184).
     *
     * getEngineRemoteConfig() searches `.wazuh-settings` with the Client's query interface: one attempt, a page
     * deadline of the runtime's request timeout, and an immediate failure when every node was probed and none is
     * usable (I190, I190b); ClientClosed and every other failure throw, as the v1 did. @ref shutdown releases both.
     *
     * @param connector The shared v1 connector for index(). Must not be null.
     * @param reader The engine's Client. Must not be null.
     * @param requestTimeout The runtime's `request_timeout_ms` (RuntimeConfig::requestTimeout).
     * @throws std::runtime_error if @p connector or @p reader is null
     */
    WIndexerConnector(std::shared_ptr<IndexerConnectorAsync> connector,
                      std::shared_ptr<indexer_client::IClient> reader,
                      std::chrono::milliseconds requestTimeout);

    /**
     * @brief Test-only constructor: a custom IIndexerConnectorAsync for the writes and a Client for the reads.
     */
    WIndexerConnector(std::unique_ptr<IIndexerConnectorAsync> async,
                      std::shared_ptr<indexer_client::IClient> reader,
                      std::chrono::milliseconds requestTimeout);

    /**
     * @brief Test-only constructor: inject a custom IIndexerConnectorAsync (e.g. a gMock).
     *
     * @param async Owned implementation of IIndexerConnectorAsync used for every backend call.
     */
    explicit WIndexerConnector(std::unique_ptr<IIndexerConnectorAsync> async);

    /**
     * @copydoc IWIndexerConnector::index
     */
    void index(std::string_view index, std::string_view data) override;

    /**
     * @copydoc IWIndexerConnector::getEngineRemoteConfig
     */
    json::Json getEngineRemoteConfig() override;

    /**
     * @copydoc IWIndexerConnector::getQueueSize
     */
    uint64_t getQueueSize() override;

    /**
     * @copydoc IWIndexerConnector::getDroppedEvents
     */
    uint64_t getDroppedEvents() override;

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
