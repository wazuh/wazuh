#ifndef _CTI_STORE_CONTENT_DOWNLOADER_HPP
#define _CTI_STORE_CONTENT_DOWNLOADER_HPP

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include <base/json.hpp>
#include <base/logging.hpp>
#include <external/nlohmann/json.hpp>

// Forward declaration of global ContentRegister (defined in shared_modules/content_manager)
class ContentRegister;

namespace cti::store
{

/**
 * @brief Result of file processing
 * tuple<offset, hash, status>
 */
using FileProcessingResult = std::tuple<int, std::string, bool>;

/**
 * @brief Callback for processing files
 */
using FileProcessingCallback = std::function<FileProcessingResult(const std::string& message)>;

/**
 * @brief Configuration structure for Content Manager
 */
struct ContentManagerConfig
{
    std::string topicName {"engine_cti_store"};
    int interval {3600}; // seconds
    bool onDemand {false};
    std::string basePath {};

    // Config data
    std::string consumerName {"Wazuh Engine"};
    std::string contentSource {"cti-offset"};
    std::string compressionType {"raw"};
    std::string versionedContent {"cti-api"};
    bool deleteDownloadedContent {true};
    std::string url {"https://cti-pre.wazuh.com/api/v1/catalog/contexts/decoders_test_5.0/consumers/decoders_test_5.0"};
    std::string outputFolder {"content"};
    std::string contentFileName {"api_file.json"};
    std::string databasePath {"rocksdb"};
    int offset {0};

    /**
     * @brief Convert configuration to JSON format for ContentRegister
     */
    json::Json toJson() const;

    /**
     * @brief Build an nlohmann::json object representing the config
     */
    nlohmann::json toNlohmann() const;

    /**
     * @brief Load configuration from JSON
     */
    void fromJson(const json::Json& config);

    /**
     * @brief Validate semantic correctness of the configuration.
     * Throws std::runtime_error describing the first violation found.
     */
    void validate() const;
};

/**
 * @brief ContentDownloader class - Manages content download from CTI platform
 *
 * This class is responsible for downloading engine assets (ruleset content)
 * from a remote CTI platform and storing it in a local database.
 */
class ContentDownloader
{
public:
    /**
     * @brief Constructor
     * @param config Configuration for the content manager
     * @param fileProcessingCallback Optional callback for processing downloaded files
     */
    explicit ContentDownloader(const ContentManagerConfig& config,
                               FileProcessingCallback fileProcessingCallback = nullptr);

    /**
     * @brief Destructor
     */
    ~ContentDownloader();

    /**
     * @brief Start the content downloader
     * @return true if started successfully
     */
    bool start();

    /**
     * @brief Stop the content downloader
     */
    void stop();

    /**
     * @brief Check if downloader is running
     * @return true if running
     */
    bool isRunning() const;

    /**
     * @brief Update the download interval
     * @param newInterval New interval in seconds
     */
    void updateInterval(size_t newInterval);

    /**
     * @brief Get current configuration
     * @return Current configuration
     */
    ContentManagerConfig getConfig() const;

    /**
     * @brief Update configuration
     * @param config New configuration
     */
    void updateConfig(const ContentManagerConfig& config);

    /**
     * @brief Process a message from Content Manager
     * @param message Message containing file paths and metadata
     * @return Processing result (offset, hash, status)
     */
    FileProcessingResult processMessage(const std::string& message);

private:
    /**
     * @brief Default file processing callback
     */
    FileProcessingResult defaultFileProcessingCallback(const std::string& message);

    /**
     * @brief Process downloaded content files
     * @param parsedMessage The parsed JSON message containing paths
     * @param type Type of content (offsets or raw)
     * @param offset Starting offset
     * @return Processing result
     */
    FileProcessingResult processContentFiles(const json::Json& parsedMessage, const std::string& type, int offset);

    /**
     * @brief Store content in local database
     * @param content Content to store
     * @return true if stored successfully
     */
    bool storeContent(const json::Json& content);

private:
    ContentManagerConfig m_config;
    FileProcessingCallback m_fileProcessingCallback;
    std::unique_ptr<ContentRegister> m_contentRegister;
    std::atomic<bool> m_isRunning {false};
    std::atomic<bool> m_shouldStop {false};
    mutable std::mutex m_mutex;
};

} // namespace cti::store

#endif // _CTI_STORE_CONTENT_DOWNLOADER_HPP
