#ifndef _CTI_STORE_CONTENT_MANAGER_CONFIG_HPP
#define _CTI_STORE_CONTENT_MANAGER_CONFIG_HPP

#include <string>
#include <tuple>
#include <functional>

#include <base/json.hpp>

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
    bool deleteDownloadedContent {false}; // TODO: Chage this, is for develop
    std::string url {"https://cti-pre.wazuh.com/api/v1/catalog/contexts/decoders_development_0.0.1/consumers/"
                     "decoders_development_0.0.1"};
    std::string outputFolder {"content"};
    std::string contentFileName {"cti_content.json"};
    std::string databasePath {"offset_database"};
    std::string assetStorePath {"assets_database"};
    int offset {0};

    /**
     * @brief Convert configuration to JSON format for ContentRegister
     */
    json::Json toJson() const;

    /**
     * @brief Load configuration from JSON
     */
    void fromJson(const json::Json& config);

    /**
     * @brief Validate semantic correctness of the configuration.
     * Throws std::runtime_error describing the first violation found.
     */
    void validate() const;

    /**
     * @brief Normalize relative paths against basePath.
     * Converts relative paths to absolute paths using basePath as base.
     * Does nothing if basePath is empty.
     */
    void normalize();

    /**
     * @brief Create all necessary directories for the configuration.
     * Creates outputFolder, databasePath, and optionally assetStorePath.
     * @param includeAssetStore If true, also creates assetStorePath directory
     */
    void createDirectories(bool includeAssetStore = false) const;
};

} // namespace cti::store

#endif // _CTI_STORE_CONTENT_MANAGER_CONFIG_HPP
