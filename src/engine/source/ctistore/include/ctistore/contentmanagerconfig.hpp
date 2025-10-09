#ifndef _CTI_STORE_CONTENT_MANAGER_CONFIG_HPP
#define _CTI_STORE_CONTENT_MANAGER_CONFIG_HPP

#include <functional>
#include <string>
#include <tuple>

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
 * @brief Aggregates all parameters required to orchestrate CTI content retrieval and processing.
 *
 * The configuration groups three logical concerns:
 *  - Scheduler & identity: topicName, interval, onDemand
 *  - Content acquisition & transformation: consumerName, contentSource, compressionType,
 *    versionedContent, url, deleteDownloadedContent, contentFileName, offset
 *  - Storage & state: basePath (path normalization), outputFolder (downloads/contents),
 *    databasePath (persist last offset for cti-offset + cti-api), assetStorePath (optional metadata store)
 *
 * Supported enumerations mirror the original shared Content Manager module:
 *  - contentSource: api | cti-offset | cti-snapshot | file | offline
 *  - compressionType: gzip | zip | xz | raw
 *  - versionedContent: "false" | "cti-api"
 *
 * Typical workflow:
 *  1. Validate() ensures semantic correctness (e.g., required fields per source type).
 *  2. Normalize() resolves relative paths against basePath.
 *  3. createDirectories() prepares filesystem layout (downloads + contents + optional assets).
 *  4. toJson() produces the structure expected by the internal ContentRegister.
 *
 * Notes:
 *  - When onDemand == true the periodic scheduler STILL runs; an additional UNIX socket endpoint
 *    allows external immediate execution triggers.
 *  - deleteDownloadedContent purges BOTH downloads and contents folders (compressed and processed
 *    files).
 *  - offset seeds incremental fetching when using cti-offset + versionedContent == "cti-api".
 */
struct ContentManagerConfig
{
    // Topic (logical identifier) that describes the action / orchestration executed
    // by the content manager. Used to tag logs and published messages.
    std::string topicName {"engine_cti_store"};

    // Interval in seconds between scheduled executions of the Content Manager.
    int interval {3600}; // seconds

    // Enables an additional on-demand execution path (UNIX socket endpoint) without
    // removing the periodic scheduling. When true you can trigger immediate runs
    // externally while the interval-based scheduler still operates.
    bool onDemand {false};

    // Base path used to normalize relative paths (outputFolder, databasePath,
    // assetStorePath). If empty, provided paths are used as-is.
    std::string basePath {};

    // -------------------------------------------------------------------------
    // Config data
    // -------------------------------------------------------------------------

    // Name of the consumer invoking the download.
    std::string consumerName {"Wazuh Engine"};

    // Content source. Supported values:
    //   api | cti-offset | cti-snapshot | file | offline
    // Default here: "cti-offset" to fetch incremental CTI offsets.
    std::string contentSource {"cti-offset"};

    // Compression type of the downloaded content. Supported values:
    //   gzip | zip | xz | raw
    // "raw" means the content is not compressed.
    std::string compressionType {"raw"};

    // Content versioning mode. Supported values:
    //   "false" (no versioning) | "cti-api" (uses CTI offsets to prevent
    //   re-processing previously seen content). Default "cti-api" given the source.
    std::string versionedContent {"cti-api"};

    // When true, the cleanup stage purges BOTH the downloads and contents folders
    // after the orchestration completes. This removes the compressed artifact and the
    // processed output files, leaving a clean state.
    bool deleteDownloadedContent {false};

    // Base URL from which content will be downloaded (CTI API, snapshot, remote
    // file, etc.). For cti-offset and cti-snapshot points to the CTI context/consumer
    // endpoint.
    std::string url {"https://cti-pre.wazuh.com/api/v1/catalog/contexts/decoders_development_0.0.1/consumers/"
                     "decoders_development_0.0.1"};

    // Output folder where two subfolders are created: downloads (original artifacts)
    // and contents (processed / decompressed). If relative and basePath is set it is
    // normalized against basePath.
    std::string outputFolder {"content"};

    // Final content file name when applicable (api source and grouped cti-api offsets).
    // If not provided in the original module a temporary name is built. Here it is
    // explicitly set.
    std::string contentFileName {"cti_content.json"};

    // RocksDB database path where the last offset is persisted when
    // contentSource = cti-offset and versionedContent = cti-api.
    std::string databasePath {"offset_database"};

    // Directory for the CTI assets RocksDB. After downloads are processed, structured
    // asset entries are persisted here.
    // Distinguished from 'databasePath':
    //   - databasePath: RocksDB holding last fetched offset and versioning state.
    //   - assetStorePath: RocksDB holding processed content-derived assets for reuse/enrichment.
    // If relative, it is normalized via basePath during normalize().
    // Created only when createDirectories(includeAssetStore=true) is invoked. Leaving it empty
    // (or not creating the directory) disables persistent asset storage (assets kept in-memory only).
    std::string assetStorePath {"assets_database"};

    // Initial (seed) offset from which to begin incremental download in cti-offset
    // mode. If 0, starts from the first available offset reported by the API.
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
