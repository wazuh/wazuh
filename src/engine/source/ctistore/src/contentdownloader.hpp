#ifndef _CTI_STORE_CONTENT_DOWNLOADER_HPP
#define _CTI_STORE_CONTENT_DOWNLOADER_HPP

#include <atomic>
#include <memory>
#include <mutex>

#include <json.hpp> // nlohmann

#include <ctistore/contentmanagerconfig.hpp>

// Forward declaration of global ContentRegister (defined in shared_modules/content_manager)
class ContentRegister;

namespace cti::store
{

// Internal helper for ContentManagerConfig that needs nlohmann::json
nlohmann::json contentManagerConfigToNlohmann(const ContentManagerConfig& config);

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
     * @brief Check if stop was requested
     * @return true if stop was requested
     */
    bool shouldStop() const
    {
        return m_shouldStop.load();
    }

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
    ContentManagerConfig m_config;
    FileProcessingCallback m_fileProcessingCallback;
    std::unique_ptr<ContentRegister> m_contentRegister;
    std::atomic<bool> m_isRunning {false};
    std::atomic<bool> m_shouldStop {false};
    mutable std::mutex m_mutex;
};

} // namespace cti::store

#endif // _CTI_STORE_CONTENT_DOWNLOADER_HPP
