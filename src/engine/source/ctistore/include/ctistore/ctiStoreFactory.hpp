#ifndef _CTI_STORE_FACTORY_HPP
#define _CTI_STORE_FACTORY_HPP

#include <memory>
#include <string>

#include <base/json.hpp>
#include <ctistore/cm.hpp>
#include <ctistore/contentDownloader.hpp>

namespace cti::store
{

/**
 * @brief Factory class for creating CTI Store instances
 */
class CTIStoreFactory
{
public:
    /**
     * @brief Create a ContentManager with default configuration
     * @param autoStart If true, starts synchronization automatically
     * @return Unique pointer to ContentManager instance
     */
    static std::unique_ptr<ContentManager> createDefaultContentManager(bool autoStart = false);

    /**
     * @brief Create a ContentManager with custom configuration
     * @param config Configuration for the content manager
     * @param autoStart If true, starts synchronization automatically
     * @return Unique pointer to ContentManager instance
     */
    static std::unique_ptr<ContentManager> createContentManager(
        const ContentManagerConfig& config,
        bool autoStart = false);

    /**
     * @brief Create a ContentManager from JSON configuration
     * @param jsonConfig JSON configuration object
     * @param autoStart If true, starts synchronization automatically
     * @return Unique pointer to ContentManager instance
     */
    static std::unique_ptr<ContentManager> createContentManagerFromJson(
        const json::Json& jsonConfig,
        bool autoStart = false);

    /**
     * @brief Create a ContentManager from configuration file
     * @param configFilePath Path to configuration file
     * @param autoStart If true, starts synchronization automatically
     * @return Unique pointer to ContentManager instance
     */
    static std::unique_ptr<ContentManager> createContentManagerFromFile(
        const std::string& configFilePath,
        bool autoStart = false);

    /**
     * @brief Get default configuration
     * @return Default configuration for ContentManager
     */
    static ContentManagerConfig getDefaultConfig();

    /**
     * @brief Load configuration from ossec.conf (future implementation)
     * @param ossecConfPath Path to ossec.conf file
     * @return Configuration loaded from ossec.conf
     */
    static ContentManagerConfig loadConfigFromOssec(const std::string& ossecConfPath = "/var/ossec/etc/ossec.conf");
};

} // namespace cti::store

#endif // _CTI_STORE_FACTORY_HPP