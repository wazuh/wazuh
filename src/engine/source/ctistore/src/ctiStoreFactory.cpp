#include <ctistore/ctiStoreFactory.hpp>

#include <fstream>
#include <sstream>
#include <stdexcept>

#include <base/logging.hpp>

namespace cti::store
{

namespace
{
constexpr auto CTI_STORE_LOG_TAG = "cti-store-factory";
} // namespace

std::unique_ptr<ContentManager> CTIStoreFactory::createDefaultContentManager(bool autoStart)
{
    LOG_INFO("Creating ContentManager with default configuration");
    return std::make_unique<ContentManager>(getDefaultConfig(), autoStart);
}

std::unique_ptr<ContentManager> CTIStoreFactory::createContentManager(
    const ContentManagerConfig& config,
    bool autoStart)
{
    LOG_INFO("Creating ContentManager with custom configuration");
    return std::make_unique<ContentManager>(config, autoStart);
}

std::unique_ptr<ContentManager> CTIStoreFactory::createContentManagerFromJson(
    const json::Json& jsonConfig,
    bool autoStart)
{
    LOG_INFO("Creating ContentManager from JSON configuration");

    ContentManagerConfig config;
    config.fromJson(jsonConfig);

    return std::make_unique<ContentManager>(config, autoStart);
}

std::unique_ptr<ContentManager> CTIStoreFactory::createContentManagerFromFile(
    const std::string& configFilePath,
    bool autoStart)
{
    LOG_INFO("Creating ContentManager from configuration file: {}", configFilePath);

    try
    {
        std::ifstream file(configFilePath);
        if (!file.is_open())
        {
            throw std::runtime_error("Failed to open configuration file: " + configFilePath);
        }

        std::stringstream buffer;
        buffer << file.rdbuf();

        json::Json jsonConfig(buffer.str().c_str());
        return createContentManagerFromJson(jsonConfig, autoStart);
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to load configuration from file: {}", e.what());
        throw;
    }
}

ContentManagerConfig CTIStoreFactory::getDefaultConfig()
{
    ContentManagerConfig config;

    // Default configuration as specified
    config.topicName = "engine_cti_store";
    config.interval = 3600;
    config.onDemand = true;
    config.consumerName = "Wazuh Engine";
    config.contentSource = "cti-offset";
    config.compressionType = "raw";
    config.versionedContent = "cti-api";
    config.deleteDownloadedContent = true;
    config.url = "https://cti-pre.wazuh.com/api/v1/catalog/contexts/decoders_test_5.0/consumers/decoders_test_5.0";
    config.outputFolder = "/var/ossec/engine/cti_store/content";
    config.contentFileName = "api_file.json";
    config.databasePath = "/var/ossec/engine/cti_store/db";
    config.offset = 0;

    return config;
}

ContentManagerConfig CTIStoreFactory::loadConfigFromOssec(const std::string& ossecConfPath)
{
    LOG_INFO("Loading CTI Store configuration from ossec.conf: {}", ossecConfPath);

    // TODO: Implement parsing of ossec.conf to extract CTI Store configuration
    // For now, return default configuration
    LOG_WARNING("ossec.conf parsing not yet implemented, using default configuration");

    return getDefaultConfig();
}

} // namespace cti::store