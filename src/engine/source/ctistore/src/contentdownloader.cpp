#include "contentdownloader.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

#include <base/logging.hpp>
#include <contentRegister.hpp>

namespace cti::store
{

nlohmann::json contentManagerConfigToNlohmann(const ContentManagerConfig& config)
{
    nlohmann::json j;
    j["topicName"] = config.topicName;
    j["interval"] = config.interval;
    j["ondemand"] = config.onDemand;
    nlohmann::json cfg;
    cfg["consumerName"] = config.consumerName;
    cfg["contentSource"] = config.contentSource;
    cfg["compressionType"] = config.compressionType;
    cfg["versionedContent"] = config.versionedContent;
    cfg["deleteDownloadedContent"] = config.deleteDownloadedContent;
    cfg["url"] = config.url;
    cfg["outputFolder"] = config.outputFolder;
    cfg["contentFileName"] = config.contentFileName;
    cfg["databasePath"] = config.databasePath;
    cfg["assetStorePath"] = config.assetStorePath;
    cfg["offset"] = config.offset;

    // OAuth configuration
    nlohmann::json oauth;
    nlohmann::json indexer;
    indexer["url"] = config.oauth.indexer.url;
    indexer["credentialsEndpoint"] = config.oauth.indexer.credentialsEndpoint;
    oauth["indexer"] = std::move(indexer);

    nlohmann::json console;
    console["url"] = config.oauth.console.url;
    console["instancesEndpoint"] = config.oauth.console.instancesEndpoint;
    console["timeout"] = config.oauth.console.timeout;
    console["productType"] = config.oauth.console.productType;
    oauth["console"] = std::move(console);

    nlohmann::json tokenExchange;
    tokenExchange["enabled"] = config.oauth.tokenExchange.enabled;
    tokenExchange["consoleUrl"] = config.oauth.console.url;
    tokenExchange["tokenEndpoint"] = config.oauth.tokenExchange.tokenEndpoint;
    tokenExchange["cacheSignedUrls"] = config.oauth.tokenExchange.cacheSignedUrls;
    oauth["tokenExchange"] = std::move(tokenExchange);

    oauth["enableProductsProvider"] = config.oauth.enableProductsProvider;
    cfg["oauth"] = std::move(oauth);

    j["configData"] = std::move(cfg);
    return j;
}

json::Json ContentManagerConfig::toJson() const
{
    auto nj = contentManagerConfigToNlohmann(*this);
    return json::Json(nj.dump().c_str());
}

void ContentManagerConfig::fromJson(const json::Json& config)
{
    if (config.exists("/topicName"))
    {
        topicName = config.getString("/topicName").value_or(topicName);
    }
    if (config.exists("/interval"))
    {
        interval = config.getInt("/interval").value_or(interval);
    }
    if (config.exists("/ondemand"))
    {
        onDemand = config.getBool("/ondemand").value_or(onDemand);
    }

    if (config.exists("/configData"))
    {
        if (config.exists("/configData/consumerName"))
        {
            consumerName = config.getString("/configData/consumerName").value_or(consumerName);
        }
        if (config.exists("/configData/contentSource"))
        {
            contentSource = config.getString("/configData/contentSource").value_or(contentSource);
        }
        if (config.exists("/configData/compressionType"))
        {
            compressionType = config.getString("/configData/compressionType").value_or(compressionType);
        }
        if (config.exists("/configData/versionedContent"))
        {
            versionedContent = config.getString("/configData/versionedContent").value_or(versionedContent);
        }
        if (config.exists("/configData/deleteDownloadedContent"))
        {
            deleteDownloadedContent =
                config.getBool("/configData/deleteDownloadedContent").value_or(deleteDownloadedContent);
        }
        if (config.exists("/configData/url"))
        {
            url = config.getString("/configData/url").value_or(url);
        }
        if (config.exists("/configData/outputFolder"))
        {
            outputFolder = config.getString("/configData/outputFolder").value_or(outputFolder);
        }
        if (config.exists("/configData/contentFileName"))
        {
            contentFileName = config.getString("/configData/contentFileName").value_or(contentFileName);
        }
        if (config.exists("/configData/databasePath"))
        {
            databasePath = config.getString("/configData/databasePath").value_or(databasePath);
        }
        if (config.exists("/configData/assetStorePath"))
        {
            assetStorePath = config.getString("/configData/assetStorePath").value_or(assetStorePath);
        }
        if (config.exists("/configData/offset"))
        {
            offset = config.getInt("/configData/offset").value_or(offset);
        }

        // OAuth configuration
        if (config.exists("/configData/oauth"))
        {
            if (config.exists("/configData/oauth/indexer/url"))
            {
                oauth.indexer.url = config.getString("/configData/oauth/indexer/url").value_or(oauth.indexer.url);
            }
            if (config.exists("/configData/oauth/indexer/credentialsEndpoint"))
            {
                oauth.indexer.credentialsEndpoint = config.getString("/configData/oauth/indexer/credentialsEndpoint")
                                                        .value_or(oauth.indexer.credentialsEndpoint);
            }
            if (config.exists("/configData/oauth/console/url"))
            {
                oauth.console.url = config.getString("/configData/oauth/console/url").value_or(oauth.console.url);
            }
            if (config.exists("/configData/oauth/console/instancesEndpoint"))
            {
                oauth.console.instancesEndpoint = config.getString("/configData/oauth/console/instancesEndpoint")
                                                      .value_or(oauth.console.instancesEndpoint);
            }
            if (config.exists("/configData/oauth/console/timeout"))
            {
                oauth.console.timeout =
                    config.getInt("/configData/oauth/console/timeout").value_or(oauth.console.timeout);
            }
            if (config.exists("/configData/oauth/console/productType"))
            {
                oauth.console.productType =
                    config.getString("/configData/oauth/console/productType").value_or(oauth.console.productType);
            }
            if (config.exists("/configData/oauth/enableProductsProvider"))
            {
                oauth.enableProductsProvider =
                    config.getBool("/configData/oauth/enableProductsProvider").value_or(oauth.enableProductsProvider);
            }

            // TokenExchange configuration
            if (config.exists("/configData/oauth/tokenExchange/enabled"))
            {
                oauth.tokenExchange.enabled =
                    config.getBool("/configData/oauth/tokenExchange/enabled").value_or(oauth.tokenExchange.enabled);
            }
            if (config.exists("/configData/oauth/tokenExchange/tokenEndpoint"))
            {
                oauth.tokenExchange.tokenEndpoint = config.getString("/configData/oauth/tokenExchange/tokenEndpoint")
                                                        .value_or(oauth.tokenExchange.tokenEndpoint);
            }
            if (config.exists("/configData/oauth/tokenExchange/cacheSignedUrls"))
            {
                oauth.tokenExchange.cacheSignedUrls = config.getBool("/configData/oauth/tokenExchange/cacheSignedUrls")
                                                          .value_or(oauth.tokenExchange.cacheSignedUrls);
            }
        }
    }
}

void ContentManagerConfig::normalize()
{
    if (basePath.empty())
    {
        return;
    }

    std::filesystem::path base {basePath};
    const auto makeAbsolute = [&](const std::string& value) -> std::string
    {
        if (value.empty())
        {
            return value;
        }
        std::filesystem::path p {value};
        if (p.is_absolute())
        {
            return p.string();
        }
        return (base / p).string();
    };

    outputFolder = makeAbsolute(outputFolder);
    databasePath = makeAbsolute(databasePath);
    if (!assetStorePath.empty())
    {
        assetStorePath = makeAbsolute(assetStorePath);
    }
}

void ContentManagerConfig::createDirectories(bool includeAssetStore) const
{
    try
    {
        if (!outputFolder.empty())
        {
            std::filesystem::create_directories(outputFolder);
        }
        if (!databasePath.empty())
        {
            std::filesystem::create_directories(databasePath);
        }
        if (includeAssetStore && !assetStorePath.empty())
        {
            std::filesystem::create_directories(assetStorePath);
        }
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to create CTI store directories: {}", e.what());
        throw;
    }
}

void ContentManagerConfig::validate() const
{
    if (topicName.empty())
    {
        throw std::runtime_error("ContentManagerConfig: topicName cannot be empty");
    }
    if (interval <= 0)
    {
        throw std::runtime_error("ContentManagerConfig: interval must be > 0");
    }
    if (consumerName.empty())
    {
        throw std::runtime_error("ContentManagerConfig: consumerName cannot be empty");
    }
    if (contentSource.empty())
    {
        throw std::runtime_error("ContentManagerConfig: contentSource cannot be empty");
    }

    static const std::array<std::string, 3> allowedSources {"cti-offset", "offline", "cti-api"};
    const bool sourceOk = std::any_of(
        allowedSources.begin(), allowedSources.end(), [&](const std::string& v) { return v == contentSource; });
    if (!sourceOk)
    {
        throw std::runtime_error("ContentManagerConfig: unsupported contentSource: " + contentSource);
    }

    // Optional OAuth validation - OAuth is enabled when indexer and console URLs are present
    if (!oauth.indexer.url.empty() || !oauth.console.url.empty())
    {
        // If any OAuth URL is set, validate complete configuration
        if (oauth.indexer.url.empty())
        {
            throw std::runtime_error("ContentManagerConfig: oauth.indexer.url required when OAuth is enabled");
        }
        if (oauth.console.url.empty())
        {
            throw std::runtime_error("ContentManagerConfig: oauth.console.url required when OAuth is enabled");
        }
        if (oauth.console.productType.empty())
        {
            throw std::runtime_error(
                "ContentManagerConfig: oauth.console.productType cannot be empty when OAuth is enabled");
        }
    }

    if (compressionType.empty())
    {
        throw std::runtime_error("ContentManagerConfig: compressionType cannot be empty");
    }
    if (versionedContent.empty())
    {
        throw std::runtime_error("ContentManagerConfig: versionedContent cannot be empty");
    }
    if (outputFolder.empty())
    {
        throw std::runtime_error("ContentManagerConfig: outputFolder cannot be empty");
    }
    if (databasePath.empty())
    {
        throw std::runtime_error("ContentManagerConfig: databasePath cannot be empty");
    }
    // assetStorePath may be empty -> fallback later to databasePath
    if (offset < 0)
    {
        throw std::runtime_error("ContentManagerConfig: offset must be >= 0");
    }

    // URL validation: only a basic scheme check (http/https) unless contentSource == offline
    if (contentSource != "offline")
    {
        if (url.empty())
        {
            throw std::runtime_error("ContentManagerConfig: url cannot be empty for non-offline sources");
        }
        if (!(url.rfind("http://", 0) == 0 || url.rfind("https://", 0) == 0))
        {
            throw std::runtime_error("ContentManagerConfig: url must start with http:// or https://");
        }
    }
}

ContentDownloader::ContentDownloader(const ContentManagerConfig& config, FileProcessingCallback fileProcessingCallback)
    : m_config(config)
    , m_fileProcessingCallback(fileProcessingCallback)
{
    m_config.normalize();
    m_config.createDirectories(false);

    LOG_DEBUG("CTI Store ContentDownloader initializing with topic: {}", m_config.topicName);
}

ContentDownloader::~ContentDownloader()
{
    if (m_isRunning)
    {
        stop();
    }
}

bool ContentDownloader::start()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_isRunning)
    {
        LOG_WARNING("ContentDownloader is already running");
        return false;
    }

    try
    {
        LOG_INFO("Starting CTI Store ContentDownloader");

        // Validate config before proceeding to register creation.
        m_config.validate();

        // Convert config to JSON format for ContentRegister
        // OAuth configuration (if present) will be passed to ContentRegister which handles OAuth providers internally
        auto nlohmannConfig = contentManagerConfigToNlohmann(m_config);

        // Log OAuth status if configured
        const bool oauthEnabled = !m_config.oauth.indexer.url.empty() && !m_config.oauth.console.url.empty();
        if (oauthEnabled)
        {
            LOG_INFO("OAuth authentication enabled for CTI Store (productType: {})",
                     m_config.oauth.console.productType);
        }
        else
        {
            LOG_DEBUG("OAuth authentication not configured, using traditional mode");
        }

        // Initialize ContentRegister with the file processing callback
        // ContentRegister will create OAuth providers internally if oauth config is present
        m_contentRegister =
            std::make_unique<ContentRegister>(m_config.topicName, nlohmannConfig, m_fileProcessingCallback);

        m_isRunning = true;
        m_shouldStop = false;

        LOG_INFO("CTI Store ContentDownloader started successfully");
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to start ContentDownloader: {}", e.what());
        return false;
    }
}

void ContentDownloader::stop()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_isRunning)
    {
        LOG_DEBUG("ContentDownloader is not running");
        return;
    }

    LOG_INFO("Stopping CTI Store ContentDownloader");

    m_shouldStop = true;
    m_contentRegister.reset();

    m_isRunning = false;

    LOG_INFO("CTI Store ContentDownloader stopped");
}

bool ContentDownloader::isRunning() const
{
    return m_isRunning;
}

void ContentDownloader::updateInterval(size_t newInterval)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_config.interval = newInterval;

    if (m_contentRegister)
    {
        m_contentRegister->changeSchedulerInterval(newInterval);
        LOG_INFO("Updated ContentDownloader interval to {} seconds", newInterval);
    }
}

ContentManagerConfig ContentDownloader::getConfig() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config;
}

void ContentDownloader::updateConfig(const ContentManagerConfig& config)
{
    config.validate();

    std::lock_guard<std::mutex> lock(m_mutex);

    m_config = config;
}

FileProcessingResult ContentDownloader::processMessage(const std::string& message)
{
    if (!m_fileProcessingCallback)
    {
        LOG_ERROR("No processing callback set in ContentDownloader");
        return {0, "", false};
    }
    return m_fileProcessingCallback(message);
}

} // namespace cti::store