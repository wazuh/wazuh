#include <ctistore/cm.hpp>

#include <filesystem>
#include <fstream>
#include <stdexcept>

#include <base/logging.hpp>

namespace cti::store
{

namespace {
constexpr auto CTI_STORE_LOG_TAG = "cti-store";
} // namespace

ContentManager::ContentManager(const ContentManagerConfig& config, bool autoStart)
    : m_config(config)
{
    LOG_INFO("Initializing CTI Store ContentManager");

    try {
        if (!m_config.databasePath.empty()) { std::filesystem::create_directories(m_config.databasePath); }
        if (!m_config.outputFolder.empty()) { std::filesystem::create_directories(m_config.outputFolder); }
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to create CTI store directories: {}", e.what());
        throw;
    }

    // Initialize the content downloader with a callback to process downloaded content
    auto processingCallback = [this](const std::string& message) -> FileProcessingResult
    {
        return processDownloadedContent(message);
    };

    m_downloader = std::make_unique<ContentDownloader>(m_config, processingCallback);

    if (autoStart)
    {
        startSync();
    }
}

ContentManager::~ContentManager()
{
    if (isSyncRunning())
    {
        stopSync();
    }
}

// ICMReader interface implementations
std::vector<base::Name> ContentManager::getAssetList(cti::store::AssetType type) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    // TODO: Implement actual database query to retrieve asset list by type
    // This will be implemented once the database backend is integrated

    LOG_TRACE("Getting asset list for type: {}", static_cast<int>(type));
    return {};
}

json::Json ContentManager::getAsset(const base::Name& name) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    // TODO: Implement actual database query to retrieve asset by name
    // This will be implemented once the database backend is integrated

    LOG_TRACE("Getting asset: {}", name.toStr());
    return json::Json();
}

bool ContentManager::assetExists(const base::Name& name) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    // TODO: Implement actual database query to check asset existence
    // This will be implemented once the database backend is integrated

    LOG_TRACE("Checking if asset exists: {}", name.toStr());
    return false;
}

std::vector<std::string> ContentManager::listKVDB() const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    // TODO: Implement actual database query to list all KVDBs
    // This will be implemented once the database backend is integrated

    LOG_TRACE("Listing all KVDBs");
    return {};
}

std::vector<std::string> ContentManager::listKVDB(const base::Name& integrationName) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    // TODO: Implement actual database query to list KVDBs by integration
    // This will be implemented once the database backend is integrated

    LOG_TRACE("Listing KVDBs for integration: {}", integrationName.toStr());
    return {};
}
bool ContentManager::kvdbExists(const std::string& kdbName) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    // TODO: Implement actual database query to check KVDB existence
    // This will be implemented once the database backend is integrated

    LOG_TRACE("Checking if KVDB exists: {}", kdbName);
    return false;
}

json::Json ContentManager::kvdbDump(const std::string& kdbName) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    // TODO: Implement actual database query to dump KVDB content
    // This will be implemented once the database backend is integrated

    LOG_TRACE("Dumping KVDB: {}", kdbName);
    return json::Json();
}

std::vector<base::Name> ContentManager::getPolicyIntegrationList() const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    // TODO: Implement actual database query to get policy integration list
    // This will be implemented once the database backend is integrated

    LOG_TRACE("Getting policy integration list");
    return {};
}

base::Name ContentManager::getPolicyDefaultParent() const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    // TODO: Implement actual database query to get default parent
    // This will be implemented once the database backend is integrated

    LOG_TRACE("Getting policy default parent");
    return base::Name();
}

/************************************************************************************
 * Other method implementations can be added here
 ************************************************************************************/

bool ContentManager::startSync()
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    LOG_INFO("Starting CTI Store content synchronization");

    if (!m_downloader)
    {
        LOG_ERROR("ContentDownloader not initialized");
        return false;
    }

    return m_downloader->start();
}

void ContentManager::stopSync()
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    LOG_INFO("Stopping CTI Store content synchronization");

    if (m_downloader)
    {
        m_downloader->stop();
    }
}

bool ContentManager::isSyncRunning() const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    return m_downloader && m_downloader->isRunning();
}

bool ContentManager::forceSyncNow()
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    LOG_INFO("Forcing immediate CTI Store synchronization");

    if (!m_downloader)
    {
        LOG_ERROR("ContentDownloader not initialized");
        return false;
    }

    return m_downloader->forceDownload();
}

void ContentManager::updateSyncInterval(size_t intervalSeconds)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    LOG_INFO("Updating sync interval to {} seconds", intervalSeconds);

    m_config.interval = intervalSeconds;

    if (m_downloader)
    {
        m_downloader->updateInterval(intervalSeconds);
    }
}

ContentManagerConfig ContentManager::getConfig() const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_config;
}

void ContentManager::updateConfig(const ContentManagerConfig& config, bool restart)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    LOG_INFO("Updating ContentManager configuration");

    m_config = config;

    if (m_downloader)
    {
        m_downloader->updateConfig(config);

        if (restart && m_downloader->isRunning())
        {
            LOG_INFO("Restarting sync with new configuration");
            m_downloader->stop();
            m_downloader->start();
        }
    }
}

FileProcessingResult ContentManager::processDownloadedContent(const std::string& message)
{
    try
    {
        LOG_DEBUG("Processing downloaded CTI content");

        // Parse the message to determine the type of content
        json::Json parsedMessage(message.c_str());

        if (!parsedMessage.exists("paths") ||
            !parsedMessage.exists("type") ||
            !parsedMessage.exists("offset"))
        {
            throw std::runtime_error("Invalid message format");
        }

        auto type = parsedMessage.getString("/type").value_or("");
        auto offset = parsedMessage.getInt("/offset").value_or(0);

        int processedOffset = offset;
        std::string hash = "";
        bool success = true;

        // Process each file in the paths array
        auto pathsArray = parsedMessage.getArray("/paths");
        if (pathsArray.has_value())
        {
            for (const auto& pathValue : pathsArray.value())
            {
                auto path = json::Json(pathValue).getString().value_or("");
                LOG_DEBUG("Processing file: {}", path);

                std::ifstream file(path);
                if (!file.is_open())
                {
                    LOG_ERROR("Failed to open file: {}", path);
                    success = false;
                    break;
                }

                std::string line;
                while (std::getline(file, line))
                {
                    try
                    {
                        json::Json content(line.c_str());

                        // Determine the type of content and store accordingly
                        if (content.exists("asset_type"))
                        {
                            if (!storeAsset(content))
                            {
                                LOG_WARNING("Failed to store asset");
                            }
                        }
                        else if (content.exists("kvdb_name"))
                        {
                            if (!storeKVDB(content))
                            {
                                LOG_WARNING("Failed to store KVDB data");
                            }
                        }
                        else if (content.exists("policy_data"))
                        {
                            if (!storePolicy(content))
                            {
                                LOG_WARNING("Failed to store policy data");
                            }
                        }

                        // Update offset if present
                        if (content.exists("offset"))
                        {
                            processedOffset = content.getInt("/offset").value_or(processedOffset);
                        }
                    }
                    catch (const std::exception& e)
                    {
                        LOG_ERROR("Error processing content line: {}", e.what());
                    }
                }
            }
        }

        LOG_INFO("Processed CTI content up to offset: {}", processedOffset);
        return {processedOffset, hash, success};
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Error processing downloaded content: {}", e.what());
        return {0, "", false};
    }
}

bool ContentManager::storeAsset(const json::Json& asset)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    try
    {
        // TODO: Implement actual storage in database
        // This is a placeholder for the actual database storage implementation

        if (asset.exists("name"))
        {
            auto name = asset.getString("/name").value_or("unknown");
            LOG_TRACE("Storing asset: {}", name);

            // Here we would store the asset in the database
            // For now, just log the operation
        }

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to store asset: {}", e.what());
        return false;
    }
}

bool ContentManager::storeKVDB(const json::Json& kvdbData)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    try
    {
        // TODO: Implement actual storage in database
        // This is a placeholder for the actual database storage implementation

        if (kvdbData.exists("kvdb_name"))
        {
            auto name = kvdbData.getString("/kvdb_name").value_or("unknown");
            LOG_TRACE("Storing KVDB: {}", name);

            // Here we would store the KVDB data in the database
            // For now, just log the operation
        }

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to store KVDB: {}", e.what());
        return false;
    }
}

bool ContentManager::storePolicy(const json::Json& policyData)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    try
    {
        // TODO: Implement actual storage in database
        // This is a placeholder for the actual database storage implementation

        if (policyData.exists("policy_id"))
        {
            auto id = policyData.getString("/policy_id").value_or("unknown");
            LOG_TRACE("Storing policy: {}", id);

            // Here we would store the policy data in the database
            // For now, just log the operation
        }

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to store policy: {}", e.what());
        return false;
    }
}

} // namespace cti::store
