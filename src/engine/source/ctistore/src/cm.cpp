#include <ctistore/cm.hpp>

#include <filesystem>
#include <fstream>
#include <stdexcept>

#include <base/logging.hpp>

namespace cti::store
{

namespace
{
constexpr auto CTI_STORE_LOG_TAG = "cti-store";
} // namespace

ContentManager::ContentManager(const ContentManagerConfig& config, bool autoStart)
    : m_config(config)
{
    LOG_INFO("Initializing CTI Store ContentManager");

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

    config.validate();

    m_config = config;

    if (m_downloader)
    {
        try
        {
            m_downloader->updateConfig(config);
            if (restart && m_downloader->isRunning())
            {
                LOG_INFO("Restarting sync with new configuration");
                m_downloader->stop();
                m_downloader->start();
            }
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Failed to apply new configuration to ContentDownloader: {}", e.what());
            // Re-throw so caller knows update failed and state is unchanged
            throw;
        }
    }
}

FileProcessingResult ContentManager::processDownloadedContent(const std::string& message)
{
    try
    {
        LOG_DEBUG("CTI: processing downloaded content message");
        json::Json parsedMessage(message.c_str());
        if (!parsedMessage.exists("/paths") || !parsedMessage.exists("/type") || !parsedMessage.exists("/offset"))
        {
            throw std::runtime_error("Invalid message format: missing required fields (paths,type,offset)");
        }

        const auto type = parsedMessage.getString("/type").value_or("");
        int startingOffset = parsedMessage.getInt("/offset").value_or(0);
        auto pathsArray = parsedMessage.getArray("/paths");
        size_t pathCount = pathsArray.has_value() ? pathsArray->size() : 0;
        LOG_DEBUG("CTI message meta: type='{}' starting_offset={} paths_count={}", type, startingOffset, pathCount);

        int currentOffset = startingOffset;
        std::string hash;
        bool success = true;

        if (type == "offsets")
        {
            // Incremental update: process each file, offset advances monotonically but may arrive out of order.
            if (pathsArray.has_value())
            {
                for (const auto& pathValue : pathsArray.value())
                {
                    const auto path = json::Json(pathValue).getString().value_or("");
                    LOG_DEBUG("CTI offsets: processing file {}", path);
                    std::ifstream file(path);
                    if (!file.is_open())
                    {
                        LOG_ERROR("Unable to open offsets file: {}", path);
                        success = false;
                        break;
                    }
                    std::string line;
                    size_t lineNumber {0};
                    while (std::getline(file, line))
                    {
                        ++lineNumber;
                        if (line.empty())
                        {
                            continue;
                        }
                        try
                        {
                            json::Json content(line.c_str());
                            if (content.exists("/offset"))
                            {
                                currentOffset = content.getInt("/offset").value_or(currentOffset);
                            }
                            // classify & store
                            auto contentType =
                                content.getString("/payload/type").value_or(content.getString("/type").value_or(""));
                            if (!contentType.empty())
                            {
                                bool stored = true;
                                if (contentType == "policy")
                                    stored = storePolicy(content);
                                else if (contentType == "integration")
                                    stored = storeIntegration(content);
                                else if (contentType == "decoder")
                                    stored = storeDecoder(content);
                                else if (contentType == "kvdb")
                                    stored = storeKVDB(content);
                                else
                                    LOG_WARNING(
                                        "Offsets: unknown content type '{}' ({}:{})", contentType, path, lineNumber);
                                if (!stored)
                                {
                                    LOG_WARNING(
                                        "Failed to store content type '{}' ({}:{})", contentType, path, lineNumber);
                                }
                            }
                        }
                        catch (const std::exception& e)
                        {
                            LOG_ERROR("Error parsing offsets line {} in {}: {}", lineNumber, path, e.what());
                        }
                    }
                }
            }
        }
        else if (type == "raw")
        {
            // Snapshot download: expect exactly one consolidated file.
            if (pathCount != 1)
            {
                throw std::runtime_error("raw message must contain exactly one path");
            }
            const auto path = json::Json(pathsArray->at(0)).getString().value_or("");
            LOG_INFO("CTI snapshot: processing consolidated file {}", path);
            // TODO: clear existing persisted data (when RocksDB integration merged)
            std::ifstream file(path);
            if (!file.is_open())
            {
                throw std::runtime_error("Unable to open raw file: " + path);
            }
            std::string line;
            size_t lineNumber {0};
            while (std::getline(file, line))
            {
                ++lineNumber;
                if (line.empty())
                    continue;
                try
                {
                    json::Json content(line.c_str());
                    if (content.exists("/offset"))
                    {
                        // Highest offset across the entire snapshot
                        currentOffset = std::max(currentOffset, content.getInt("/offset").value_or(currentOffset));
                    }
                    auto contentType =
                        content.getString("/payload/type").value_or(content.getString("/type").value_or(""));
                    if (!contentType.empty())
                    {
                        bool stored = true;
                        if (contentType == "policy")
                            stored = storePolicy(content);
                        else if (contentType == "integration")
                            stored = storeIntegration(content);
                        else if (contentType == "decoder")
                            stored = storeDecoder(content);
                        else if (contentType == "kvdb")
                            stored = storeKVDB(content);
                        else
                            LOG_WARNING("Raw: unknown content type '{}' ({}:{})", contentType, path, lineNumber);
                        if (!stored)
                        {
                            LOG_WARNING("Failed to store content type '{}' ({}:{})", contentType, path, lineNumber);
                        }
                    }
                }
                catch (const std::exception& e)
                {
                    LOG_ERROR("Error parsing raw line {} in {}: {}", lineNumber, path, e.what());
                }
            }
            // Extract hash if provided (offline scenario)
            if (parsedMessage.exists("/fileMetadata/hash"))
            {
                hash = parsedMessage.getString("/fileMetadata/hash").value_or("");
            }
        }
        else
        {
            throw std::runtime_error("Unknown message type: " + type);
        }

        LOG_INFO("CTI processed up to offset {} (type='{}')", currentOffset, type);
        return {currentOffset, hash, success};
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Error processing downloaded content: {}", e.what());
        return {0, "", false};
    }
}

bool ContentManager::storeIntegration(const json::Json& integration)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    try
    {
        // TODO: Implement actual storage in database
        // This is a placeholder for the actual database storage implementation

        auto name = integration.getString("/name").value_or("unknown");
        // payload.document.* holds metadata
        auto title = integration.getString("/payload/document/title").value_or("");
        LOG_TRACE("Storing integration name='{}' title='{}'", name, title);
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to store integration: {}", e.what());
        return false;
    }
}

bool ContentManager::storeDecoder(const json::Json& decoder)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    try
    {
        // TODO: Implement actual storage in database
        // This is a placeholder for the actual database storage implementation

        auto name = decoder.getString("/name").value_or("unknown");
        auto module = decoder.getString("/payload/document/metadata/module").value_or("");
        LOG_TRACE("Storing decoder name='{}' module='{}'", name, module);
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to store decoder: {}", e.what());
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

        auto name = kvdbData.getString("/name").value_or("unknown");
        // integration_id may be at root (decoder style) or inside payload for kvdb entries
        auto integration =
            kvdbData.getString("/integration_id").value_or(kvdbData.getString("/payload/integration_id").value_or(""));
        LOG_TRACE("Storing KVDB '{}' (integration='{}')", name, integration);

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

        auto name = policyData.getString("/name").value_or("unknown");
        LOG_TRACE("Storing policy '{}'", name);

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to store policy: {}", e.what());
        return false;
    }
}

} // namespace cti::store
