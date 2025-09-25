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

        if (!parsedMessage.exists("/paths") ||
            !parsedMessage.exists("/type") ||
            !parsedMessage.exists("/offset"))
        {
            throw std::runtime_error("Invalid message format");
        }

    auto type = parsedMessage.getString("/type").value_or("");
    auto offset = parsedMessage.getInt("/offset").value_or(0);
    auto pathsMaybe = parsedMessage.getArray("/paths");
    size_t pathsCount = pathsMaybe.has_value() ? pathsMaybe.value().size() : 0;
    LOG_DEBUG("Downloaded message metadata: type='{}' starting_offset={} paths_count={}",
          type,
          offset,
          pathsCount);

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
                size_t lineNumber {0};
                size_t unclassifiedCount {0};
                size_t classifiedCount {0};
                while (std::getline(file, line))
                {
                    ++lineNumber;
                    if (line.empty()) { continue; }
                    try
                    {
                        json::Json content(line.c_str());

                        // Update offset first if present to be resilient to partial failures
                        if (content.exists("/offset"))
                        {
                            processedOffset = content.getInt("/offset").value_or(processedOffset);
                        }

                        // Classification rules based on observed JSON lines retrieved from CTI platform:
                        // Each line has: name, offset, version, inserted_at, payload{...}, type (policy|integration|decoder|kvdb)
                        // Optional: integration_id when type != policy/integration itself (e.g. decoder, kvdb belongs to integration)
                        // 'type' may appear either at root (e.g. some decoder entries) or under payload (policy, integration, kvdb)
                        // Prefer /payload/type (observed format). Fallback to root /type if ever provided.
                        auto contentType = content.getString("/payload/type").value_or(
                            content.getString("/type").value_or(""));
                        LOG_TRACE("Classifying line {}: type='{}'", lineNumber, contentType.empty() ? "<none>" : contentType.c_str());
                        if (contentType.empty())
                        {
                            ++unclassifiedCount;
                            continue; // skip silently; we'll summarize after loop
                        }

                        bool stored = true;
                        if (contentType == "policy") {
                            stored = storePolicy(content);
                        } else if (contentType == "integration") {
                            stored = storeIntegration(content);
                        } else if (contentType == "decoder") {
                            stored = storeDecoder(content);
                        } else if (contentType == "kvdb") {
                            stored = storeKVDB(content);
                        }
                        else
                        {
                            LOG_WARNING("Unknown content type '{}' on line {} in file {}", contentType, lineNumber, path);
                            continue;
                        }

                        if (stored)
                        {
                            ++classifiedCount;
                        }
                        else
                        {
                            LOG_WARNING("Failed to persist content type '{}' (line {} in {})", contentType, lineNumber, path);
                        }
                    }
                    catch (const std::exception& e)
                    {
                        LOG_ERROR("Error processing content line {} in {}: {}", lineNumber, path, e.what());
                    }
                }
                if (unclassifiedCount > 0)
                {
                    LOG_WARNING("File '{}' processed with {} classified and {} unclassified lines (missing type). First bytes: '{}'", path, classifiedCount, unclassifiedCount, line.substr(0, 60));
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

bool ContentManager::storeIntegration(const json::Json& integration)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    try {
        // TODO: Implement actual storage in database
        // This is a placeholder for the actual database storage implementation

        auto name = integration.getString("/name").value_or("unknown");
        // payload.document.* holds metadata
        auto title = integration.getString("/payload/document/title").value_or("");
        LOG_TRACE("Storing integration name='{}' title='{}'", name, title);
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to store integration: {}", e.what());
        return false;
    }
}

bool ContentManager::storeDecoder(const json::Json& decoder)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    try {
        // TODO: Implement actual storage in database
        // This is a placeholder for the actual database storage implementation

        auto name = decoder.getString("/name").value_or("unknown");
        auto module = decoder.getString("/payload/document/metadata/module").value_or("");
        LOG_TRACE("Storing decoder name='{}' module='{}'", name, module);
        return true;
    } catch (const std::exception& e) {
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
        auto integration = kvdbData.getString("/integration_id").value_or(
            kvdbData.getString("/payload/integration_id").value_or(""));
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
