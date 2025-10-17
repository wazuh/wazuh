#include <ctistore/cm.hpp>
#include "contentdownloader.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include <base/logging.hpp>

namespace cti::store
{

namespace
{
// Helper function to convert AssetType enum to string
constexpr std::string_view assetTypeToString(cti::store::AssetType type) noexcept
{
    switch (type)
    {
        case cti::store::AssetType::INTEGRATION: return "integration";
        case cti::store::AssetType::DECODER: return "decoder";
        case cti::store::AssetType::ERROR_TYPE: return "";
    }
    return "";
}

} // namespace

ContentManager::ContentManager(const ContentManagerConfig& config, ContentDeployCallback deployCallback)
    : m_config(config)
    , m_deployCallback(deployCallback)
{
    LOG_INFO("Initializing CTI Store ContentManager");

    try
    {
        // Normalize paths
        m_config.normalize();

        // Validate after normalization so that any path-dependent semantics are consistent.
        m_config.validate();
        if (m_config.databasePath.empty())
        {
            throw std::runtime_error("ContentManager: databasePath cannot be empty");
        }

        m_config.createDirectories(true);

        // Decide asset storage path (separate from offset DB if provided)
        const std::string assetPath = m_config.assetStorePath.empty() ? m_config.databasePath : m_config.assetStorePath;

        m_storage = std::make_unique<CTIStorageDB>(assetPath, true);
        LOG_INFO("ContentManager: CTIStorageDB opened at '{}' (open={})", assetPath, m_storage->isOpen());
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed initializing CTIStorageDB: {}", e.what());
        throw; // propagate - storage is mandatory for manager operation now
    }

    auto processingCallback = [this](const std::string& message) -> FileProcessingResult
    {
        // Check if stop was requested before starting processing
        if (m_downloader && m_downloader->shouldStop())
        {
            LOG_DEBUG("ContentManager: stop requested, aborting content processing");
            return {0, "", false};
        }
        return processDownloadedContent(message);
    };

    m_downloader = std::make_unique<ContentDownloader>(m_config, processingCallback);

}

ContentManager::~ContentManager()
{
    if (isSyncRunning() || (m_storage && m_storage->isOpen()))
    {
        shutdown();
    }
}

// ICMReader interface implementations
std::vector<base::Name> ContentManager::getAssetList(cti::store::AssetType type) const
{
    if (!m_storage || !m_storage->isOpen())
    {
        LOG_WARNING("getAssetList called but storage not initialized");
        return {};
    }

    auto typeStr = assetTypeToString(type);
    if (typeStr.empty())
    {
        return {}; // unsupported type
    }

    try
    {
        return m_storage->getAssetList(std::string(typeStr));
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("getAssetList error for type='{}': {}", typeStr, e.what());
        return {};
    }
}

json::Json ContentManager::getAsset(const base::Name& name) const
{
    if (!m_storage || !m_storage->isOpen())
    {
        LOG_WARNING("getAsset called but storage not initialized");
        return json::Json();
    }

    // We don't know the type, try in order (integration, decoder)
    // Using constexpr array with string_view for zero-cost abstraction
    static constexpr std::array<std::string_view, 2> types {"integration", "decoder"};
    for (const auto& t : types)
    {
        try
        {
            return m_storage->getAsset(name, std::string(t));
        }
        catch (const std::exception&)
        {
            // ignore and try next
        }
    }
    LOG_TRACE("Asset '{}' not found in any type", name.toStr());
    return json::Json();
}

bool ContentManager::assetExists(const base::Name& name) const
{
    if (!m_storage || !m_storage->isOpen())
    {
        return false;
    }
    static constexpr std::array<std::string_view, 2> types {"integration", "decoder"};
    for (const auto& t : types)
    {
        try
        {
            if (m_storage->assetExists(name, std::string(t)))
            {
                return true;
            }
        }
        catch (const std::exception&)
        {
            // ignore
        }
    }
    return false;
}

std::string ContentManager::resolveNameFromUUID(const std::string& uuid) const
{
    if (!m_storage || !m_storage->isOpen())
    {
        throw std::runtime_error("Storage not initialized");
    }

    static const std::array<std::string, 2> types {"integration", "decoder"};
    std::optional<std::string> errorMsg = std::nullopt;

    for (const auto& t : types)
    {
        try
        {
            return m_storage->resolveNameFromUUID(uuid, t);
        }
        catch (const std::exception& e)
        {
            // ignore and try next
            if (!errorMsg)
            {
                errorMsg = std::string("Error list: ");
            }
            errorMsg->append(fmt::format("[type='{}': {}] ", t, e.what()));
        }
    }
    throw std::runtime_error(fmt::format("Asset with UUID '{}' not found: {}", uuid, errorMsg ? *errorMsg : "unknown error"));
}

std::vector<std::string> ContentManager::listKVDB() const
{
    if (!m_storage || !m_storage->isOpen())
    {
        return {};
    }
    try
    {
        return m_storage->getKVDBList();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("listKVDB (all) error: {}", e.what());
        return {};
    }
}

std::vector<std::string> ContentManager::listKVDB(const base::Name& integrationName) const
{
    if (!m_storage || !m_storage->isOpen())
    {
        return {};
    }
    try
    {
        return m_storage->getKVDBList(integrationName);
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("listKVDB (integration='{}') error: {}", integrationName.toStr(), e.what());
        return {};
    }
}
bool ContentManager::kvdbExists(const std::string& kdbName) const
{
    if (!m_storage || !m_storage->isOpen())
    {
        return false;
    }
    try
    {
        return m_storage->kvdbExists(kdbName);
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("kvdbExists('{}') error: {}", kdbName, e.what());
        return false;
    }
}

json::Json ContentManager::kvdbDump(const std::string& kdbName) const
{
    if (!m_storage || !m_storage->isOpen())
    {
        return json::Json();
    }
    try
    {
        return m_storage->kvdbDump(kdbName);
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("kvdbDump('{}') error: {}", kdbName, e.what());
        return json::Json();
    }
}

std::vector<base::Name> ContentManager::getPolicyIntegrationList() const
{
    if (!m_storage || !m_storage->isOpen())
    {
        return {};
    }
    try
    {
        return m_storage->getPolicyIntegrationList();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("getPolicyIntegrationList error: {}", e.what());
        return {};
    }
}


json::Json ContentManager::getPolicy(const base::Name& name) const
{
    if (!m_storage || !m_storage->isOpen())
    {
        LOG_WARNING("getPolicy called but storage not initialized");
        return json::Json();
    }
    try
    {
        return m_storage->getPolicy(name);
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("getPolicy('{}') error: {}", name.fullName(), e.what());
        throw;
    }
}

std::vector<base::Name> ContentManager::getPolicyList() const
{
    if (!m_storage || !m_storage->isOpen())
    {
        return {};
    }
    try
    {
        return m_storage->getPolicyList();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("getPolicyList error: {}", e.what());
        return {};
    }
}

bool ContentManager::policyExists(const base::Name& name) const
{
    if (!m_storage || !m_storage->isOpen())
    {
        return false;
    }
    try
    {
        return m_storage->policyExists(name);
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("policyExists('{}') error: {}", name.fullName(), e.what());
        return false;
    }
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

void ContentManager::shutdown()
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    LOG_INFO("Shutting down CTI Store ContentManager");

    // 1. Stop content synchronization if running
    if (m_downloader && m_downloader->isRunning())
    {
        LOG_DEBUG("Stopping content downloader");
        m_downloader->stop();
    }

    // 2. Close CTI storage database gracefully
    if (m_storage && m_storage->isOpen())
    {
        LOG_DEBUG("Closing CTI storage database");
        try
        {
            m_storage->shutdown();
            LOG_INFO("CTI storage database closed successfully");
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Failed to shutdown CTI storage database: {}", e.what());
        }
    }

    LOG_INFO("CTI Store ContentManager shutdown completed");
}

bool ContentManager::isSyncRunning() const
{
    // No lock needed - m_downloader is fixed after construction
    // and isRunning() is thread-safe
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

const ContentManagerConfig& ContentManager::getConfig() const
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

FileProcessingResult ContentManager::testProcessMessage(const std::string& message)
{
    if (m_downloader)
    {
        return m_downloader->processMessage(message);
    }
    return {0, "", false};
}

FileProcessingResult ContentManager::processDownloadedContent(const std::string& message)
{
    try
    {
        LOG_TRACE("CTI: processing downloaded content message: {}", message);

        json::Json parsedMessage(message.c_str());

        if (!parsedMessage.exists("/paths") || !parsedMessage.exists("/type") || !parsedMessage.exists("/offset"))
        {
            throw std::runtime_error("Invalid message format: missing required fields (paths,type,offset)");
        }

        const auto type = parsedMessage.getString("/type").value_or("");
        auto pathsArray = parsedMessage.getArray("/paths");
        size_t pathCount = pathsArray.has_value() ? pathsArray->size() : 0;

        auto currentOffset = 0;
        std::string hash;
        bool success = true;

        if (type == "offsets")
        {
            // Incremental processing
            size_t totalEntries {0};
            size_t storedItems {0};
            if (pathsArray.has_value())
            {
                for (const auto& pathValue : pathsArray.value())
                {
                    // Check if stop was requested before processing next file
                    if (m_downloader && m_downloader->shouldStop())
                    {
                        LOG_INFO("CTI offsets: processing interrupted by stop request (offset={})", currentOffset);
                        return {currentOffset, "", true};
                    }

                    const auto path = json::Json(pathValue).getString().value_or("");
                    if (path.empty())
                    {
                        LOG_WARNING("CTI offsets: encountered path entry without string value; skipping");
                        continue;
                    }

                    LOG_TRACE("CTI offsets: processing file {}", path);

                    auto readFile = [&](const std::string& p) -> std::string
                    {
                        std::ifstream f(p);
                        if (!f.is_open())
                        {
                            LOG_ERROR("Unable to open offsets file: {}", p);
                            success = false;
                            return {};
                        }
                        std::ostringstream oss;
                        oss << f.rdbuf();
                        return oss.str();
                    };

                    const auto raw = readFile(path);
                    if (raw.empty())
                    {
                        if (success)
                        {
                            LOG_WARNING("Offsets file '{}' is empty", path);
                        }
                        continue;
                    }

                    try
                    {
                        json::Json root(raw.c_str());
                        auto dataArray = root.getArray("/data");
                        if (!dataArray.has_value())
                        {
                            LOG_ERROR("Offsets file '{}' missing or invalid /data array; skipping", path);
                            success = false;
                            continue;
                        }

                        totalEntries += dataArray->size();

                        for (size_t i = 0; i < dataArray->size(); ++i)
                        {
                            // Check if stop was requested
                            if (m_downloader && m_downloader->shouldStop())
                            {
                                LOG_INFO("CTI offsets: processing interrupted by stop request at entry {} (offset={})",
                                         i, currentOffset);
                                // Return current progress - offset will be saved
                                return {currentOffset, "", true};
                            }

                            try
                            {
                                json::Json entryJson(dataArray->at(i));

                                // operation type: create|update|delete
                                const auto operationType = entryJson.getString("/type").value_or("");

                                // asset type: policy|integration|decoder|kvdb
                                const auto assetType = entryJson.getString("/payload/type").value_or("");

                                if (entryJson.exists("/offset"))
                                {
                                    currentOffset = entryJson.getInt("/offset").value_or(currentOffset);
                                }

                                entryJson.setString(entryJson.getString("/resource").value_or(""), "/name");

                                if (operationType == "create")
                                {
                                    if (assetType.empty())
                                    {
                                        LOG_WARNING("Offsets: entry #{} missing asset type (file='{}')", i, path);
                                        continue;
                                    }

                                    bool stored = true;
                                    if (assetType == "policy")
                                    {
                                        stored = storePolicy(entryJson);
                                    }
                                    else if (assetType == "integration")
                                    {
                                        stored = storeIntegration(entryJson);
                                    }
                                    else if (assetType == "decoder")
                                    {
                                        stored = storeDecoder(entryJson);
                                    }
                                    else if (assetType == "kvdb")
                                    {
                                        stored = storeKVDB(entryJson);
                                    }
                                    else
                                    {
                                        LOG_WARNING(
                                            "Offsets: unknown asset type '{}' (#{} file='{}')", assetType, i, path);
                                        stored = false;
                                    }

                                    if (!stored)
                                    {
                                        LOG_WARNING(
                                            "Offsets: failed to store asset type='{}' (#{} file='{}' offset={})",
                                            assetType,
                                            i,
                                            path,
                                            currentOffset);
                                    }
                                    else
                                    {
                                        ++storedItems;
                                    }
                                }
                                else if (operationType == "update")
                                {
                                    // Get resource ID and patch operations
                                    const auto resourceId = entryJson.getString("/resource").value_or("");
                                    if (resourceId.empty())
                                    {
                                        LOG_WARNING("Offsets: update op missing resource ID (#{} file='{}')", i, path);
                                        continue;
                                    }

                                    // Extract operations array (JSON Patch format)
                                    if (!entryJson.exists("/operations"))
                                    {
                                        LOG_WARNING("Offsets: update op missing operations field (#{} file='{}')", i, path);
                                        continue;
                                    }

                                    auto opsArray = entryJson.getArray("/operations");
                                    if (!opsArray || opsArray->empty())
                                    {
                                        LOG_WARNING("Offsets: update op has empty operations array (#{} file='{}')", i, path);
                                        continue;
                                    }

                                    json::Json operations;
                                    operations.setArray();
                                    for (const auto& op : *opsArray)
                                    {
                                        operations.appendJson(json::Json(op));
                                    }

                                    bool updated = updateAsset(resourceId, operations);
                                    if (updated)
                                    {
                                        LOG_TRACE("Offsets: updated asset resource='{}' (#{} offset={})",
                                                  resourceId,
                                                  i,
                                                  currentOffset);
                                        ++storedItems;
                                    }
                                    else
                                    {
                                        LOG_WARNING("Offsets: failed to update asset resource='{}' (#{} file='{}' offset={})",
                                                    resourceId,
                                                    i,
                                                    path,
                                                    currentOffset);
                                    }
                                }
                                else if (operationType == "delete")
                                {
                                    // Get resource ID for deletion
                                    const auto resourceId = entryJson.getString("/resource").value_or("");
                                    if (resourceId.empty())
                                    {
                                        LOG_WARNING("Offsets: delete op missing resource ID (#{} file='{}')", i, path);
                                        continue;
                                    }

                                    bool deleted = deleteAsset(resourceId);
                                    if (deleted)
                                    {
                                        LOG_TRACE("Offsets: deleted asset resource='{}' (#{} offset={})",
                                                  resourceId,
                                                  i,
                                                  currentOffset);
                                        ++storedItems;
                                    }
                                    else
                                    {
                                        LOG_WARNING("Offsets: failed to delete asset resource='{}' (#{} file='{}' offset={})",
                                                    resourceId,
                                                    i,
                                                    path,
                                                    currentOffset);
                                    }
                                }
                                else
                                {
                                    LOG_WARNING("Offsets: unknown operation '{}' for asset='{}' (#{} file='{}')",
                                                operationType,
                                                assetType,
                                                i,
                                                path);
                                    continue;
                                }
                            }
                            catch (const std::exception& e)
                            {
                                LOG_ERROR("Error parsing offsets entry #{} in '{}': {}", i, path, e.what());
                            }
                        }
                    }
                    catch (const std::exception& e)
                    {
                        LOG_ERROR("Error parsing offsets root in '{}': {}", path, e.what());
                        success = false;
                    }
                }
            }
            LOG_DEBUG("CTI offsets summary: files={} entries={} stored_items={} final_offset={}",
                      pathCount,
                      totalEntries,
                      storedItems,
                      currentOffset);
        }
        else if (type == "raw")
        {
            // Snapshot download: expect exactly one consolidated file.
            if (pathCount != 1)
            {
                throw std::runtime_error("Raw message must contain exactly one path");
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

                // Check if stop was requested
                if (m_downloader && m_downloader->shouldStop())
                {
                    LOG_INFO("CTI snapshot: processing interrupted by stop request at line {} (offset={})",
                             lineNumber, currentOffset);
                    // Return current progress - offset will be saved so we can resume later
                    return {currentOffset, hash, true};
                }

                if (line.empty())
                    continue;
                try
                {
                    json::Json content(line.c_str());
                    if (!content.exists("/offset") || !content.exists("/name"))
                    {
                        LOG_WARNING("Raw: entry missing required fields offset or name ({}:{})", path, lineNumber);
                        continue;
                    }

                    // Offsets are not always in order, so we need to get the highest offset.
                    currentOffset = std::max(currentOffset, content.getInt("/offset").value_or(0));

                    content.setString("create", "/type");

                    auto contentType = content.getString("/payload/type").value_or("");
                    if (!contentType.empty())
                    {
                        bool stored = true;
                        if (contentType == "policy")
                        {
                            stored = storePolicy(content);
                        }
                        else if (contentType == "integration")
                        {
                            stored = storeIntegration(content);
                        }
                        else if (contentType == "decoder")
                        {
                            stored = storeDecoder(content);
                        }
                        else if (contentType == "kvdb")
                        {
                            stored = storeKVDB(content);
                        }
                        else
                        {
                            LOG_WARNING("Raw: unknown content type '{}' ({}:{})", contentType, path, lineNumber);
                        }

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

        // Notify CMSync if content was successfully deployed
        if (success && m_deployCallback)
        {
            try
            {
                LOG_DEBUG("CTI: notifying deploy callback");
                m_deployCallback(shared_from_this());
            }
            catch (const std::exception& e)
            {
                LOG_ERROR("CTI: deploy callback failed: {}", e.what());
            }
        }

        return {currentOffset, hash, success};
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Error processing downloaded content: {}", e.what());
        return {0, "", false};
    }
}

bool ContentManager::storePolicy(const json::Json& policyData)
{
    try
    {
        if (!m_storage || !m_storage->isOpen())
        {
            LOG_ERROR("storePolicy called but storage not initialized");
            return false;
        }
        m_storage->storePolicy(policyData);
        auto name = policyData.getString("/name").value_or("");
        LOG_TRACE("Stored policy '{}'", name);
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to store policy: {}", e.what());
        return false;
    }
}

bool ContentManager::storeIntegration(const json::Json& integration)
{
    try
    {
        if (!m_storage || !m_storage->isOpen())
        {
            LOG_ERROR("storeIntegration called but storage not initialized");
            return false;
        }
        m_storage->storeIntegration(integration);
        auto name = integration.getString("/name").value_or("");
        auto title = integration.getString("/payload/document/title").value_or("");
        LOG_TRACE("Stored integration name='{}' title='{}'", name, title);
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
    try
    {
        if (!m_storage || !m_storage->isOpen())
        {
            LOG_ERROR("storeDecoder called but storage not initialized");
            return false;
        }
        m_storage->storeDecoder(decoder);
        auto name = decoder.getString("/name").value_or("");
        auto module = decoder.getString("/payload/document/metadata/module").value_or("");
        LOG_TRACE("Stored decoder name='{}' module='{}'", name, module);
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
    try
    {
        if (!m_storage || !m_storage->isOpen())
        {
            LOG_ERROR("storeKVDB called but storage not initialized");
            return false;
        }
        m_storage->storeKVDB(kvdbData);
        auto name = kvdbData.getString("/name").value_or("");
        auto integration =
            kvdbData.getString("/integration_id").value_or(kvdbData.getString("/payload/integration_id").value_or(""));
        LOG_TRACE("Stored KVDB '{}' (integration='{}')", name, integration);
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to store KVDB: {}", e.what());
        return false;
    }
}

bool ContentManager::deleteAsset(const std::string& resourceId)
{
    try
    {
        if (!m_storage || !m_storage->isOpen())
        {
            LOG_ERROR("deleteAsset called but storage not initialized");
            return false;
        }

        bool deleted = m_storage->deleteAsset(resourceId);
        if (deleted)
        {
            LOG_DEBUG("Deleted asset with resource ID: {}", resourceId);
        }
        else
        {
            LOG_TRACE("Asset with resource ID '{}' not found for deletion", resourceId);
        }
        return deleted;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to delete asset '{}': {}", resourceId, e.what());
        return false;
    }
}

bool ContentManager::updateAsset(const std::string& resourceId, const json::Json& operations)
{
    try
    {
        if (!m_storage || !m_storage->isOpen())
        {
            LOG_ERROR("updateAsset called but storage not initialized");
            return false;
        }

        bool updated = m_storage->updateAsset(resourceId, operations);
        if (updated)
        {
            LOG_DEBUG("Updated asset with resource ID: {}", resourceId);
        }
        else
        {
            LOG_TRACE("Asset with resource ID '{}' not found for update", resourceId);
        }
        return updated;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to update asset '{}': {}", resourceId, e.what());
        return false;
    }
}

} // namespace cti::store
