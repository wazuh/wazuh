#include <ctistore/cm.hpp>

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
constexpr auto CTI_STORE_LOG_TAG = "cti-store";
} // namespace

ContentManager::ContentManager(const ContentManagerConfig& config, bool autoStart)
    : m_config(config)
{
    LOG_INFO("Initializing CTI Store ContentManager");

    try
    {
        if (!m_config.basePath.empty())
        {
            std::filesystem::path base {m_config.basePath};
            const auto makeAbsolute = [&](const std::string& value) -> std::string
            {
                if (value.empty())
                    return value;
                std::filesystem::path p {value};
                if (p.is_absolute())
                    return p.string();
                return (base / p).string();
            };
            m_config.outputFolder = makeAbsolute(m_config.outputFolder);
            m_config.databasePath = makeAbsolute(m_config.databasePath);
            if (!m_config.assetStorePath.empty())
            {
                m_config.assetStorePath = makeAbsolute(m_config.assetStorePath);
            }
        }

        // Validate after normalization so that any path-dependent semantics are consistent.
        m_config.validate();
        if (m_config.databasePath.empty())
        {
            throw std::runtime_error("ContentManager: databasePath cannot be empty");
        }

        // Decide asset storage path (separate from offset DB if provided)
        const std::string assetPath = m_config.assetStorePath.empty() ? m_config.databasePath : m_config.assetStorePath;

        // Ensure directories exist prior to CTIStorageDB creation (it will also ensure internally, but we mirror
        // downloader behavior).
        if (!m_config.outputFolder.empty())
        {
            std::filesystem::create_directories(m_config.outputFolder);
        }
        std::filesystem::create_directories(m_config.databasePath); // offsets DB path (shared module)
        std::filesystem::create_directories(assetPath);             // assets DB path

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

    if (!m_storage || !m_storage->isOpen())
    {
        LOG_WARNING("getAssetList called but storage not initialized");
        return {};
    }

    const char* typeStr = nullptr;
    switch (type)
    {
        case AssetType::INTEGRATION: typeStr = "integration"; break;
        case AssetType::DECODER: typeStr = "decoder"; break;
        default: return {}; // unsupported
    }

    try
    {
        return m_storage->getAssetList(typeStr);
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("getAssetList error for type='{}': {}", typeStr, e.what());
        return {};
    }
}

json::Json ContentManager::getAsset(const base::Name& name) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    if (!m_storage || !m_storage->isOpen())
    {
        LOG_WARNING("getAsset called but storage not initialized");
        return json::Json();
    }

    // We don't know the type, try in order (policy, integration, decoder)
    static const std::vector<std::string> types {"integration", "decoder"};
    for (const auto& t : types)
    {
        try
        {
            return m_storage->getAsset(name, t);
        }
        catch (...)
        {
            // ignore and try next
        }
    }
    LOG_TRACE("Asset '{}' not found in any type", name.toStr());
    return json::Json();
}

bool ContentManager::assetExists(const base::Name& name) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    if (!m_storage || !m_storage->isOpen())
    {
        return false;
    }
    static const std::vector<std::string> types {"integration", "decoder"};
    for (const auto& t : types)
    {
        try
        {
            if (m_storage->assetExists(name, t))
            {
                return true;
            }
        }
        catch (...)
        {
            // ignore
        }
    }
    return false;
}

std::vector<std::string> ContentManager::listKVDB() const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

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
    std::shared_lock<std::shared_mutex> lock(m_mutex);

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
    std::shared_lock<std::shared_mutex> lock(m_mutex);

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
    std::shared_lock<std::shared_mutex> lock(m_mutex);

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
    std::shared_lock<std::shared_mutex> lock(m_mutex);

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

base::Name ContentManager::getPolicyDefaultParent() const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    if (!m_storage || !m_storage->isOpen())
    {
        return base::Name();
    }
    try
    {
        return m_storage->getPolicyDefaultParent();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("getPolicyDefaultParent error: {}", e.what());
        return base::Name();
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

                                if (assetType.empty())
                                {
                                    LOG_WARNING("Offsets: entry #{} missing asset type (file='{}')", i, path);
                                    continue;
                                }

                                entryJson.setString(entryJson.getString("/resource").value_or(""), "/name");

                                if (operationType == "create")
                                {
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
                                    // TODO: Implement update semantics (merge vs replace?) when persistence layer is
                                    // added
                                    LOG_TRACE("Offsets: TODO update op asset='{}' (#{} offset={})",
                                              assetType,
                                              i,
                                              currentOffset);
                                    continue; // For now do not treat update as create
                                }
                                else if (operationType == "delete")
                                {
                                    // TODO: Implement deletion semantics when storage backend is available (remove
                                    // record / tombstone)
                                    LOG_TRACE("Offsets: skip delete op asset='{}' (#{} offset={})",
                                              assetType,
                                              i,
                                              currentOffset);
                                    continue;
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
    std::unique_lock<std::shared_mutex> lock(m_mutex);

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
    std::unique_lock<std::shared_mutex> lock(m_mutex);
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
    std::unique_lock<std::shared_mutex> lock(m_mutex);
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
    std::unique_lock<std::shared_mutex> lock(m_mutex);

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

} // namespace cti::store
