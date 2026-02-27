#include <exception>
#include <utility>
#include <vector>

#include <base/error.hpp>
#include <base/logging.hpp>
#include <base/name.hpp>
#include <remoteconf/remoteconfmanager.hpp>
#include <store/istore.hpp>

namespace remoteconf
{

namespace
{
const base::Name REMOTE_CONF_CACHE_DOC {"remote-config/engine-cnf/0"};
}

RemoteConfManager::RemoteConfManager(std::shared_ptr<wiconnector::IWIndexerConnector> connector,
                                     std::shared_ptr<store::IStore> cacheStore)
    : m_connector(std::move(connector))
    , m_cacheStore(std::move(cacheStore))
{
}

void RemoteConfManager::initialize()
{
    std::lock_guard<std::mutex> lock(m_operationMutex);
    if (m_initialized.load(std::memory_order_acquire))
    {
        return;
    }

    bool applied = false;

    if (m_connector)
    {
        try
        {
            const auto remoteSettings = m_connector->getRemoteConfigEngine();
            const auto parsedSettings = parseSource(remoteSettings);
            if (parsedSettings.has_value())
            {
                syncRemoteSettings(parsedSettings.value());
                m_lastSettingsSnapshot = remoteSettings;
                updateCachedSettings(remoteSettings);
                applied = true;
                LOG_INFO("Remote settings initialized successfully.");
            }
            else
            {
                LOG_WARNING("Remote settings payload is invalid on initialize. Trying local cache.");
            }
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Failed to fetch remote settings on initialize (reason: {}). Trying local cache.", e.what());
        }
    }
    else
    {
        LOG_WARNING("RemoteConfManager has no indexer connector. Trying local cache.");
    }

    if (!applied)
    {
        LOG_INFO("Checking local cache for remote settings.");
        const auto cached = readCachedSettings();
        if (cached.has_value())
        {
            const auto parsedSettings = parseSource(cached.value());
            if (parsedSettings.has_value())
            {
                syncRemoteSettings(parsedSettings.value());
                m_lastSettingsSnapshot = cached.value();
                applied = true;
                LOG_INFO("Remote settings applied from local cache.");
            }
            else
            {
                LOG_WARNING("Remote settings cache document is invalid. Ignoring cache.");
            }
        }

        if (!applied)
        {
            LOG_INFO("No remote settings applied from source/cache. Applying defaults for registered keys.");
        }
    }

    fillMissingWithDefaults();
    m_initialized.store(true, std::memory_order_release);
}

void RemoteConfManager::refresh()
{
    std::lock_guard<std::mutex> lock(m_operationMutex);
    if (!m_initialized.load(std::memory_order_acquire))
    {
        return;
    }

    if (!m_connector)
    {
        LOG_WARNING("RemoteConfManager has no indexer connector. Refresh is skipped.");
        return;
    }

    json::Json remoteSettings;
    try
    {
        remoteSettings = m_connector->getRemoteConfigEngine();
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("Failed to fetch remote settings during refresh (reason: {}). Keeping current state.", e.what());
        return;
    }

    const auto parsedSettings = parseSource(remoteSettings);
    if (!parsedSettings.has_value())
    {
        LOG_WARNING("Remote settings payload is invalid during refresh. Keeping current state.");
        return;
    }

    if (m_lastSettingsSnapshot.has_value() && m_lastSettingsSnapshot.value() == remoteSettings)
    {
        LOG_INFO("Remote settings unchanged during refresh. Keeping current state.");
        return;
    }

    syncRemoteSettings(parsedSettings.value());
    m_lastSettingsSnapshot = remoteSettings;
    updateCachedSettings(remoteSettings);
    LOG_INFO("Remote settings: changes detected, updating.");
}

void RemoteConfManager::addTrigger(std::string_view key,
                                   std::function<bool(const json::Json&)> onChange,
                                   const json::Json& defaultValue)
{
    std::unique_lock<std::shared_mutex> lock(m_entriesMutex);
    auto& entry = m_entries[std::string(key)];
    entry.defaultValue = json::Json(defaultValue);
    entry.onChange = std::move(onChange);
}

bool RemoteConfManager::flattenObject(const json::Json& object, std::string& path, SettingsMap& out)
{
    const auto fields = object.getObject();
    if (!fields.has_value())
    {
        return false;
    }

    for (const auto& [name, value] : fields.value())
    {
        const auto prev = path.size();
        if (!path.empty())
        {
            path.push_back('.');
        }
        path += name;

        if (value.isObject())
        {
            if (!flattenObject(value, path, out))
            {
                return false;
            }
        }
        else
        {
            out.emplace(path, value);
        }

        path.resize(prev);
    }

    return true;
}

std::optional<RemoteConfManager::SettingsMap> RemoteConfManager::parseSource(const json::Json& source) const
{
    if (!source.isObject())
    {
        return std::nullopt;
    }

    SettingsMap result;
    std::string path;
    if (!flattenObject(source, path, result))
    {
        return std::nullopt;
    }

    return result;
}

void RemoteConfManager::syncRemoteSettings(const SettingsMap& remoteSettings)
{
    std::vector<std::pair<std::string, SettingEntry>> entriesSnapshot;
    {
        std::shared_lock<std::shared_mutex> lock(m_entriesMutex);
        entriesSnapshot.reserve(m_entries.size());
        for (const auto& [key, entry] : m_entries)
        {
            entriesSnapshot.emplace_back(key, entry);
        }
    }

    for (const auto& [key, entry] : entriesSnapshot)
    {
        const auto remoteIt = remoteSettings.find(key);
        if (remoteIt == remoteSettings.end())
        {
            if (entry.currentValue.has_value())
            {
                LOG_WARNING("Remote setting '{}' removed from payload. Keeping current value.", key);
            }
            continue;
        }

        const auto& value = remoteIt->second;
        if (entry.currentValue.has_value() && entry.currentValue.value() == value)
        {
            continue;
        }

        if (!entry.onChange || !entry.onChange(value))
        {
            continue;
        }

        std::unique_lock<std::shared_mutex> lock(m_entriesMutex);
        const auto it = m_entries.find(key);
        if (it == m_entries.end())
        {
            continue;
        }

        it->second.currentValue = json::Json(value);
    }
}

void RemoteConfManager::fillMissingWithDefaults()
{
    std::vector<std::pair<std::string, SettingEntry>> entriesSnapshot;
    {
        std::shared_lock<std::shared_mutex> lock(m_entriesMutex);
        entriesSnapshot.reserve(m_entries.size());
        for (const auto& [key, entry] : m_entries)
        {
            entriesSnapshot.emplace_back(key, entry);
        }
    }

    for (const auto& [key, entry] : entriesSnapshot)
    {
        if (entry.currentValue.has_value())
        {
            continue;
        }

        if (!entry.onChange || !entry.onChange(entry.defaultValue))
        {
            continue;
        }

        std::unique_lock<std::shared_mutex> lock(m_entriesMutex);
        const auto it = m_entries.find(key);
        if (it == m_entries.end() || it->second.currentValue.has_value())
        {
            continue;
        }

        it->second.currentValue = json::Json(entry.defaultValue);
    }
}

std::optional<json::Json> RemoteConfManager::readCachedSettings() const
{
    if (!m_cacheStore)
    {
        return std::nullopt;
    }

    const auto docResp = m_cacheStore->readDoc(REMOTE_CONF_CACHE_DOC);
    if (base::isError(docResp))
    {
        LOG_INFO("Remote settings cache not available: {}", base::getError(docResp).message);
        return std::nullopt;
    }

    const auto& cached = base::getResponse(docResp);
    if (!cached.isObject())
    {
        LOG_WARNING("Remote settings cache is corrupted (expected JSON object).");
        return std::nullopt;
    }

    return cached;
}

void RemoteConfManager::updateCachedSettings(const json::Json& settings) const
{
    if (!m_cacheStore)
    {
        return;
    }

    if (auto err = m_cacheStore->upsertDoc(REMOTE_CONF_CACHE_DOC, settings); base::isError(err))
    {
        LOG_WARNING("Failed to persist remote settings cache: {}", base::getError(err).message);
    }
}

} // namespace remoteconf
