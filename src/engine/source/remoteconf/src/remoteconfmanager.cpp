#include <exception>
#include <utility>

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

RemoteConfManager::RemoteConfManager(std::shared_ptr<ISettingsSource> source, std::shared_ptr<store::IStore> cacheStore)
    : m_source(std::move(source))
    , m_cacheStore(std::move(cacheStore))
{
}

void RemoteConfManager::initialize()
{
    std::lock_guard<std::mutex> lock(m_operationMutex);
    if (m_initialized)
    {
        return;
    }

    bool applied = false;

    if (m_source)
    {
        const auto fetchResult = m_source->fetchSettings();
        if (fetchResult.status == FetchStatus::Success)
        {
            const auto parsedSettings = parseSource(fetchResult.source);
            if (parsedSettings.has_value())
            {
                syncRemoteSettings(parsedSettings.value());
                m_lastSettingsSnapshot = fetchResult.source;
                updateCachedSettings(fetchResult.source);
                applied = true;
            }
            else
            {
                LOG_WARNING("Remote settings payload is invalid on initialize. Trying local cache.");
            }
        }
        else
        {
            LOG_WARNING("Failed to fetch remote settings on initialize (status: {}, reason: {}). Trying local cache.",
                        toString(fetchResult.status),
                        fetchResult.error);
        }
    }
    else
    {
        LOG_WARNING("RemoteConfManager has no settings source. Trying local cache.");
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
    m_initialized = true;
}

void RemoteConfManager::refresh()
{
    std::lock_guard<std::mutex> lock(m_operationMutex);
    if (!m_initialized)
    {
        return;
    }

    if (!m_source)
    {
        LOG_WARNING("RemoteConfManager has no settings source. Refresh is skipped.");
        return;
    }

    const auto fetchResult = m_source->fetchSettings();
    if (fetchResult.status != FetchStatus::Success)
    {
        if (fetchResult.error.empty())
        {
            LOG_WARNING("Failed to fetch remote settings during refresh (status: {}). Keeping current state.",
                        toString(fetchResult.status));
        }
        else
        {
            LOG_WARNING("Failed to fetch remote settings during refresh (status: {}, reason: {}). Keeping current "
                        "state.",
                        toString(fetchResult.status),
                        fetchResult.error);
        }
        return;
    }

    const auto parsedSettings = parseSource(fetchResult.source);
    if (!parsedSettings.has_value())
    {
        LOG_WARNING("Remote settings payload is invalid during refresh. Keeping current state.");
        return;
    }

    if (m_lastSettingsSnapshot.has_value() && m_lastSettingsSnapshot.value() == fetchResult.source)
    {
        LOG_INFO("Remote settings unchanged during refresh. Keeping current state.");
        return;
    }

    syncRemoteSettings(parsedSettings.value());
    m_lastSettingsSnapshot = fetchResult.source;
    updateCachedSettings(fetchResult.source);
}

void RemoteConfManager::addTrigger(std::string_view key,
                                   std::function<bool(const json::Json&)> onChange,
                                   const json::Json& defaultValue)
{
    std::lock_guard<std::mutex> lock(m_subscribersMutex);
    m_subscribers.insert_or_assign(std::string(key), Subscriber {json::Json(defaultValue), std::move(onChange)});
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
    std::unordered_map<std::string, Subscriber> subs;
    {
        std::lock_guard<std::mutex> lock(m_subscribersMutex);
        subs = m_subscribers;
    }

    for (const auto& [key, sub] : subs)
    {
        const auto remoteIt = remoteSettings.find(key);
        if (remoteIt == remoteSettings.end())
        {
            std::shared_lock<std::shared_mutex> lock(m_stateMutex);
            if (m_active.count(key))
            {
                LOG_WARNING("Remote setting '{}' removed from payload. Keeping current value.", key);
            }
            continue;
        }

        const auto& value = remoteIt->second;
        {
            std::shared_lock<std::shared_mutex> lock(m_stateMutex);
            const auto activeIt = m_active.find(key);
            if (activeIt != m_active.end() && activeIt->second == value)
            {
                continue;
            }
        }

        bool accepted = false;
        try
        {
            accepted = sub.onChange(value);
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Callback for '{}' threw during sync: {}", key, e.what());
            continue;
        }
        catch (...)
        {
            LOG_WARNING("Callback for '{}' threw during sync with unknown error.", key);
            continue;
        }

        if (!accepted)
        {
            continue;
        }

        std::unique_lock<std::shared_mutex> lock(m_stateMutex);
        m_active.insert_or_assign(key, json::Json(value));
    }
}

void RemoteConfManager::fillMissingWithDefaults()
{
    std::unordered_map<std::string, Subscriber> subs;
    {
        std::lock_guard<std::mutex> lock(m_subscribersMutex);
        subs = m_subscribers;
    }

    for (const auto& [key, sub] : subs)
    {
        {
            std::shared_lock<std::shared_mutex> lock(m_stateMutex);
            if (m_active.count(key))
            {
                continue;
            }
        }

        bool accepted = false;
        try
        {
            accepted = sub.onChange(sub.defaultValue);
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Callback for '{}' threw on default: {}", key, e.what());
            continue;
        }
        catch (...)
        {
            LOG_WARNING("Callback for '{}' threw on default with unknown error.", key);
            continue;
        }

        if (!accepted)
        {
            continue;
        }

        std::unique_lock<std::shared_mutex> lock(m_stateMutex);
        m_active.insert_or_assign(key, json::Json(sub.defaultValue));
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
