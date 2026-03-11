#include <exception>
#include <utility>

#include <base/error.hpp>
#include <base/logging.hpp>
#include <base/name.hpp>
#include <base/utils/metaHelpers.hpp>
#include <confremote/confremotemanager.hpp>
#include <store/istore.hpp>

namespace confremote
{

namespace
{
const base::Name REMOTE_CONF_CACHE_DOC {"remote-config/engine-cnf/0"};
}

ConfRemoteManager::ConfRemoteManager(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerConnector,
                                     const std::shared_ptr<store::IStore>& store)
    : m_indexerConnector(indexerConnector)
    , m_store(store)
    , m_attempts(3)
    , m_waitSeconds(5)
{
    if (store->existsDoc(REMOTE_CONF_CACHE_DOC))
    {
        loadSettingsFromStore();
    }
}

void ConfRemoteManager::synchronize()
{
    json::Json remoteSettings;

    try
    {
        auto connector = base::utils::lockWeakPtr(m_indexerConnector, "IndexerConnector");
        remoteSettings = base::utils::executeWithRetry([&connector]() { return connector->getEngineRemoteConfig(); },
                                                       "synchronize",
                                                       "ConfRemoteManager",
                                                       m_attempts,
                                                       m_waitSeconds);
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("Failed to synchronize remote settings. Keeping current state.");
        LOG_DEBUG("Synchronize failure detail: {}.", e.what());
        return;
    }

    const auto fields = remoteSettings.getObject();
    if (!fields.has_value())
    {
        LOG_WARNING("Remote config payload is not a valid JSON object. Skipping synchronize.");
        return;
    }

    bool stateChanged = false;
    std::unique_lock lock(m_mutex);

    for (const auto& [key, value] : fields.value())
    {
        const auto it = m_settings.find(key);
        if (it == m_settings.end() || !it->second.onConfigChange)
        {
            LOG_DEBUG("Ignoring unregistered remote setting '{}'.", key);
            continue;
        }

        if (it->second.lastConfig.has_value() && it->second.lastConfig.value() == value)
        {
            continue;
        }

        try
        {
            if (!it->second.onConfigChange(value))
            {
                LOG_WARNING("Remote setting '{}' was rejected. Keeping current value.", key);
                continue;
            }
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Remote setting '{}' failed to apply: {}", key, e.what());
            continue;
        }

        it->second.lastConfig.emplace(value);
        stateChanged = true;
    }

    if (stateChanged)
    {
        LOG_INFO("Remote settings synchronized: changes detected and applied.");
        try
        {
            saveSettingsToStore();
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Failed to persist remote settings cache: {}", e.what());
        }
    }
}

json::Json ConfRemoteManager::addTrigger(std::string_view key,
                                         std::function<bool(const json::Json&)> onConfigChange,
                                         const json::Json& defaultValue)
{
    std::unique_lock lock(m_mutex);

    auto& setting = m_settings[std::string(key)];
    setting.onConfigChange = std::move(onConfigChange);

    return setting.lastConfig.has_value() ? setting.lastConfig.value() : defaultValue;
}

void ConfRemoteManager::loadSettingsFromStore()
{
    const auto docResp = m_store.lock()->readDoc(REMOTE_CONF_CACHE_DOC);
    if (base::isError(docResp))
    {
        throw std::runtime_error(
            fmt::format("Failed to load remote settings from store: {}", base::getError(docResp).message));
    }

    const auto& cached = base::getResponse(docResp);
    if (!cached.isObject())
    {
        throw std::runtime_error("Remote settings cache is corrupted (expected JSON object).");
    }

    const auto fields = cached.getObject();
    if (!fields.has_value())
    {
        return;
    }

    for (const auto& [key, value] : fields.value())
    {
        m_settings[key].lastConfig.emplace(value);
    }
}

void ConfRemoteManager::saveSettingsToStore() const
{
    json::Json persisted;
    persisted.setObject();

    for (const auto& [key, setting] : m_settings)
    {
        if (!setting.lastConfig.has_value())
        {
            continue;
        }
        persisted.set(fmt::format("/{}", key), setting.lastConfig.value());
    }

    auto storePtr = base::utils::lockWeakPtr(m_store, "StoreInternal");
    if (auto err = storePtr->upsertDoc(REMOTE_CONF_CACHE_DOC, persisted); base::isError(err))
    {
        throw std::runtime_error(
            fmt::format("Failed to save remote settings to store: {}", base::getError(err).message));
    }
}

} // namespace confremote
