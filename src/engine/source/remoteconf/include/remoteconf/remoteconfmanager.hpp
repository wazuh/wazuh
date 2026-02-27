#ifndef REMOTECONF_REMOTECONFMANAGER_HPP
#define REMOTECONF_REMOTECONFMANAGER_HPP

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include <base/json.hpp>
#include <remoteconf/iremoteconf.hpp>
#include <wiconnector/iwindexerconnector.hpp>

namespace store
{
class IStore;
}

namespace remoteconf
{

/**
 * @brief Runtime remote configuration manager.
 *
 * Orchestrates startup/refresh retrieval of engine runtime settings from indexer,
 * applies accepted per-key changes through registered callbacks, and persists a
 * normalized cache copy in store for startup fallback.
 */
class RemoteConfManager final : public IRemoteConf
{
public:
    /**
     * @brief Constructs a remote configuration manager.
     *
     * @param connector Indexer connector used to fetch remote engine settings.
     * @param cacheStore Optional store backend used for local cache persistence.
     */
    explicit RemoteConfManager(std::shared_ptr<wiconnector::IWIndexerConnector> connector,
                               std::shared_ptr<store::IStore> cacheStore = {});

    /**
     * @brief Initializes runtime settings from remote source/cache/defaults.
     */
    void initialize() override;

    /**
     * @brief Refreshes runtime settings from the remote source.
     */
    void refresh() override;

    /**
     * @brief Registers a callback trigger for a runtime setting key.
     *
     * @param key Setting key (flattened path style).
     * @param onChange Callback invoked with the candidate value. Return true to accept/apply it.
     * @param defaultValue Fallback value applied when no remote/cache value is available.
     */
    void addTrigger(std::string_view key,
                    std::function<bool(const json::Json& cnf)> onChange,
                    const json::Json& defaultValue) override;

private:
    /**
     * @brief Per-setting runtime binding and last applied value.
     */
    struct SettingEntry
    {
        json::Json defaultValue;
        std::function<bool(const json::Json&)> onChange;
        std::optional<json::Json> currentValue;
    };

    using SettingsMap = std::unordered_map<std::string, json::Json>;

    static bool flattenObject(const json::Json& object, std::string& path, SettingsMap& out);
    std::optional<SettingsMap> parseSource(const json::Json& source) const;
    void syncRemoteSettings(const SettingsMap& remoteSettings);
    void fillMissingWithDefaults();
    std::optional<json::Json> readCachedSettings() const;
    void updateCachedSettings(const json::Json& settings) const;

    std::shared_ptr<wiconnector::IWIndexerConnector> m_connector;
    std::shared_ptr<store::IStore> m_cacheStore;

    std::mutex m_operationMutex;
    std::shared_mutex m_entriesMutex;
    std::unordered_map<std::string, SettingEntry> m_entries;
    std::optional<json::Json> m_lastSettingsSnapshot;

    std::atomic<bool> m_initialized {false};
};

} // namespace remoteconf

#endif // REMOTECONF_REMOTECONFMANAGER_HPP
