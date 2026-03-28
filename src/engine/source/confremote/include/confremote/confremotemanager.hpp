#ifndef CONFREMOTE_CONFREMOTEMANAGER_HPP
#define CONFREMOTE_CONFREMOTEMANAGER_HPP

#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include <base/json.hpp>
#include <confremote/iconfremote.hpp>
#include <store/istore.hpp>
#include <wiconnector/iwindexerconnector.hpp>

namespace confremote
{

/**
 * @brief Runtime remote configuration manager.
 *
 * On construction, loads the last persisted settings from store. Modules register
 * per-key callbacks via addTrigger(). On each synchronize() call, fetches the
 * current settings from wazuh-indexer, applies accepted changes through the
 * registered callbacks, and persists successful updates to store.
 */
class ConfRemoteManager final : public IConfRemote
{
public:
    /**
     * @brief Runtime remote configuration manager.
     *
     * Loads the last persisted runtime settings from store, registers per-key
     * callbacks, and synchronizes updated values from wazuh-indexer.
     *
     * @param indexerConnector Shared pointer to the indexer connector for fetching remote settings.
     * @param store Shared pointer to the internal store for persisting settings.
     * @param attempts Number of attempts to connect or retry operations before failing.
     * @param waitSeconds Seconds to wait between attempts.
     */
    explicit ConfRemoteManager(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerConnector,
                               const std::shared_ptr<store::IStore>& store,
                               const size_t attempts,
                               const size_t waitSeconds);

    /**
     * @brief Synchronizes runtime settings from wazuh-indexer.
     */
    void synchronize() override;

    /**
     * @brief Registers a callback trigger for a runtime setting key.
     *
     * Returns the last persisted value for the key if available,
     * otherwise returns the provided default value.
     *
     * @param key Setting key.
     * @param onConfigChange Callback invoked with the candidate value. Throw to reject and keep current value.
     * @param defaultValue Fallback value returned when no persisted value is available.
     * @return json::Json Persisted value or provided default value.
     */
    json::Json addTrigger(std::string_view key,
                          std::function<void(const json::Json&)> onConfigChange,
                          const json::Json& defaultValue);

private:
    /**
     * @brief Per-setting runtime binding and last applied value.
     */
    struct SettingEntry
    {
        std::optional<json::Json> lastConfig;
        std::function<void(const json::Json&)> onConfigChange;
    };

    void loadSettingsFromStore();
    void saveSettingsToStore() const;

    std::weak_ptr<wiconnector::IWIndexerConnector> m_indexerConnector;
    std::weak_ptr<store::IStore> m_store;
    mutable std::shared_mutex m_mutex;
    std::unordered_map<std::string, SettingEntry> m_settings;
    std::size_t m_attempts;
    std::size_t m_waitSeconds;
};

} // namespace confremote

#endif // CONFREMOTE_CONFREMOTEMANAGER_HPP
