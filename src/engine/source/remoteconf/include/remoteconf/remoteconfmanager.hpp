#ifndef REMOTECONF_REMOTECONFMANAGER_HPP
#define REMOTECONF_REMOTECONFMANAGER_HPP

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
#include <remoteconf/isettingssource.hpp>

namespace wiconnector
{
class IWIndexerConnector;
}

namespace store
{
class IStore;
}

namespace remoteconf
{

class RemoteConfManager final : public IRemoteConf
{
public:
    explicit RemoteConfManager(std::shared_ptr<ISettingsSource> source, std::shared_ptr<store::IStore> cacheStore = {});

    void initialize() override;
    void refresh() override;
    void addTrigger(std::string_view key,
                    std::function<bool(const json::Json& cnf)> onChange,
                    const json::Json& defaultValue) override;

private:
    struct Subscriber
    {
        json::Json defaultValue;
        std::function<bool(const json::Json&)> onChange;
    };

    using SettingsMap = std::unordered_map<std::string, json::Json>;

    static bool flattenObject(const json::Json& object, std::string& path, SettingsMap& out);
    std::optional<SettingsMap> parseSource(const json::Json& source) const;
    void syncRemoteSettings(const SettingsMap& remoteSettings);
    void fillMissingWithDefaults();
    std::optional<json::Json> readCachedSettings() const;
    void updateCachedSettings(const json::Json& settings) const;

    std::shared_ptr<ISettingsSource> m_source;
    std::shared_ptr<store::IStore> m_cacheStore;

    std::mutex m_operationMutex;
    std::shared_mutex m_stateMutex;
    SettingsMap m_active;
    std::optional<json::Json> m_lastSettingsSnapshot;

    bool m_initialized {false};

    std::mutex m_subscribersMutex;
    std::unordered_map<std::string, Subscriber> m_subscribers;
};

std::shared_ptr<ISettingsSource> makeIndexerSettingsSource(std::shared_ptr<wiconnector::IWIndexerConnector> connector);

} // namespace remoteconf

#endif // REMOTECONF_REMOTECONFMANAGER_HPP
