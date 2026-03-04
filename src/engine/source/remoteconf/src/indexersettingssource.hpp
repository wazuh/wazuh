#ifndef REMOTECONF_INDEXERSETTINGSSOURCE_HPP
#define REMOTECONF_INDEXERSETTINGSSOURCE_HPP

#include <memory>
#include <string_view>

#include <remoteconf/isettingssource.hpp>
#include <wiconnector/iwindexerconnector.hpp>

namespace remoteconf
{

class IndexerSettingsSource final : public ISettingsSource
{
public:
    explicit IndexerSettingsSource(std::shared_ptr<wiconnector::IWIndexerConnector> connector);

    SettingsFetchResult fetchSettings() override;

private:
    std::shared_ptr<wiconnector::IWIndexerConnector> m_connector;

    static constexpr std::string_view INDEX_NAME {".wazuh-settings"};
    static constexpr std::string_view DOCUMENT_ID {"1"};
};

} // namespace remoteconf

#endif // REMOTECONF_INDEXERSETTINGSSOURCE_HPP
