#include <quickwitConnector.hpp>
#include <json.hpp>

#include <base/logging.hpp>

#include <wiconnector/wquickwitconnector.hpp>

namespace wiconnector
{

/****************************************************************************************
 * QuickwitConfig class implementation
 ****************************************************************************************/

/*
 * Example:
 * {
 *   "hosts": [
 *     "http://10.2.20.2:7280",
 *     "http://10.2.20.42:7280"
 *   ],
 *   "ssl": {
 *     "certificate_authorities": [
 *       "/var/ossec/",
 *       "/var/ossec_cert/"
 *     ],
 *     "certificate": "cert",
 *     "key": "key_example"
 *   }
 * }
 */
std::string QuickwitConfig::toJson() const
{
    nlohmann::json config {};
    config["hosts"] = hosts;
    if (!username.empty() && !password.empty())
    {
        config["username"] = username;
        config["password"] = password;
    }

    if (!ssl.cacert.empty() || !ssl.cert.empty() || !ssl.key.empty())
    {
        nlohmann::json sslJson {};
        if (!ssl.cacert.empty())
        {
            sslJson["certificate_authorities"] = ssl.cacert;
        }
        if (!ssl.cert.empty())
        {
            sslJson["certificate"] = ssl.cert;
        }
        if (!ssl.key.empty())
        {
            sslJson["key"] = ssl.key;
        }
        config["ssl"] = sslJson;
    }

    return config.dump();
}

/****************************************************************************************
 * Wrapper of QuickwitConnector class implementation
 ****************************************************************************************/
WQuickwitConnector::WQuickwitConnector(std::string_view jsonOssecConfig)
{
    if (jsonOssecConfig.empty())
    {
        throw std::runtime_error("Empty JSON configuration for QuickwitConnector");
    }

    const auto jsonParsed = nlohmann::json::parse(jsonOssecConfig, nullptr, false);
    if (jsonParsed.is_discarded())
    {
        throw std::runtime_error("Invalid JSON configuration for QuickwitConnector");
    }

    const auto logFunction = logging::createStandaloneLogFunction();
    m_quickwitConnectorAsync = std::make_unique<QuickwitConnectorAsync>(jsonParsed, logFunction);
}

WQuickwitConnector::WQuickwitConnector(const QuickwitConfig& config, const LogFunctionType& logFunction)
{
    nlohmann::json jsonConfig = nlohmann::json::parse(config.toJson(), nullptr, false);
    if (jsonConfig.is_discarded())
    {
        throw std::runtime_error("Invalid JSON configuration for QuickwitConnector");
    }

    m_quickwitConnectorAsync = std::make_unique<QuickwitConnectorAsync>(jsonConfig, logFunction);
}

WQuickwitConnector::~WQuickwitConnector() = default;

void WQuickwitConnector::shutdown()
{
    std::unique_lock lock(m_mutex);
    m_quickwitConnectorAsync.reset();
}

void WQuickwitConnector::index(std::string_view index, std::string_view data)
{
    std::shared_lock lock(m_mutex);
    if (m_quickwitConnectorAsync)
    {
        try {
            m_quickwitConnectorAsync->index(index, data);
        }
        catch (const QuickwitConnectorException& e) {
            LOG_WARNING("Error indexing data to Quickwit: %s", e.what());
            return;
        }
        catch (const std::exception& e) {
            LOG_WARNING("Error indexing data to Quickwit: %s", e.what());
            return;
        }
    }
    else
    {
        LOG_DEBUG("QuickwitConnectorAsync shutdown, cannot index data");
    }
}
}; // namespace wiconnector
