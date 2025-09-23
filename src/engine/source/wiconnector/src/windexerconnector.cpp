#include <indexerConnector.hpp>
#include <json.hpp>

#include <base/logging.hpp>

#include <wiconnector/windexerconnector.hpp>

namespace wiconnector
{

/****************************************************************************************
 * Config class implementation
 ****************************************************************************************/

/*
 * Example:
 * {
 *   "hosts": [
 *     "http://10.2.20.2:9200",
 *     "https://10.2.20.42:9200"
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
std::string Config::toJson() const
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
 * Wrapper of IndexerConnector class implementation
 ****************************************************************************************/
WIndexerConnector::WIndexerConnector(std::string_view jsonOssecConfig)
{
    if (jsonOssecConfig.empty())
    {
        throw std::runtime_error("Empty JSON configuration for IndexerConnector");
    }

    const auto jsonParsed = nlohmann::json::parse(jsonOssecConfig, nullptr, false);
    if (jsonParsed.is_discarded())
    {
        throw std::runtime_error("Invalid JSON configuration for IndexerConnector");
    }

    const auto logFunction = logging::createStandaloneLogFunction();
    m_indexerConnectorAsync = std::make_unique<IndexerConnectorAsync>(jsonParsed, logFunction);
}

WIndexerConnector::WIndexerConnector(const Config& config, const LogFunctionType& logFunction)
{
    nlohmann::json jsonConfig = nlohmann::json::parse(config.toJson(), nullptr, false);
    if (jsonConfig.is_discarded())
    {
        throw std::runtime_error("Invalid JSON configuration for IndexerConnector");
    }

    m_indexerConnectorAsync = std::make_unique<IndexerConnectorAsync>(jsonConfig, logFunction);
}

WIndexerConnector::~WIndexerConnector() = default;

void WIndexerConnector::shutdown()
{
    std::unique_lock lock(m_mutex);
    m_indexerConnectorAsync.reset();
}

void WIndexerConnector::index(std::string_view index, std::string_view data)
{
    std::shared_lock lock(m_mutex);
    if (m_indexerConnectorAsync)
    {
        try {
            m_indexerConnectorAsync->index(index, data);
        }
        catch (const IndexerConnectorException& e) {
            LOG_WARNING("Error indexing data: %s", e.what());
            return;
        }
        catch (const std::exception& e) {
            LOG_WARNING("Error indexing data: %s", e.what());
            return;
        }
    }
    else
    {
        LOG_DEBUG("IndexerConnectorAsync shutdown, cannot index data");
    }
}
}; // namespace wiconnector
