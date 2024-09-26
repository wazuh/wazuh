#include <config/config.hpp>

#include <unistd.h>

#include <fmt/format.h>

namespace {
std::string getExecutablePath()
{
    char path[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", path, PATH_MAX);
    if (count != -1)
    {
        path[count] = '\0';
        std::string pathStr(path);
        return pathStr.substr(0, pathStr.find_last_of('/'));
    }
    return {};
}
}

namespace config
{

using namespace internal;

Config::Config()
{

    // Register aviation configuration units

    // Logging module
    m_units["/logging/level"] = UConf<std::string>::make("WAZUH_LOGGING_LEVEL", "info");


    // Store module
    m_units["/store/path"] = UConf<std::string>::make("WAZUH_STORE_PATH", "/var/wazuh/store");

    // KVDB module
    m_units["/kvdb/path"] = UConf<std::string>::make("WAZUH_KVDB_PATH", "/var/wazuh/kvdb");

    // Indexer connector
    m_units["/indexer/index"] = UConf<std::string>::make("WAZUH_INDEXER_INDEX", "wazuh-alerts-5x");
    m_units["/indexer/host"] = UConf<std::vector<std::string>>::make("WAZUH_INDEXER_HOST", {"http://127.0.0.1:9200"});
    m_units["/indexer/user"] = UConf<std::string>::make("WAZUH_INDEXER_USER", "admin");
    m_units["/indexer/password"] = UConf<std::string>::make("WAZUH_INDEXER_PASSWORD", "WazuhEngine5+");
    m_units["/indexer/ssl/certificate_authorities"] =
        UConf<std::string>::make("WAZUH_INDEXER_SSL_CERTIFICATE_AUTHORITIES", "");
    m_units["/indexer/ssl/certificate"] = UConf<std::string>::make("WAZUH_INDEXER_SSL_CERTIFICATE", "");
    m_units["/indexer/ssl/key"] = UConf<std::string>::make("WAZUH_INDEXER_SSL_KEY", "");

    // Queue module
    m_units["/queue/size"] = UConf<int>::make("WAZUH_QUEUE_SIZE", 1000000);
    // If file is "" the queue will block until the event is pushed to the queue.
    m_units["/queue/flood_file"] =
        UConf<std::string>::make("WAZUH_QUEUE_FLOOD_FILE", "/var/wazuh/logs/engine-flood.log");
    // Number of attempts to try to push an event to the queue.
    m_units["/queue/flood_attempts"] = UConf<int>::make("WAZUH_QUEUE_FLOOD_ATTEMPTS", 3);
    // Microseconds to sleep between attempts to push an event to the queue.
    m_units["/queue/flood_sleep"] = UConf<int>::make("WAZUH_QUEUE_FLOOD_SLEEP", 100);
    // If enabled, the queue will drop the flood events instead of storing them in the file.
    m_units["/queue/drop_on_flood"] = UConf<bool>::make("WAZUH_QUEUE_DROP_ON_FLOOD", false);

    // Orchestrator module
    m_units["/orchestrator/threads"] = UConf<int>::make("WAZUH_ORCHESTRATOR_THREADS", 1);

    // OLD Server module
    // TODO Deprecate this configuration after the migration to the new httplib server
    m_units["/server/thread_pool_size"] = UConf<int>::make("WAZUH_SERVER_THREAD_POOL_SIZE", 1);
    m_units["/server/event_socket"] =
        UConf<std::string>::make("WAZUH_SERVER_EVENT_SOCKET", "/var/wazuh/sockets/old-queue.sock");
    m_units["/server/event_queue_size"] = UConf<int>::make("WAZUH_SERVER_EVENT_QUEUE_SIZE", 0);

    m_units["/server/api_socket"] =
        UConf<std::string>::make("WAZUH_SERVER_API_SOCKET", "/var/wazuh/sockets/old-api.sock");
    m_units["/server/api_queue_size"] = UConf<int>::make("WAZUH_SERVER_API_QUEUE_SIZE", 50);
    m_units["/server/api_timeout"] = UConf<int>::make("WAZUH_SERVER_API_TIMEOUT", 5000);

    // New API Server module
    m_units["/api_server/socket"] = UConf<std::string>::make("WAZUH_API_SERVER_SOCKET", getExecutablePath() + "/sockets/api.sock");

    // TZDB module
    m_units["/tzdb/path"] = UConf<std::string>::make("WAZUH_TZDB_PATH", getExecutablePath() + "/tzdb");
    m_units["/tzdb/auto_update"] = UConf<bool>::make("WAZUH_TZDB_AUTO_UPDATE", false);
};

json::Json Config::loadFromAPI() const
{
    // TODO: Connect to the framework API to get the configuration
    return json::Json("{}");
}

void Config::validate(const json::Json& config) const
{
    for (const auto& [key, value] : m_units)
    {
        if (!config.exists(key))
        {
            continue; // The configuration is not set for this key, ignore it
        }

        const auto unitType = value->getType();
        switch (unitType)
        {
            case UnitConfType::INTEGER:
                if (config.isInt(key) || config.isInt64(key))
                {
                    continue;
                }
                throw std::runtime_error(fmt::format(
                    "Invalid configuration type for key '{}'. Expected integer, got '{}'.", key, config.str(key).value_or("errorValue")));
            case UnitConfType::STRING:
                if (config.isString(key))
                {
                    continue;
                }
                throw std::runtime_error(fmt::format(
                    "Invalid configuration type for key '{}'. Expected string, got '{}'.", key, config.str(key).value_or("errorValue")));
            case UnitConfType::STRING_LIST:
                if (config.isArray(key))
                {
                    auto jArr = config.getArray(key).value();

                    for (const auto& item : jArr)
                    {
                        if (!item.isString())
                        {
                            throw std::runtime_error(
                                fmt::format("Invalid configuration type for key '{}'. Expected string, got '{}'.",
                                            key,
                                            item.str()));
                        }
                    }
                    continue;
                }
                throw std::runtime_error(
                    fmt::format("Invalid configuration type for key '{}'. Expected array of strings, got '{}'.",
                                key,
                                config.str(key).value_or("errorValue")));
            case UnitConfType::BOOL:
                if (config.isBool(key))
                {
                    continue;
                }
                throw std::runtime_error(fmt::format(
                    "Invalid configuration type for key '{}'. Expected boolean, got '{}'.", key, config.str(key).value_or("errorValue")));
            default: throw std::runtime_error(fmt::format("Invalid configuration type for key '{}'.", key));
        }
    }
}

void Config::load()
{
    auto apiConfig = loadFromAPI();
    validate(apiConfig);
    m_apiConfig = std::move(apiConfig);
}

} // namespace config
