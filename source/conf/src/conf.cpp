#include <conf/conf.hpp>

#include <unistd.h>

#include <fmt/format.h>

#include <conf/keys.hpp>

namespace
{
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
} // namespace

namespace conf
{

using namespace internal;

Conf::Conf(std::shared_ptr<IApiLoader> apiLoader)
    : m_apiLoader(apiLoader)
    , m_apiConfig(R"(null)")
{
    if (!m_apiLoader)
    {
        throw std::invalid_argument("The API loader cannot be null.");
    }

    // Register aviablable configuration units with Default Settings

    // Logging module
    addUnit<std::string>(key::LOGGING_LEVEL, "WAZUH_LOG_LEVEL", "info");

    // Store module
    addUnit<std::string>(key::STORE_PATH, "WAZUH_STORE_PATH", "/var/lib/wazuh-server/engine/store");

    // KVDB module
    addUnit<std::string>(key::KVDB_PATH, "WAZUH_KVDB_PATH", "/var/lib/wazuh-server/engine/kvdb/");

    // Indexer connector
    addUnit<std::string>(key::INDEXER_INDEX, "WAZUH_INDEXER_INDEX", "wazuh-alerts-5.x-0001");
    addUnit<std::vector<std::string>>(key::INDEXER_HOST, "WAZUH_INDEXER_HOST", {"http://127.0.0.1:9200"});
    addUnit<std::string>(key::INDEXER_USER, "WAZUH_INDEXER_USER", "admin");
    addUnit<std::string>(key::INDEXER_PASSWORD, "WAZUH_INDEXER_PASSWORD", "WazuhEngine5+");
    addUnit<std::vector<std::string>>(key::INDEXER_SSL_CA_LIST, "WAZUH_INDEXER_SSL_CA_LIST", {});
    addUnit<std::string>(key::INDEXER_SSL_CERTIFICATE, "WAZUH_INDEXER_SSL_CERTIFICATE", "");
    addUnit<std::string>(key::INDEXER_SSL_KEY, "WAZUH_INDEXER_SSL_KEY", "");
    addUnit<bool>(key::INDEXER_SSL_USE_SSL, "WAZUH_INDEXER_SSL_USE_SSL", false);
    addUnit<bool>(key::INDEXER_SSL_VERIFY_CERTS, "WAZUH_INDEXER_SSL_VERIFY_CERTS", true);
    addUnit<int>(key::INDEXER_TIMEOUT, "WAZUH_INDEXER_TIMEOUT", 60000);
    addUnit<int>(key::INDEXER_THREADS, "WAZUH_INDEXER_THREADS", 1);
    addUnit<std::string>(key::INDEXER_DB_PATH, "WAZUH_INDEXER_DB_PATH", "/var/lib/wazuh-server/indexer-connector/");

    // Queue module
    addUnit<int>(key::QUEUE_SIZE, "WAZUH_QUEUE_SIZE", 1000000);
    // If file is "" the queue will block until the event is pushed to the queue.
    addUnit<std::string>(key::QUEUE_FLOOD_FILE, "WAZUH_QUEUE_FLOOD_FILE", ""); // or /var/wazuh/logs/engine-flood.log
    // Number of attempts to try to push an event to the queue.
    addUnit<int>(key::QUEUE_FLOOD_ATTEMPS, "WAZUH_QUEUE_FLOOD_ATTEMPTS", 3);
    // Microseconds to sleep between attempts to push an event to the queue.
    addUnit<int>(key::QUEUE_FLOOD_SLEEP, "WAZUH_QUEUE_FLOOD_SLEEP", 100);
    // If enabled, the queue will drop the flood events instead of storing them in the file.
    addUnit<bool>(key::QUEUE_DROP_ON_FLOOD, "WAZUH_QUEUE_DROP_ON_FLOOD", false);

    // Orchestrator module
    addUnit<int>(key::ORCHESTRATOR_THREADS, "WAZUH_ORCHESTRATOR_THREADS", 1);

    // OLD Server module
    // TODO Deprecate this configuration after the migration to the new httplib server
    addUnit<int>(key::SERVER_THREAD_POOL_SIZE, "WAZUH_SERVER_THREAD_POOL_SIZE", 1);
    addUnit<int>(key::SERVER_EVENT_QUEUE_SIZE, "WAZUH_SERVER_EVENT_QUEUE_SIZE", 0);

    addUnit<std::string>(key::SERVER_API_SOCKET, "WAZUH_SERVER_API_SOCKET", "/run/wazuh-server/engine-api.socket");
    addUnit<int>(key::SERVER_API_QUEUE_SIZE, "WAZUH_SERVER_API_QUEUE_SIZE", 300);
    addUnit<int>(key::SERVER_API_TIMEOUT, "WAZUH_SERVER_API_TIMEOUT", 5000);

    // New API Server module
    addUnit<std::string>(key::API_SERVER_SOCKET, "WAZUH_API_SERVER_SOCKET", "/run/wazuh-server/engine.socket");

    // TZDB module
    addUnit<std::string>(key::TZDB_PATH, "WAZUH_TZDB_PATH", "/var/lib/wazuh-server/engine/tzdb");
    addUnit<bool>(key::TZDB_AUTO_UPDATE, "WAZUH_TZDB_AUTO_UPDATE", false);

    // Metrics module
    addUnit<bool>(key::METRICS_ENABLED, "WAZUH_METRICS_ENABLED", false);
    addUnit<int64_t>(key::METRICS_EXPORT_INTERVAL, "WAZUH_METRICS_EXPORT_INTERVAL", 10000);
    addUnit<int64_t>(key::METRICS_EXPORT_TIMEOUT, "WAZUH_METRICS_EXPORT_TIMEOUT", 1000);
};

void Conf::validate(const json::Json& config) const
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
                throw std::runtime_error(
                    fmt::format("Invalid configuration type for key '{}'. Expected integer, got '{}'.",
                                key,
                                config.str(key).value_or("errorValue")));
            case UnitConfType::STRING:
                if (config.isString(key))
                {
                    continue;
                }
                throw std::runtime_error(
                    fmt::format("Invalid configuration type for key '{}'. Expected string, got '{}'.",
                                key,
                                config.str(key).value_or("errorValue")));
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
                throw std::runtime_error(
                    fmt::format("Invalid configuration type for key '{}'. Expected boolean, got '{}'.",
                                key,
                                config.str(key).value_or("errorValue")));
            default: throw std::logic_error(fmt::format("Invalid configuration type for key '{}'.", key));
        }
    }
}

void Conf::load()
{
    if (!m_apiConfig.isNull())
    {
        throw std::logic_error("The configuration is already loaded.");
    }
    json::Json apiConf = (*m_apiLoader)();
    validate(apiConf);
    m_apiConfig = std::move(apiConf);
}

} // namespace conf
