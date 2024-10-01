#include <conf/conf.hpp>

#include <unistd.h>

#include <fmt/format.h>

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

    // Register aviablable configuration units

    // Logging module
    addUnit<std::string>("/logging/level", "WAZUH_LOG_LEVEL", "info");

    // Store module
    addUnit<std::string>("/store/path", "WAZUH_STORE_PATH", "/var/wazuh/store");

    // KVDB module
    addUnit<std::string>("/kvdb/path", "WAZUH_KVDB_PATH", "/var/wazuh/kvdb");

    // Indexer connector
    addUnit<std::string>("/indexer/index", "WAZUH_INDEXER_INDEX", "wazuh-alerts-5x");
    addUnit<std::vector<std::string>>("/indexer/host", "WAZUH_INDEXER_HOST", {"http://127.0.0.1:9200"});
    addUnit<std::string>("/indexer/user", "WAZUH_INDEXER_USER", "admin");
    addUnit<std::string>("/indexer/password", "WAZUH_INDEXER_PASSWORD", "WazuhEngine5+");
    addUnit<std::string>("/indexer/ssl/certificate_authorities", "WAZUH_INDEXER_SSL_CERTIFICATE_AUTHORITIES", "");
    addUnit<std::string>("/indexer/ssl/certificate", "WAZUH_INDEXER_SSL_CERTIFICATE", "");
    addUnit<std::string>("/indexer/ssl/key", "WAZUH_INDEXER_SSL_KEY", "");

    // Queue module
    addUnit<int>("/queue/size", "WAZUH_QUEUE_SIZE", 1000000);

    // If file is "" the queue will block until the event is pushed to the queue.
    addUnit<std::string>("/queue/flood_file", "WAZUH_QUEUE_FLOOD_FILE", "/var/wazuh/logs/engine-flood.log");
    // Number of attempts to try to push an event to the queue.
    addUnit<int>("/queue/flood_attempts", "WAZUH_QUEUE_FLOOD_ATTEMPTS", 3);
    // Microseconds to sleep between attempts to push an event to the queue.
    addUnit<int>("/queue/flood_sleep", "WAZUH_QUEUE_FLOOD_SLEEP", 100);
    // If enabled, the queue will drop the flood events instead of storing them in the file.
    addUnit<bool>("/queue/drop_on_flood", "WAZUH_QUEUE_DROP_ON_FLOOD", false);

    // Orchestrator module
    addUnit<int>("/orchestrator/threads", "WAZUH_ORCHESTRATOR_THREADS", 1);

    // OLD Server module
    // TODO Deprecate this configuration after the migration to the new httplib server
    addUnit<int>("/server/thread_pool_size", "WAZUH_SERVER_THREAD_POOL_SIZE", 1);
    addUnit<std::string>("/server/event_socket", "WAZUH_SERVER_EVENT_SOCKET", "/var/wazuh/sockets/old-queue.sock");
    addUnit<int>("/server/event_queue_size", "WAZUH_SERVER_EVENT_QUEUE_SIZE", 0);

    addUnit<std::string>("/server/api_socket", "WAZUH_SERVER_API_SOCKET", "/var/wazuh/sockets/old-api.sock");
    addUnit<int>("/server/api_queue_size", "WAZUH_SERVER_API_QUEUE_SIZE", 50);
    addUnit<int>("/server/api_timeout", "WAZUH_SERVER_API_TIMEOUT", 5000);

    // New API Server module
    addUnit<std::string>("/api_server/socket", "WAZUH_API_SERVER_SOCKET", getExecutablePath() + "/sockets/api.sock");

    // TZDB module
    addUnit<std::string>("/tzdb/path", "WAZUH_TZDB_PATH", getExecutablePath() + "/tzdb");
    addUnit<bool>("/tzdb/auto_update", "WAZUH_TZDB_AUTO_UPDATE", false);
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
