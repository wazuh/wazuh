#include <conf/conf.hpp>

#include <filesystem>
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

Conf::Conf(std::shared_ptr<IFileLoader> fileLoader)
    : m_fileLoader(fileLoader)
{
    if (!m_fileLoader)
    {
        throw std::invalid_argument("The file loader cannot be null.");
    }

    // fs path
    const std::filesystem::path wazuhRoot {"/var/ossec/"};

    // Register available configuration units with Default Settings

    // Logging module
    addUnit<std::string>(key::LOGGING_LEVEL, "WAZUH_LOG_LEVEL", "info");

    // Store module
    addUnit<std::string>(key::STORE_PATH, "WAZUH_STORE_PATH", (wazuhRoot / "engine/store").c_str());

    // KVDB module
    addUnit<std::string>(key::KVDB_PATH, "WAZUH_KVDB_PATH", (wazuhRoot / "engine/kvdb/").c_str());

    // Indexer connector
    addUnit<std::string>(key::INDEXER_INDEX, "WAZUH_INDEXER_INDEX", "wazuh-alerts-5.x-0001");
    addUnit<std::vector<std::string>>(key::INDEXER_HOST, "WAZUH_INDEXER_HOST", {"http://127.0.0.1:9200"});
    addUnit<std::string>(key::INDEXER_USER, "WAZUH_INDEXER_USER", "admin");
    addUnit<std::string>(key::INDEXER_PASSWORD, "WAZUH_INDEXER_PASSWORD", "WazuhEngine5+");
    addUnit<std::string>(key::INDEXER_SSL_CA_BUNDLE, "WAZUH_INDEXER_SSL_CA_BUNDLE", "");
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
    addUnit<bool>(key::QUEUE_DROP_ON_FLOOD, "WAZUH_QUEUE_DROP_ON_FLOOD", true);

    // Orchestrator module
    addUnit<int>(key::ORCHESTRATOR_THREADS, "WAZUH_ORCHESTRATOR_THREADS", 0);

    // Http server module
    addUnit<std::string>(
        key::SERVER_API_SOCKET, "WAZUH_SERVER_API_SOCKET", (wazuhRoot / "queue/sockets/engine-api").c_str());
    addUnit<int>(key::SERVER_API_TIMEOUT, "WAZUH_SERVER_API_TIMEOUT", 5000);

    // Event server (dgram)
    addUnit<std::string>(
        key::SERVER_EVENT_SOCKET, "WAZUH_SERVER_EVENT_SOCKET", (wazuhRoot / "queue/sockets/queue").c_str());
    addUnit<int>(key::SERVER_EVENT_THREADS, "WAZUH_SERVER_EVENT_THREADS", 1);

    // Event server - enriched (http)
    addUnit<std::string>(key::SERVER_ENRICHED_EVENTS_SOCKET, "WAZUH_SERVER_ENRICHED_EVENTS_SOCKET", (wazuhRoot / "queue/sockets/queue-http.sock").c_str());

    // TZDB module
    addUnit<std::string>(key::TZDB_PATH, "WAZUH_TZDB_PATH", (wazuhRoot / "queue/tzdb").c_str());
    addUnit<bool>(key::TZDB_AUTO_UPDATE, "WAZUH_TZDB_AUTO_UPDATE", false);
    addUnit<std::string>(key::TZDB_FORCE_VERSION_UPDATE, "WAZUH_TZDB_FORCE_VERSION_UPDATE", "");

    // Metrics module
    addUnit<bool>(key::METRICS_ENABLED, "WAZUH_METRICS_ENABLED", false);
    addUnit<int64_t>(key::METRICS_EXPORT_INTERVAL, "WAZUH_METRICS_EXPORT_INTERVAL", 10000);
    addUnit<int64_t>(key::METRICS_EXPORT_TIMEOUT, "WAZUH_METRICS_EXPORT_TIMEOUT", 1000);

    // Archiver module
    addUnit<bool>(key::ARCHIVER_ENABLED, "WAZUH_ARCHIVER_ENABLED", false);
    addUnit<std::string>(
        key::ARCHIVER_PATH, "WAZUH_ARCHIVER_PATH", (wazuhRoot / "logs/archives/archives.json").c_str());

    // Process module
    addUnit<std::string>(key::PID_FILE_PATH, "WAZUH_ENGINE_PID_FILE_PATH", (wazuhRoot / "var/run/").c_str());
    addUnit<std::string>(key::USER, "WAZUH_ENGINE_USER", "wazuh");
    addUnit<std::string>(key::GROUP, "WAZUH_ENGINE_GROUP", "wazuh");
    addUnit<bool>(key::SKIP_USER_CHANGE, "WAZUH_SKIP_USER_CHANGE", false);
};

void Conf::validate(const OptionMap& config) const
{
    for (const auto& [key, unit] : m_units)
    {
        auto it = config.find(key);
        if (it == config.end())
        {
            continue; // The configuration is not set for this key, ignore it
        }

        const auto& valueStr = it->second;
        const auto unitType = unit->getType();
        switch (unitType)
        {
            case UnitConfType::INTEGER:
            {
                if (!base::utils::string::isNumber(valueStr))
                {
                    throw std::runtime_error(fmt::format(
                        "Invalid configuration type for key '{}'. Expected integer, got '{}'.", key, valueStr));
                }

                std::size_t pos = 0;
                try
                {
                    auto v = std::stoll(valueStr, &pos);

                    if (pos != valueStr.size())
                    {
                        throw std::runtime_error(fmt::format(
                            "Invalid configuration type for key '{}'. Extra characters found in integer: '{}'.",
                            key,
                            valueStr.substr(pos)));
                    }
                }
                catch (const std::invalid_argument& e)
                {
                    throw std::runtime_error(
                        fmt::format("Invalid configuration type for key '{}'. Could not parse '{}'.", key, valueStr));
                }
                catch (const std::out_of_range& e)
                {
                    throw std::runtime_error(
                        fmt::format("Invalid configuration type for key '{}'. Value out of range for integer: '{}'.",
                                    key,
                                    valueStr));
                }

                break;
            }

            case UnitConfType::STRING:
            {
                break;
            }

            case UnitConfType::STRING_LIST:
            {
                // Detect list-style formatting with brackets: [a,b]
                if (valueStr.front() == '[' && valueStr.back() == ']')
                {
                    throw std::runtime_error(fmt::format(
                        "Invalid configuration type for key '{}'. Bracket notation '[...]' is not allowed: '{}'.",
                        key,
                        valueStr));
                }

                if (valueStr.find(',') == std::string::npos)
                {
                    throw std::runtime_error(
                        fmt::format("Invalid configuration type for key '{}'. Expected comma-separated list, got '{}'.",
                                    key,
                                    valueStr));
                }

                break;
            }

            case UnitConfType::BOOL:
            {
                std::string lowerVal = valueStr;
                std::transform(lowerVal.begin(), lowerVal.end(), lowerVal.begin(), ::tolower);
                if (lowerVal != "true" && lowerVal != "false")
                {
                    throw std::runtime_error(fmt::format(
                        "Invalid configuration type for key '{}'. Expected boolean, got '{}'.", key, valueStr));
                }
                break;
            }

            default: throw std::logic_error(fmt::format("Invalid configuration type for key '{}'.", key));
        }
    }
}

void Conf::load()
{
    if (!m_fileConfig.empty())
    {
        throw std::logic_error("The configuration is already loaded.");
    }
    auto fileConf = (*m_fileLoader)();
    validate(fileConf);
    m_fileConfig = std::move(fileConf);
}

} // namespace conf
