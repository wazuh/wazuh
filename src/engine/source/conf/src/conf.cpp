#include <conf/conf.hpp>

#include <filesystem>
#include <unistd.h>

#include <base/process.hpp>
#include <fmt/format.h>

#include <conf/keys.hpp>

namespace conf
{

using namespace internal;

Conf::Conf(std::shared_ptr<IFileLoader> fileLoader)
    : m_fileLoader(fileLoader)
    , m_loaded(false)
{
    if (!m_fileLoader)
    {
        throw std::invalid_argument("The file loader cannot be null.");
    }

    // fs path
    const std::filesystem::path wazuhRoot = base::process::getWazuhHome();

    // Register available configuration units with Default Settings

    // Logging module
    addUnit<int>(key::LOGGING_LEVEL, "WAZUH_LOG_LEVEL", 0);

    // Standalone Logging module
    addUnit<std::string>(key::STANDALONE_LOGGING_LEVEL, "WAZUH_STANDALONE_LOG_LEVEL", "info");

    // Store module
    addUnit<std::string>(key::STORE_PATH, "WAZUH_STORE_PATH", (wazuhRoot / "engine/store").c_str());

    // Default outputs
    addUnit<std::string>(key::OUTPUTS_PATH, "WAZUH_OUTPUTS_PATH", (wazuhRoot / "engine/outputs/").c_str());

    // Default kvdb ioc
    addUnit<std::string>(key::KVDB_IOC_PATH, "WAZUH_KVDB_IOC_PATH", (wazuhRoot / "engine/kvdb-ioc").c_str());

    // Content Manager
    addUnit<std::string>(key::CM_RULESET_PATH, "WAZUH_CM_RULESET_PATH", (wazuhRoot / "etc/ruleset").c_str());
    addUnit<size_t>(key::CM_SYNC_INTERVAL, "WAZUH_CM_SYNC_INTERVAL", 120);

    // Geo module
    addUnit<size_t>(key::GEO_SYNC_INTERVAL, "WAZUH_GEO_SYNC_INTERVAL", 360);
    addUnit<std::string>(key::GEO_DB_PATH, "WAZUH_GEO_DB_PATH", (wazuhRoot / "engine/mmdb").c_str());
    addUnit<std::string>(key::GEO_MANIFEST_URL,
                         "WAZUH_GEO_MANIFEST_URL",
                         "https://cti-web-components-dev.s3.us-east-1.amazonaws.com/maxmind_geoip/manifest.json");

    // Indexer connector
    addUnit<std::vector<std::string>>(key::INDEXER_HOST, "WAZUH_INDEXER_HOSTS", {"http://localhost:9200"});
    addUnit<std::string>(key::INDEXER_USER, "WAZUH_INDEXER_USER", "admin");
    addUnit<std::string>(key::INDEXER_PASSWORD, "WAZUH_INDEXER_PASSWORD", "admin");
    addUnit<std::vector<std::string>>(key::INDEXER_SSL_CA_BUNDLE, "WAZUH_INDEXER_SSL_CA_BUNDLE", {});
    addUnit<std::string>(key::INDEXER_SSL_CERTIFICATE, "WAZUH_INDEXER_SSL_CERTIFICATE", "");
    addUnit<std::string>(key::INDEXER_SSL_KEY, "WAZUH_INDEXER_SSL_KEY", "");

    // Raw Event Indexer
    addUnit<bool>(key::RAW_EVENT_INDEXER_ENABLED, "WAZUH_RAW_EVENT_INDEXER_ENABLED", false);

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
        key::SERVER_API_SOCKET, "WAZUH_SERVER_API_SOCKET", (wazuhRoot / "queue/sockets/analysis").c_str());
    addUnit<int>(key::SERVER_API_TIMEOUT, "WAZUH_SERVER_API_TIMEOUT", 5000);
    addUnit<int64_t>(key::SERVER_API_PAYLOAD_MAX_BYTES, "WAZUH_SERVER_API_PAYLOAD_MAX_BYTES", 0);

    // Event server (dgram)
    addUnit<std::string>(
        key::SERVER_EVENT_SOCKET, "WAZUH_SERVER_EVENT_SOCKET", (wazuhRoot / "queue/sockets/queue").c_str());
    addUnit<int>(key::SERVER_EVENT_THREADS, "WAZUH_SERVER_EVENT_THREADS", 1);

    // Event server - enriched (http)
    addUnit<std::string>(key::SERVER_ENRICHED_EVENTS_SOCKET,
                         "WAZUH_SERVER_ENRICHED_EVENTS_SOCKET",
                         (wazuhRoot / "queue/sockets/queue-http.sock").c_str());

    // Enable or disable server event processing
    addUnit<bool>(key::SERVER_ENABLE_EVENT_PROCESSING, "WAZUH_SERVER_ENABLE_EVENT_PROCESSING", true);

    // TZDB module
    addUnit<std::string>(key::TZDB_PATH, "WAZUH_TZDB_PATH", (wazuhRoot / "queue/tzdb").c_str());
    addUnit<bool>(key::TZDB_AUTO_UPDATE, "WAZUH_TZDB_AUTO_UPDATE", false);
    addUnit<std::string>(key::TZDB_FORCE_VERSION_UPDATE, "WAZUH_TZDB_FORCE_VERSION_UPDATE", "");

    // Streamlog module
    addUnit<std::string>(key::STREAMLOG_BASE_PATH, "WAZUH_STREAMLOG_BASE_PATH", (wazuhRoot / "logs/").c_str());
    addUnit<bool>(key::STREAMLOG_SHOULD_COMPRESS, "WAZUH_STREAMLOG_SHOULD_COMPRESS", true);
    addUnit<size_t>(key::STREAMLOG_COMPRESSION_LEVEL, "WAZUH_STREAMLOG_COMPRESSION_LEVEL", 5);
    addUnit<std::string>(
        key::STREAMLOG_ALERTS_PATTERN, "WAZUH_STREAMLOG_ALERTS_PATTERN", "${YYYY}/${MMM}/ossec-${name}-${DD}.json");
    addUnit<size_t>(key::STREAMLOG_ALERTS_MAX_SIZE, "WAZUH_STREAMLOG_ALERTS_MAX_SIZE", 0);
    addUnit<size_t>(key::STREAMLOG_ALERTS_BUFFER_SIZE, "WAZUH_STREAMLOG_ALERTS_BUFFER_SIZE", 0x1 << 20);
    addUnit<std::string>(
        key::STREAMLOG_ARCHIVES_PATTERN, "WAZUH_STREAMLOG_ARCHIVES_PATTERN", "${YYYY}/${MMM}/ossec-${name}-${DD}.json");
    addUnit<size_t>(key::STREAMLOG_ARCHIVES_MAX_SIZE, "WAZUH_STREAMLOG_ARCHIVES_MAX_SIZE", 0);
    addUnit<size_t>(key::STREAMLOG_ARCHIVES_BUFFER_SIZE, "WAZUH_STREAMLOG_ARCHIVES_BUFFER_SIZE", 0x1 << 20);

    // Archiver module
    addUnit<bool>(key::ARCHIVER_ENABLED, "WAZUH_ARCHIVER_ENABLED", false);

    // Process module
    addUnit<std::string>(key::PID_FILE_PATH, "WAZUH_ENGINE_PID_FILE_PATH", (wazuhRoot / "var/run/").c_str());
    addUnit<std::string>(key::GROUP, "WAZUH_ENGINE_GROUP", "wazuh-manager");
    addUnit<bool>(key::SKIP_GROUP_CHANGE, "WAZUH_SKIP_GROUP_CHANGE", false);

    // API modules
    addUnit<int64_t>(key::API_RESOURCE_PAYLOAD_MAX_BYTES, "WAZUH_SERVER_API_MAX_RESOURCE_PAYLOAD_SIZE", 50'000);
    addUnit<int64_t>(
        key::API_RESOURCE_KVDB_PAYLOAD_MAX_BYTES, "WAZUH_SERVER_API_MAX_RESOURCE_KVDB_PAYLOAD_SIZE", 100'000);
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
    if (m_loaded)
    {
        throw std::logic_error("The configuration is already loaded.");
    }
    m_loaded = true;

    // Only load the internal configuration if we are not in standalone mode
    if (!base::process::isStandaloneModeEnable())
    {
        auto fileConf = (*m_fileLoader)();
        validate(fileConf);
        m_fileConfig = std::move(fileConf);
    }
}

} // namespace conf
