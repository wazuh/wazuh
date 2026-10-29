// SPDX-License-Identifier: AGPL-3.0-or-later
#include <conf/conf.hpp>

#include <filesystem>
#include <limits>
#include <unistd.h>

#include <base/managerConfig.hpp>
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
    addUnit<std::string>(key::STORE_PATH, "WAZUH_STORE_PATH", (wazuhRoot / "data/store").c_str());

    // Default outputs: in the fixed configuration directory on a manager; relative to the cwd standalone.
    const std::filesystem::path outputsPath =
        base::process::isStandaloneModeEnable()
            ? wazuhRoot / "etc/outputs/"
            : std::filesystem::path(std::string(base::managerConfig::MANAGER_CONF_DIR)) / "outputs/";
    addUnit<std::string>(key::OUTPUTS_PATH, "WAZUH_OUTPUTS_PATH", outputsPath.c_str());

    // Default kvdb ioc
    addUnit<std::string>(key::KVDB_IOC_PATH, "WAZUH_KVDB_IOC_PATH", (wazuhRoot / "data/kvdb-ioc").c_str());
    addUnit<std::string>(key::KVDB_IOC_INPUT_PATH, "WAZUH_KVDB_IOC_INPUT_PATH", (wazuhRoot / "data/ioc-input").c_str());

    // Content Manager
    addUnit<std::string>(key::CM_RULESET_PATH, "WAZUH_CM_RULESET_PATH", (wazuhRoot / "data/ruleset").c_str());
    addUnit<size_t>(key::CM_SYNC_INTERVAL, "WAZUH_CM_SYNC_INTERVAL", 120);
    // 0 is legal and disables the early content-sync retry.
    addUnit<size_t>(key::CM_SYNC_RETRY_INTERVAL, "WAZUH_CM_SYNC_RETRY_INTERVAL", 30, Range {0, 3600});
    addUnit<size_t>(key::IOC_SYNC_INTERVAL, "WAZUH_IOC_SYNC_INTERVAL", 360);

    // Geo module
    addUnit<size_t>(key::GEO_SYNC_INTERVAL, "WAZUH_GEO_SYNC_INTERVAL", 360);
    addUnit<std::string>(key::GEO_DB_PATH, "WAZUH_GEO_DB_PATH", (wazuhRoot / "data/mmdb").c_str());
    addUnit<std::string>(
        key::GEO_MANIFEST_URL, "WAZUH_GEO_MANIFEST_URL", "https://api.pre.cloud.wazuh.com/maxmind_geoip/manifest.json");
    addUnit<size_t>(key::GEO_DOWNLOAD_TIMEOUT, "WAZUH_GEO_DOWNLOAD_TIMEOUT", 60000);

    // Indexer connector
    addUnit<std::vector<std::string>>(key::INDEXER_HOST, "WAZUH_INDEXER_HOSTS", {"http://localhost:9200"});
    addUnit<std::vector<std::string>>(key::INDEXER_SSL_CA_BUNDLE, "WAZUH_INDEXER_SSL_CA_BUNDLE", {});
    addUnit<std::string>(key::INDEXER_SSL_CERTIFICATE, "WAZUH_INDEXER_SSL_CERTIFICATE", "");
    addUnit<std::string>(key::INDEXER_SSL_KEY, "WAZUH_INDEXER_SSL_KEY", "");
    addUnit<size_t>(key::INDEXER_QUEUE_MAX_BYTES, "WAZUH_INDEXER_QUEUE_MAX_BYTES", size_t {0x1} << 26); // 64 MB
    addUnit<size_t>(key::INDEXER_BULK_MAX_BYTES,
                    "WAZUH_INDEXER_BULK_MAX_BYTES",
                    size_t {0x1} << 23,                                // 8 MB
                    Range {int64_t {0x1} << 16, int64_t {100} << 20}); // 64 KB to 100 MB
    addUnit<size_t>(key::INDEXER_FLUSH_INTERVAL, "WAZUH_INDEXER_FLUSH_INTERVAL", 20, Range {1, 3600});
    // Error-logger sizing: bounded queue + thread count (only error responses are queued)
    addUnit<size_t>(key::INDEXER_LOGGER_QUEUE_SIZE, "WAZUH_INDEXER_LOGGER_QUEUE_SIZE", 8, Range {1, 1024});
    addUnit<size_t>(key::INDEXER_LOGGER_THREADS, "WAZUH_INDEXER_LOGGER_THREADS", 1, Range {1, 16});
    addUnit<size_t>(key::INDEXER_MAX_RETRY_DELAY, "WAZUH_INDEXER_MAX_RETRY_DELAY", 15, Range {1, 3600});
    // 0 is legal and disables the per-request bound.
    addUnit<size_t>(key::INDEXER_REQUEST_TIMEOUT, "WAZUH_INDEXER_REQUEST_TIMEOUT", 60, Range {0, 3600});
    // 0 is NOT legal: a zero polling period turns the health-monitor thread into a busy loop.
    addUnit<size_t>(key::INDEXER_MONITORING_INTERVAL, "WAZUH_INDEXER_MONITORING_INTERVAL", 10, Range {1, 3600});
    addUnit<size_t>(
        key::CMSYNC_INDEXER_CONNECTOR_SYNC_BATCH_SIZE, "WAZUH_CMSYNC_INDEXER_CONNECTOR_SYNC_BATCH_SIZE", 100);
    // IOC Sync
    addUnit<size_t>(key::IOC_INDEXER_CONNECTOR_MAX_RETRIES, "WAZUH_IOC_INDEXER_CONNECTOR_MAX_RETRIES", 3);
    addUnit<size_t>(key::IOC_INDEXER_CONNECTOR_RETRY_INTERVAL, "WAZUH_IOC_INDEXER_CONNECTOR_RETRY_INTERVAL", 5);
    addUnit<size_t>(key::IOC_INDEXER_CONNECTOR_SYNC_BATCH_SIZE, "WAZUH_IOC_INDEXER_CONNECTOR_SYNC_BATCH_SIZE", 1000);
    // CM Sync
    addUnit<size_t>(key::CMSYNC_INDEXER_CONNECTOR_MAX_RETRIES, "WAZUH_CMSYNC_INDEXER_CONNECTOR_MAX_RETRIES", 3);
    addUnit<size_t>(key::CMSYNC_INDEXER_CONNECTOR_RETRY_INTERVAL, "WAZUH_CMSYNC_INDEXER_CONNECTOR_RETRY_INTERVAL", 5);
    // Remote Configuration Sync
    addUnit<size_t>(
        key::REMOTE_CONF_INDEXER_CONNECTOR_MAX_RETRIES, "WAZUH_REMOTE_CONF_INDEXER_CONNECTOR_MAX_RETRIES", 3);
    addUnit<size_t>(
        key::REMOTE_CONF_INDEXER_CONNECTOR_RETRY_INTERVAL, "WAZUH_REMOTE_CONF_INDEXER_CONNECTOR_RETRY_INTERVAL", 5);

    // RemoteConfig Indexer
    addUnit<size_t>(key::REMOTE_CONF_SYNC_INTERVAL, "WAZUH_REMOTE_CONF_SYNC_INTERVAL", 120);

    // Queue event module
    // The queues take an int capacity of at least fastqueue's minimum (8192)
    addUnit<size_t>(
        key::EVENT_QUEUE_SIZE, "WAZUH_EVENT_QUEUE_SIZE", 0x1 << 17, Range {8192, std::numeric_limits<int>::max()});
    addUnit<size_t>(key::EVENT_QUEUE_EPS, "WAZUH_EVENT_QUEUE_EPS", 0);
    addUnit<size_t>(key::EVENT_QUEUE_MAX_BYTES, "WAZUH_EVENT_QUEUE_MAX_BYTES", 0x1 << 25); // 0 = unlimited

    // Agent Metadata Cache
    addUnit<size_t>(key::AGENT_METADATA_CACHE_TTL,
                    "WAZUH_AGENT_METADATA_CACHE_TTL",
                    300,               // 5 minutes
                    Range {1, 86400}); // up to 1 day
    addUnit<size_t>(
        key::AGENT_METADATA_CACHE_CLEAN_INTERVAL, "WAZUH_AGENT_METADATA_CACHE_CLEAN_INTERVAL", 60); // 1 minute

    // Orchestrator module
    // 0 means one worker per CPU core
    addUnit<int>(key::ORCHESTRATOR_THREADS, "WAZUH_ORCHESTRATOR_THREADS", 0, Range {0, 128});

    // Http server module
    addUnit<std::string>(
        key::SERVER_API_SOCKET, "WAZUH_SERVER_API_SOCKET", (wazuhRoot / "queue/sockets/engine-api-http.sock").c_str());
    addUnit<int>(key::SERVER_API_TIMEOUT, "WAZUH_SERVER_API_TIMEOUT", 5000, Range {1, std::numeric_limits<int>::max()});
    addUnit<int64_t>(key::SERVER_API_PAYLOAD_MAX_BYTES, "WAZUH_SERVER_API_PAYLOAD_MAX_BYTES", 0);

    // Event server - enriched (http)
    addUnit<std::string>(key::SERVER_ENRICHED_EVENTS_SOCKET,
                         "WAZUH_SERVER_ENRICHED_EVENTS_SOCKET",
                         (wazuhRoot / "queue/sockets/engine-ingest-http.sock").c_str());

    // Enable or disable server event processing
    addUnit<bool>(key::SERVER_ENABLE_EVENT_PROCESSING, "WAZUH_SERVER_ENABLE_EVENT_PROCESSING", true);

    // TZDB module
    addUnit<std::string>(key::TZDB_PATH, "WAZUH_TZDB_PATH", (wazuhRoot / "data/tzdb").c_str());
    addUnit<bool>(key::TZDB_AUTO_UPDATE, "WAZUH_TZDB_AUTO_UPDATE", false);
    addUnit<std::string>(key::TZDB_FORCE_VERSION_UPDATE, "WAZUH_TZDB_FORCE_VERSION_UPDATE", "");

    // Streamlog module
    addUnit<std::string>(key::STREAMLOG_BASE_PATH, "WAZUH_STREAMLOG_BASE_PATH", (wazuhRoot / "logs/").c_str());
    addUnit<bool>(key::STREAMLOG_SHOULD_COMPRESS, "WAZUH_STREAMLOG_SHOULD_COMPRESS", true);
    addUnit<size_t>(key::STREAMLOG_COMPRESSION_LEVEL, "WAZUH_STREAMLOG_COMPRESSION_LEVEL", 5, Range {1, 9});
    addUnit<std::string>(
        key::STREAMLOG_EVENTS_PATTERN, "WAZUH_STREAMLOG_EVENTS_PATTERN", "${YYYY}/${MMM}/wazuh-${name}-${DD}");
    addUnit<size_t>(key::STREAMLOG_EVENTS_MAX_SIZE, "WAZUH_STREAMLOG_EVENTS_MAX_SIZE", 0);
    addUnit<size_t>(key::STREAMLOG_EVENTS_BUFFER_SIZE, "WAZUH_STREAMLOG_EVENTS_BUFFER_SIZE", 0x1 << 20);
    addUnit<std::string>(
        key::STREAMLOG_DUMPER_PATTERN, "WAZUH_STREAMLOG_DUMPER_PATTERN", "${YYYY}/${MMM}/wazuh-${name}-${DD}");
    addUnit<size_t>(key::STREAMLOG_DUMPER_MAX_SIZE, "WAZUH_STREAMLOG_DUMPER_MAX_SIZE", 0);
    addUnit<size_t>(key::STREAMLOG_DUMPER_BUFFER_SIZE, "WAZUH_STREAMLOG_DUMPER_BUFFER_SIZE", 0x1 << 20);

    addUnit<size_t>(key::STREAMLOG_MAX_FILES, "WAZUH_STREAMLOG_MAX_FILES", 90);
    addUnit<size_t>(
        key::STREAMLOG_MAX_ACCUMULATED_SIZE, "WAZUH_STREAMLOG_MAX_ACCUMULATED_SIZE", 20ULL * 1024 * 1024 * 1024);

    // Dumper module
    addUnit<bool>(key::DUMPER_ENABLED, "WAZUH_DUMPER_ENABLED", false);

    // Process module
    addUnit<std::string>(key::PID_FILE_PATH, "WAZUH_ENGINE_PID_FILE_PATH", (wazuhRoot / "var/run/").c_str());
    addUnit<bool>(key::DROP_PRIVILEGES, "WAZUH_ENGINE_DROP_PRIVILEGES", true);

    // API modules
    addUnit<int64_t>(key::API_RESOURCE_PAYLOAD_MAX_BYTES, "WAZUH_SERVER_API_MAX_RESOURCE_PAYLOAD_SIZE", 50'000);
    addUnit<int64_t>(
        key::API_RESOURCE_KVDB_PAYLOAD_MAX_BYTES, "WAZUH_SERVER_API_MAX_RESOURCE_KVDB_PAYLOAD_SIZE", 100'000);
};

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
        m_fileConfig = (*m_fileLoader)();
    }

    // A value that does not parse as its key's type (a sign on an unsigned key, an overflow, trailing characters) is
    // refused like an out-of-range one, whatever its source, instead of falling back to the next source
    for (const auto& check : m_typeChecks)
    {
        check(*this);
    }

    // Ranges apply to the effective value, whatever its source: the single place a start and `-t` check them
    for (const auto& check : m_rangeChecks)
    {
        check(*this);
    }
}

} // namespace conf
