#ifndef _CONF_KEYS_HPP
#define _CONF_KEYS_HPP

#include <string>

// Define the default key path for each configuration unit
namespace conf::key
{
constexpr std::string_view STANDALONE_LOGGING_LEVEL = "analysisd.logging_level";
constexpr std::string_view LOGGING_LEVEL = "analysisd.debug";

constexpr std::string_view STORE_PATH = "analysisd.store_path";

constexpr std::string_view KVDB_PATH = "analysisd.kvdb_path";

constexpr std::string_view CMSYNC_OUTPUT_PATH = "analysisd.cmsync_output_path";

constexpr std::string_view CTI_PATH = "analysisd.cti_path";
constexpr std::string_view CTI_FORCE_IF_EMPTY = "analysisd.cti_force_if_empty";
constexpr std::string_view CTI_ENABLED = "analysisd.cti_enabled";

constexpr std::string_view INDEXER_HOST = "analysisd.indexer_hosts";
constexpr std::string_view INDEXER_USER = "analysisd.indexer_username";
constexpr std::string_view INDEXER_PASSWORD = "analysisd.indexer_password";
constexpr std::string_view INDEXER_SSL_CA_BUNDLE = "analysisd.indexer_ssl_certificate_authorities";
constexpr std::string_view INDEXER_SSL_CERTIFICATE = "analysisd.indexer_ssl_certificate";
constexpr std::string_view INDEXER_SSL_KEY = "analysisd.indexer_ssl_key";

constexpr std::string_view QUEUE_SIZE = "analysisd.queue_size";
constexpr std::string_view QUEUE_FLOOD_FILE = "analysisd.queue_flood_file";
constexpr std::string_view QUEUE_FLOOD_ATTEMPS = "analysisd.queue_flood_attempts";
constexpr std::string_view QUEUE_FLOOD_SLEEP = "analysisd.queue_flood_sleep";
constexpr std::string_view QUEUE_DROP_ON_FLOOD = "analysisd.queue_drop_on_flood";

constexpr std::string_view ORCHESTRATOR_THREADS = "analysisd.orchestrator_threads";

constexpr std::string_view SERVER_API_SOCKET = "analysisd.server_api_socket";
constexpr std::string_view SERVER_API_TIMEOUT = "analysisd.server_api_timeout";

constexpr std::string_view SERVER_ENRICHED_EVENTS_SOCKET = "/analysisd/server/enriched_events_socket";

constexpr std::string_view SERVER_EVENT_SOCKET = "/analysisd/server/event_socket";
constexpr std::string_view SERVER_EVENT_THREADS = "/analysisd/server/event_threads";

constexpr std::string_view TZDB_PATH = "analysisd.tzdb_path";
constexpr std::string_view TZDB_AUTO_UPDATE = "analysisd.tzdb_auto_update";
constexpr std::string_view TZDB_FORCE_VERSION_UPDATE = "analysisd.tzdb_force_version_update";

constexpr std::string_view METRICS_ENABLED = "analysisd.metrics_enabled";
constexpr std::string_view METRICS_EXPORT_INTERVAL = "analysisd.metrics_export_interval";
constexpr std::string_view METRICS_EXPORT_TIMEOUT = "analysisd.metrics_export_timeout";

constexpr std::string_view STREAMLOG_BASE_PATH = "analysisd.streamlog_base_path";
constexpr std::string_view STREAMLOG_SHOULD_COMPRESS = "analysisd.streamlog_compress";
constexpr std::string_view STREAMLOG_COMPRESSION_LEVEL = "analysisd.streamlog_compression_level";
constexpr std::string_view STREAMLOG_ALERTS_PATTERN = "analysisd.streamlog_alerts_pattern";
constexpr std::string_view STREAMLOG_ALERTS_MAX_SIZE = "analysisd.streamlog_alerts_max_size";
constexpr std::string_view STREAMLOG_ALERTS_BUFFER_SIZE = "analysisd.streamlog_alerts_buffer_size";
constexpr std::string_view STREAMLOG_ARCHIVES_PATTERN = "analysisd.streamlog_archives_pattern";
constexpr std::string_view STREAMLOG_ARCHIVES_MAX_SIZE = "analysisd.streamlog_archives_max_size";
constexpr std::string_view STREAMLOG_ARCHIVES_BUFFER_SIZE = "analysisd.streamlog_archives_buffer_size";

constexpr std::string_view ARCHIVER_ENABLED = "analysisd.archiver_enabled";

constexpr std::string_view PID_FILE_PATH = "analysisd.pid_path";
constexpr std::string_view SKIP_GROUP_CHANGE = "analysisd.owner_group_change_skip";
constexpr std::string_view GROUP = "analysisd.owner_group";
}; // namespace conf::key

#endif // _CONF_KEYS_HPP
