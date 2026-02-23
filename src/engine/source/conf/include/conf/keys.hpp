#ifndef _CONF_KEYS_HPP
#define _CONF_KEYS_HPP

#include <string>

// Define the default key path for each configuration unit
namespace conf::key
{
constexpr std::string_view STANDALONE_LOGGING_LEVEL = "analysisd.logging_level";
constexpr std::string_view LOGGING_LEVEL = "analysisd.debug";

constexpr std::string_view STORE_PATH = "analysisd.store_path";

constexpr std::string_view KVDB_IOC_PATH = "analysisd.kvdb_ioc_path";

constexpr std::string_view OUTPUTS_PATH = "analysisd.output_path";

constexpr std::string_view CM_RULESET_PATH = "analysisd.cm_ruleset_path";
constexpr std::string_view CM_SYNC_INTERVAL = "analysisd.cm_sync_interval";

constexpr std::string_view GEO_SYNC_INTERVAL = "analysisd.geo_sync_interval";
constexpr std::string_view GEO_DB_PATH = "analysisd.geo_db_path";
constexpr std::string_view GEO_MANIFEST_URL = "analysisd.geo_manifest_url";

constexpr std::string_view INDEXER_HOST = "analysisd.indexer_hosts";
constexpr std::string_view INDEXER_USER = "analysisd.indexer_username";
constexpr std::string_view INDEXER_PASSWORD = "analysisd.indexer_password";
constexpr std::string_view INDEXER_SSL_CA_BUNDLE = "analysisd.indexer_ssl_certificate_authorities";
constexpr std::string_view INDEXER_SSL_CERTIFICATE = "analysisd.indexer_ssl_certificate";
constexpr std::string_view INDEXER_SSL_KEY = "analysisd.indexer_ssl_key";

constexpr std::string_view RAW_EVENT_INDEXER_ENABLED = "analysisd.raw_event_indexer_enabled";

constexpr std::string_view RAW_EVENT_INDEXER_ENABLED = "analysisd.raw_event_indexer_enabled";

constexpr std::string_view EVENT_QUEUE_SIZE = "analysisd.event_queue_size";
constexpr std::string_view EVENT_QUEUE_EPS = "analysisd.event_queue_eps";

constexpr std::string_view ORCHESTRATOR_THREADS = "analysisd.orchestrator_threads";

constexpr std::string_view SERVER_API_SOCKET = "analysisd.server_api_socket";
constexpr std::string_view SERVER_API_TIMEOUT = "analysisd.server_api_timeout";
constexpr std::string_view SERVER_API_PAYLOAD_MAX_BYTES = "analysisd.server_api_payload_max_bytes";

constexpr std::string_view SERVER_ENRICHED_EVENTS_SOCKET = "analysisd.server_enriched_events_socket";

constexpr std::string_view SERVER_ENABLE_EVENT_PROCESSING = "analysisd.server_enable_event_processing";

constexpr std::string_view TZDB_PATH = "analysisd.tzdb_path";
constexpr std::string_view TZDB_AUTO_UPDATE = "analysisd.tzdb_auto_update";
constexpr std::string_view TZDB_FORCE_VERSION_UPDATE = "analysisd.tzdb_force_version_update";

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

constexpr std::string_view API_RESOURCE_PAYLOAD_MAX_BYTES = "analysisd.api_resource_payload_max_bytes";
constexpr std::string_view API_RESOURCE_KVDB_PAYLOAD_MAX_BYTES = "analysisd.api_resource_kvdb_payload_max_bytes";
}; // namespace conf::key

#endif // _CONF_KEYS_HPP
