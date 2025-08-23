#ifndef _CONF_KEYS_HPP
#define _CONF_KEYS_HPP

#include <string>

// Define the default key path for each configuration unit
namespace conf::key
{
constexpr std::string_view LOGGING_LEVEL = "engine.logging_level";

constexpr std::string_view STORE_PATH = "engine.store_path";

constexpr std::string_view KVDB_PATH = "engine.kvdb_path";

constexpr std::string_view INDEXER_INDEX = "indexer.index";
constexpr std::string_view INDEXER_HOST = "indexer.hosts";
constexpr std::string_view INDEXER_USER = "indexer.username";
constexpr std::string_view INDEXER_PASSWORD = "indexer.password";
constexpr std::string_view INDEXER_SSL_CA_BUNDLE = "indexer.ssl_certificate_authorities_bundle";
constexpr std::string_view INDEXER_SSL_CERTIFICATE = "indexer.ssl_certificate";
constexpr std::string_view INDEXER_SSL_KEY = "indexer.ssl_key";
constexpr std::string_view INDEXER_SSL_USE_SSL = "indexer.ssl_use_ssl";
constexpr std::string_view INDEXER_SSL_VERIFY_CERTS = "indexer.ssl_verify_certificates";

constexpr std::string_view INDEXER_TIMEOUT = "indexer.timeout";
constexpr std::string_view INDEXER_THREADS = "indexer.threads";
constexpr std::string_view INDEXER_DB_PATH = "indexer.db_path";

constexpr std::string_view QUEUE_SIZE = "engine.queue_size";
constexpr std::string_view QUEUE_FLOOD_FILE = "engine.queue_flood_file";
constexpr std::string_view QUEUE_FLOOD_ATTEMPS = "engine.queue_flood_attempts";
constexpr std::string_view QUEUE_FLOOD_SLEEP = "engine.queue_flood_sleep";
constexpr std::string_view QUEUE_DROP_ON_FLOOD = "engine.queue_drop_on_flood";

constexpr std::string_view ORCHESTRATOR_THREADS = "engine.orchestrator_threads";

constexpr std::string_view SERVER_API_SOCKET = "engine.server_api_socket";
constexpr std::string_view SERVER_API_TIMEOUT = "engine.server_api_timeout";

constexpr std::string_view SERVER_ENRICHED_EVENTS_SOCKET = "/engine/server/enriched_events_socket";

constexpr std::string_view SERVER_EVENT_SOCKET = "/engine/server/event_socket";
constexpr std::string_view SERVER_EVENT_THREADS = "/engine/server/event_threads";

constexpr std::string_view TZDB_PATH = "engine.tzdb_path";
constexpr std::string_view TZDB_AUTO_UPDATE = "engine.tzdb_auto_update";
constexpr std::string_view TZDB_FORCE_VERSION_UPDATE = "engine.tzdb_force_version_update";

constexpr std::string_view METRICS_ENABLED = "engine.metrics_enabled";
constexpr std::string_view METRICS_EXPORT_INTERVAL = "engine.metrics_export_interval";
constexpr std::string_view METRICS_EXPORT_TIMEOUT = "engine.metrics_export_timeout";

constexpr std::string_view ARCHIVER_ENABLED = "engine.archiver_enabled";
constexpr std::string_view ARCHIVER_PATH = "engine.archiver_path";

constexpr std::string_view PID_FILE_PATH = "engine.pid_path";
constexpr std::string_view SKIP_USER_CHANGE = "engine.owner_user_change_skip";
constexpr std::string_view USER = "engine.owner_user";
constexpr std::string_view GROUP = "engine.owner_group";
}; // namespace conf::key

#endif // _CONF_KEYS_HPP
