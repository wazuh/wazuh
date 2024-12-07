#ifndef _CONF_KEYS_HPP
#define _CONF_KEYS_HPP

#include <string>

// Define the default key path for each configuration unit
namespace conf::key
{
constexpr std::string_view LOGGING_LEVEL = "/engine/logging/level";

constexpr std::string_view STORE_PATH = "/engine/store/path";

constexpr std::string_view KVDB_PATH = "/engine/kvdb/path";

constexpr std::string_view INDEXER_INDEX = "/indexer/index";
constexpr std::string_view INDEXER_HOST = "/indexer/hosts";
constexpr std::string_view INDEXER_USER = "/indexer/username";
constexpr std::string_view INDEXER_PASSWORD = "/indexer/password";
constexpr std::string_view INDEXER_SSL_CA_LIST = "/indexer/ssl/certificate_authorities";
constexpr std::string_view INDEXER_SSL_CERTIFICATE = "/indexer/ssl/certificate";
constexpr std::string_view INDEXER_SSL_KEY = "/indexer/ssl/key";
constexpr std::string_view INDEXER_SSL_USE_SSL = "/indexer/ssl/use_ssl";
constexpr std::string_view INDEXER_SSL_VERIFY_CERTS = "/indexer/ssl/verify_certificates";

constexpr std::string_view INDEXER_TIMEOUT = "/indexer/timeout";
constexpr std::string_view INDEXER_THREADS = "/indexer/threads";
constexpr std::string_view INDEXER_DB_PATH = "/indexer/db_path";
constexpr std::string_view INDEXER_KEYSTORE_PATH = "/indexer/keystore_path";

constexpr std::string_view QUEUE_SIZE = "/engine/queue/size";
constexpr std::string_view QUEUE_FLOOD_FILE = "/engine/queue/flood_file";
constexpr std::string_view QUEUE_FLOOD_ATTEMPS = "/engine/queue/flood_attempts";
constexpr std::string_view QUEUE_FLOOD_SLEEP = "/engine/queue/flood_sleep";
constexpr std::string_view QUEUE_DROP_ON_FLOOD = "/engine/queue/drop_on_flood";

constexpr std::string_view ORCHESTRATOR_THREADS = "/engine/orchestrator/threads";

constexpr std::string_view SERVER_THREAD_POOL_SIZE = "/engine/server/thread_pool_size";
constexpr std::string_view SERVER_EVENT_QUEUE_SIZE = "/engine/server/event_queue_size";
constexpr std::string_view SERVER_API_SOCKET = "/engine/server/api_socket";
constexpr std::string_view SERVER_API_QUEUE_SIZE = "/engine/server/api_queue_size";
constexpr std::string_view SERVER_API_TIMEOUT = "/engine/server/api_timeout";

constexpr std::string_view API_SERVER_SOCKET = "/engine/api_server/socket";

constexpr std::string_view TZDB_PATH = "/engine/tzdb/path";
constexpr std::string_view TZDB_AUTO_UPDATE = "/engine/tzdb/auto_update";

constexpr std::string_view METRICS_EXPORT_INTERVAL = "/engine/metrics/export_interval";
constexpr std::string_view METRICS_EXPORT_TIMEOUT = "/engine/metrics/export_timeout";

}; // namespace conf::key

#endif // _CONF_KEYS_HPP
