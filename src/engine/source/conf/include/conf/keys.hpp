#ifndef _CONF_KEYS_HPP
#define _CONF_KEYS_HPP

#include <string>

// Define the default key path for each configuration unit
namespace conf::key
{
constexpr std::string_view LOGGING_LEVEL = "/logging/level";

constexpr std::string_view STORE_PATH = "/store/path";

constexpr std::string_view KVDB_PATH = "/kvdb/path";

constexpr std::string_view INDEXER_INDEX = "/indexer/index";
constexpr std::string_view INDEXER_HOST = "/indexer/host";
constexpr std::string_view INDEXER_USER = "/indexer/user";
constexpr std::string_view INDEXER_PASSWORD = "/indexer/password";
constexpr std::string_view INDEXER_SSL_CA_LIST = "/indexer/ssl/certificate_authorities";
constexpr std::string_view INDEXER_SSL_CERTIFICATE = "/indexer/ssl/certificate";
constexpr std::string_view INDEXER_SSL_KEY = "/indexer/ssl/key";
constexpr std::string_view INDEXER_TIMEOUT = "/indexer/timeout";
constexpr std::string_view INDEXER_THREADS = "/indexer/threads";
constexpr std::string_view INDEXER_DB_PATH = "/indexer/db_path";

constexpr std::string_view QUEUE_SIZE = "/queue/size";
constexpr std::string_view QUEUE_FLOOD_FILE = "/queue/flood_file";
constexpr std::string_view QUEUE_FLOOD_ATTEMPS = "/queue/flood_attempts";
constexpr std::string_view QUEUE_FLOOD_SLEEP = "/queue/flood_sleep";
constexpr std::string_view QUEUE_DROP_ON_FLOOD = "/queue/drop_on_flood";

constexpr std::string_view ORCHESTRATOR_THREADS = "/orchestrator/threads";

constexpr std::string_view SERVER_THREAD_POOL_SIZE = "/server/thread_pool_size";
constexpr std::string_view SERVER_EVENT_QUEUE_SIZE = "/server/event_queue_size";
constexpr std::string_view SERVER_API_SOCKET = "/server/api_socket";
constexpr std::string_view SERVER_API_QUEUE_SIZE = "/server/api_queue_size";
constexpr std::string_view SERVER_API_TIMEOUT = "/server/api_timeout";

constexpr std::string_view API_SERVER_SOCKET = "/api_server/socket";

constexpr std::string_view TZDB_PATH = "/tzdb/path";
constexpr std::string_view TZDB_AUTO_UPDATE = "/tzdb/auto_update";

}; // namespace conf::key

#endif // _CONF_KEYS_HPP
