#ifndef _CMD_DEFAULT_SETTINGS_HPP
#define _CMD_DEFAULT_SETTINGS_HPP

namespace cmd
{
/******************************************************************************
 *  Server start
 ******************************************************************************/
// Loggin module
constexpr auto ENGINE_LOG_LEVEL = "error";
constexpr auto ENGINE_LOG_LEVEL_ENV = "WZE_LOG_LEVEL";

constexpr auto ENGINE_LOG_OUTPUT = "/dev/stdout";
constexpr auto ENGINE_LOG_OUTPUT_ENV = "WZE_LOG_OUTPUT";

constexpr auto ENGINE_LOG_TRUNCATE = false;
constexpr auto ENGINE_LOG_TRUNCATE_ENV = "WZE_LOG_TRUNCATE";

// Server module
constexpr auto ENGINE_SRV_PULL_THREADS = 1;
constexpr auto ENGINE_SRV_PULL_THREADS_ENV = "WZE_PULL_THREADS";

constexpr auto ENGINE_SRV_EVENT_SOCK = "/var/ossec/queue/sockets/queue";
constexpr auto ENGINE_SRV_EVENT_SOCK_ENV = "WZE_EVENT_SOCK";

constexpr auto ENGINE_SRV_EVENT_QUEUE_TASK = 0;
constexpr auto ENGINE_SRV_EVENT_QUEUE_TASK_ENV = "WZE_EVENT_QUEUE_TASK";

constexpr auto ENGINE_SRV_API_SOCK = "/var/ossec/queue/sockets/engine-api";
constexpr auto ENGINE_SRV_API_SOCK_ENV = "WZE_API_SOCK";

constexpr auto ENGINE_SRV_API_QUEUE_TASK = 50;
constexpr auto ENGINE_SRV_API_QUEUE_TASK_ENV = "WZE_API_QUEUE_TASK";

constexpr auto ENGINE_CLIENT_TIMEOUT = 1000;
constexpr auto ENGINE_SRV_API_TIMEOUT = 1000;
constexpr auto ENGINE_SRV_API_TIMEOUT_ENV = "WZE_API_TIMEOUT";

// Store module
constexpr auto ENGINE_DEFAULT_POLICY = "policy/wazuh/0";
constexpr auto ENGINE_STORE_PATH = "/var/ossec/engine/store";
constexpr auto ENGINE_STORE_PATH_ENV = "WZE_STORE_PATH";

// KVDB module
constexpr auto ENGINE_KVDB_PATH = "/var/ossec/etc/kvdb/";
constexpr auto ENGINE_KVDB_PATH_ENV = "WZE_KVDB_PATH";

// TZDB
constexpr auto ENGINE_TZDB_PATH = "/var/ossec/engine/tzdb";
constexpr auto ENGINE_TZDB_PATH_ENV = "WZE_TZDB_PATH";

constexpr auto ENGINE_TZDB_AUTO_UPDATE = true;
constexpr auto ENGINE_TZDB_AUTO_UPDATE_ENV = "WZE_TZDB_AUTO_UPDATE";

constexpr auto ENGINE_KVDB_CLI_PAGE = 1;
constexpr auto ENGINE_KVDB_CLI_RECORDS = 50;

constexpr auto ENGINE_ROUTER_THREADS = 1;
constexpr auto ENGINE_ROUTER_THREADS_ENV = "WZE_ROUTER_THREADS";

// Maxmind module
constexpr auto ENGINE_MMDB_ASN_PATH = "";
constexpr auto ENGINE_MMDB_ASN_PATH_ENV = "WZE_MMDB_ASN_PATH";

constexpr auto ENGINE_MMDB_CITY_PATH = "";
constexpr auto ENGINE_MMDB_CITY_PATH_ENV = "WZE_MMDB_CITY_PATH";

// Queue Module
constexpr auto ENGINE_QUEUE_SIZE = 1000000;
constexpr auto ENGINE_QUEUE_SIZE_ENV = "WZE_QUEUE_SIZE";

constexpr auto ENGINE_QUEUE_FLOOD_FILE = "/var/ossec/logs/engine-flood.log";
constexpr auto ENGINE_QUEUE_FLOOD_FILE_ENV = "WZE_QUEUE_FLOOD_FILE";

constexpr auto ENGINE_QUEUE_FLOOD_ATTEMPTS = 3;
constexpr auto ENGINE_QUEUE_FLOOD_ATTEMPTS_ENV = "WZE_QUEUE_FLOOD_ATTEMPTS";

constexpr auto ENGINE_QUEUE_FLOOD_SLEEP = 100;
constexpr auto ENGINE_QUEUE_FLOOD_SLEEP_ENV = "WZE_QUEUE_FLOOD_SLEEP";

// RBAC Module
constexpr auto ENGINE_RBAC_ROLE = "user-developer";

// Namespace
constexpr auto ENGINE_NAMESPACE = "user";

// Policy
constexpr auto DEFAULT_PARENT = "decoder/integrations/0";

/******************************************************************************
 *  Test
 ******************************************************************************/
constexpr auto ENGINE_KVDB_TEST_PATH = "/var/ossec/etc/kvdb_test/";
constexpr auto ENGINE_PROTOCOL_DEFAULT_QUEUE = '1';
constexpr auto ENGINE_PROTOCOL_LOCATION = "api.test";
constexpr auto TRACE_ALL = "ALL";
} // namespace cmd

#endif // _CMD_DEFAULT_SETTINGS_HPP
