#ifndef _CMD_DEFAULT_SETTINGS_HPP
#define _CMD_DEFAULT_SETTINGS_HPP

namespace cmd
{
// Server start
constexpr auto ENGINE_EVENT_SOCK = "/var/ossec/queue/sockets/queue";
constexpr auto ENGINE_EVENT_SOCK_ENV = "WZE_EVENT_SOCK";

constexpr auto ENGINE_API_SOCK = "/var/ossec/queue/sockets/engine-api";
constexpr auto ENGINE_API_SOCK_ENV = "WZE_API_SOCK";

constexpr auto ENGINE_STORE_PATH = "/var/ossec/engine/store";
constexpr auto ENGINE_STORE_PATH_ENV = "WZE_STORE_PATH";

constexpr auto ENGINE_KVDB_PATH = "/var/ossec/etc/kvdb/";
constexpr auto ENGINE_KVDB_PATH_ENV = "WZE_KVDB_PATH";

constexpr auto ENGINE_LOG_OUTPUT = "/dev/stderr";
constexpr auto ENGINE_LOG_OUTPUT_ENV = "WZE_LOG_OUTPUT";

constexpr auto ENGINE_ENVIRONMENT = "environment/wazuh/0";
constexpr auto ENGINE_ENVIRONMENT_ENV = "WZE_ENVIRONMENT";

constexpr auto ENGINE_QUEUE_SIZE = 1000000;
constexpr auto ENGINE_QUEUE_SIZE_ENV = "WZE_QUEUE_SIZE";

constexpr auto ENGINE_LOG_LEVEL = 3;
constexpr auto ENGINE_LOG_LEVEL_ENV = "WZE_LOG_LEVEL";

constexpr auto ENGINE_THREADS = 1;
constexpr auto ENGINE_THREADS_ENV = "WZE_THREADS";

// Test
constexpr auto ENGINE_KVDB_TEST_PATH = "/var/ossec/etc/kvdb_test/";
constexpr auto ENGINE_PROTOCOL_QUEUE = 1;
constexpr auto ENGINE_PROTOCOL_LOCATION = "/dev/stdin";
constexpr auto TRACE_ALL = "ALL";
} // namespace cmd

#endif // _CMD_DEFAULT_SETTINGS_HPP
