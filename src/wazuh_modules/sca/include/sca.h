#ifndef _SCA_H
#define _SCA_H

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#include "logging_helper.h"
#include "agent_sync_protocol_c_interface_types.h"

/* SCA db directory */
#ifndef WAZUH_UNIT_TESTING
#define SCA_DB_DISK_PATH "queue/sca/db/sca.db"
#else
#ifndef WIN32
#define SCA_DB_DISK_PATH    "./sca.db"
#else
#define SCA_DB_DISK_PATH    ".\\sca.db"
#endif // WIN32
#endif // WAZUH_UNIT_TESTING

/* SCA sync protocol index name */
#define SCA_SYNC_INDEX "wazuh-states-sca"

// Forward declarations
struct wm_sca_t;
struct cJSON;

typedef void((*log_callback_t)(const modules_log_level_t level, const char* log, const char* tag));

typedef int (*wm_exec_callback_t)(char* command, char** output, int* exitcode, int secs, const char* add_path);
typedef int (*push_stateless_func)(const char* message);
typedef int (*push_stateful_func)(const char* id, Operation_t operation, const char* index, const char* message, uint64_t version);
typedef struct cJSON* (*yaml_to_cjson_func)(const char* yaml_path);

EXPORTED void sca_start(const struct wm_sca_t* sca_config);

EXPORTED void sca_init();

EXPORTED void sca_stop();

EXPORTED void sca_set_wm_exec(wm_exec_callback_t wm_exec_callback);

EXPORTED void sca_set_log_function(log_callback_t log_callback);

EXPORTED void sca_set_push_functions(push_stateless_func stateless_func, push_stateful_func stateful_func);

EXPORTED void sca_set_sync_parameters(const char* module_name, const char* sync_db_path, const MQ_Functions* mq_funcs, unsigned int sync_end_delay, unsigned int timeout, unsigned int retries,
                                      size_t maxEps);

// Sync protocol C wrapper functions
EXPORTED bool sca_sync_module(Mode_t mode);
EXPORTED void sca_persist_diff(const char* id, Operation_t operation, const char* index, const char* data, uint64_t version);
EXPORTED bool sca_parse_response(const unsigned char* data, size_t length);
EXPORTED bool sca_notify_data_clean(const char** indices, size_t indices_count);
EXPORTED void sca_delete_database();

// Query function
EXPORTED size_t sca_query(const char* query, char** output);

// YAML to cJSON function
EXPORTED void sca_set_yaml_to_cjson_func(yaml_to_cjson_func yaml_func);

#ifdef __cplusplus
}
#endif

typedef void (*sca_init_func)();

typedef void (*sca_start_func)(const struct wm_sca_t* sca_config);

typedef void (*sca_stop_func)();

typedef void (*sca_set_wm_exec_func)(
    int (*wm_exec_callback)(char* command, char** output, int* exitcode, int secs, const char* add_path));

typedef void (*sca_set_log_function_func)(log_callback_t log_callback);

typedef void (*sca_set_push_functions_func)(push_stateless_func stateless_func, push_stateful_func stateful_func);

typedef void (*sca_set_sync_parameters_func)(const char* module_name, const char* sync_db_path, const MQ_Functions* mq_funcs, unsigned int sync_end_delay, unsigned int timeout,
                                             unsigned int retries, size_t maxEps);

// Sync protocol C wrapper functions
typedef bool(*sca_sync_module_func)(Mode_t mode);
typedef void(*sca_persist_diff_func)(const char* id, Operation_t operation, const char* index, const char* data, uint64_t version);
typedef bool(*sca_parse_response_func)(const unsigned char* data, size_t length);
typedef bool(*sca_notify_data_clean_func)(const char** indices, size_t indices_count);
typedef void(*sca_delete_database_func)();

// YAML to cJSON function
typedef void (*sca_set_yaml_to_cjson_func_func)(yaml_to_cjson_func yaml_func);

#endif //_SCA_H
