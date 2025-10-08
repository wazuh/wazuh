#ifndef _AGENT_INFO_H
#define _AGENT_INFO_H

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

// Forward declarations
struct wm_agent_info_t;

typedef void (*log_callback_t)(const modules_log_level_t level, const char* log, const char* tag);
typedef int (*report_callback_t)(const char* message);
typedef int (*persist_callback_t)(const char* id, Operation_t operation, const char* index, const char* message);

EXPORTED void agent_info_start(const struct wm_agent_info_t* agent_info_config);

EXPORTED void agent_info_stop();

EXPORTED void agent_info_set_log_function(log_callback_t log_callback);

EXPORTED void agent_info_set_report_function(report_callback_t report_callback);

EXPORTED void agent_info_set_persist_function(persist_callback_t persist_callback);

EXPORTED void agent_info_persist_diff(const char* id, Operation_t operation, const char* index, const char* data);

#ifdef __cplusplus
}
#endif

typedef void (*agent_info_start_func)(const struct wm_agent_info_t* agent_info_config);
typedef void (*agent_info_stop_func)();
typedef void (*agent_info_set_log_function_func)(log_callback_t log_callback);
typedef void (*agent_info_set_report_function_func)(report_callback_t report_callback);
typedef void (*agent_info_set_persist_function_func)(persist_callback_t persist_callback);

#endif //_AGENT_INFO_H
