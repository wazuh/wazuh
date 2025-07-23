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

    typedef void((*log_callback_t)(const modules_log_level_t level, const char* log, const char* tag));

    typedef void((*send_data_callback_t)(const void* buffer));

    typedef int (*wm_exec_callback_t)(char *command, char **output, int *exitcode, int secs, const char * add_path);

    EXPORTED void sca_start(log_callback_t callbackLog);

    EXPORTED void sca_stop();

    EXPORTED int sca_sync_message(const char* data);

    EXPORTED void sca_set_wm_exec(wm_exec_callback_t wm_exec_callback);

#ifdef __cplusplus
}
#endif

typedef void (*sca_start_func)(log_callback_t callbackLog);

typedef void (*sca_stop_func)();

typedef int (*sca_sync_message_func)(const char* data);

typedef void (*sca_set_wm_exec_func)(int (*wm_exec_callback)(char *command, char **output, int *exitcode, int secs, const char * add_path));

#endif //_SCA_H
