/*
 * Wazuh Syscollector
 * Copyright (C) 2015-2021, Wazuh Inc.
 * November 15, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#ifndef _SYSCOLLECTOR_H
#define _SYSCOLLECTOR_H

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

#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef enum syscollector_log_level_t {
   SYS_LOG_ERROR,
   SYS_LOG_INFO,
   SYS_LOG_DEBUG,
   SYS_LOG_DEBUG_VERBOSE
}syscollector_log_level_t;

typedef void((*log_callback_t)(const syscollector_log_level_t level, const char* log));

typedef void((*send_data_callback_t)(const void* buffer));

EXPORTED void syscollector_start(const unsigned int inverval,
                                 send_data_callback_t callbackDiff,
                                 send_data_callback_t callbackSync,
                                 log_callback_t callbackLog,
                                 const char* dbPath,
                                 const char* normalizerConfigPath,
                                 const char* normalizerType,
                                 const bool scanOnStart,
                                 const bool hardware,
                                 const bool os,
                                 const bool network,
                                 const bool packages,
                                 const bool ports,
                                 const bool portsAll,
                                 const bool processes,
                                 const bool hotfixes);

EXPORTED void syscollector_stop();

EXPORTED int syscollector_sync_message(const char* data);



#ifdef __cplusplus
}
#endif

typedef void(*syscollector_start_func)(const unsigned int inverval,
                                       send_data_callback_t callbackDiff,
                                       send_data_callback_t callbackSync,
                                       log_callback_t callbackLog,
                                       const char* dbPath,
                                       const char* normalizerConfigPath,
                                       const char* normalizerType,
                                       const bool scanOnStart,
                                       const bool hardware,
                                       const bool os,
                                       const bool network,
                                       const bool packages,
                                       const bool ports,
                                       const bool portsAll,
                                       const bool processes,
                                       const bool hotfixes);

typedef void(*syscollector_stop_func)();

typedef int (*syscollector_sync_message_func)(const char* data);

#endif //_SYSCOLLECTOR_H