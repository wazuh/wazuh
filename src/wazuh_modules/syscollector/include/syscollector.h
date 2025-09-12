/*
 * Wazuh Syscollector
 * Copyright (C) 2015, Wazuh Inc.
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
#include "commonDefs.h"
#ifdef __cplusplus
extern "C" {
#endif
#include "logging_helper.h"
#include "agent_sync_protocol_c_interface_types.h"

typedef void((*log_callback_t)(const modules_log_level_t level, const char* log, const char* tag));

typedef void((*send_data_callback_t)(const void* buffer));

typedef void((*persist_data_callback_t)(const char* id, Operation_t operation, const char* index, const void* buffer));

EXPORTED void syscollector_start(const unsigned int inverval,
                                 send_data_callback_t callbackDiff,
                                 persist_data_callback_t callbackPersistDiff,
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
                                 const bool hotfixes,
                                 const bool groups,
                                 const bool users,
                                 const bool services,
                                 const bool browserExtensions,
                                 const bool notifyOnFirstScan);

EXPORTED void syscollector_stop();

// Sync protocol C wrapper functions
EXPORTED void syscollector_init_sync(const char* moduleName, const char* syncDbPath, const MQ_Functions* mqFuncs);
EXPORTED bool syscollector_sync_module(Mode_t mode, unsigned int timeout, unsigned int retries, unsigned int maxEps);
EXPORTED void syscollector_persist_diff(const char* id, Operation_t operation, const char* index, const char* data);
EXPORTED bool syscollector_parse_response(const unsigned char* data, size_t length);

#ifdef __cplusplus
}
#endif

typedef void(*syscollector_start_func)(const unsigned int inverval,
                                       send_data_callback_t callbackDiff,
                                       persist_data_callback_t callbackPersistDiff,
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
                                       const bool hotfixes,
                                       const bool groups,
                                       const bool users,
                                       const bool services,
                                       const bool browserExtensions,
                                       const bool notifyOnFirstScan);

typedef void(*syscollector_stop_func)();

// Sync protocol C wrapper functions
typedef void(*syscollector_init_sync_func)(const char* moduleName, const char* syncDbPath, const MQ_Functions* mqFuncs);
typedef bool(*syscollector_sync_module_func)(Mode_t mode, unsigned int timeout, unsigned int retries, unsigned int maxEps);
typedef void(*syscollector_persist_diff_func)(const char* id, Operation_t operation, const char* index, const char* data);
typedef bool(*syscollector_parse_response_func)(const unsigned char* data, size_t length);

#endif //_SYSCOLLECTOR_H
