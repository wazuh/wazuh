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

/* Syscollector sync protocol index names */
#define SYSCOLLECTOR_SYNC_INDEX_SYSTEM "wazuh-states-inventory-system"
#define SYSCOLLECTOR_SYNC_INDEX_HARDWARE "wazuh-states-inventory-hardware"
#define SYSCOLLECTOR_SYNC_INDEX_HOTFIXES "wazuh-states-inventory-hotfixes"
#define SYSCOLLECTOR_SYNC_INDEX_PACKAGES "wazuh-states-inventory-packages"
#define SYSCOLLECTOR_SYNC_INDEX_PROCESSES "wazuh-states-inventory-processes"
#define SYSCOLLECTOR_SYNC_INDEX_PORTS "wazuh-states-inventory-ports"
#define SYSCOLLECTOR_SYNC_INDEX_INTERFACES "wazuh-states-inventory-interfaces"
#define SYSCOLLECTOR_SYNC_INDEX_PROTOCOLS "wazuh-states-inventory-protocols"
#define SYSCOLLECTOR_SYNC_INDEX_NETWORKS "wazuh-states-inventory-networks"
#define SYSCOLLECTOR_SYNC_INDEX_USERS "wazuh-states-inventory-users"
#define SYSCOLLECTOR_SYNC_INDEX_GROUPS "wazuh-states-inventory-groups"
#define SYSCOLLECTOR_SYNC_INDEX_SERVICES "wazuh-states-inventory-services"
#define SYSCOLLECTOR_SYNC_INDEX_BROWSER_EXTENSIONS "wazuh-states-inventory-browser-extensions"

typedef void((*log_callback_t)(const modules_log_level_t level, const char* log, const char* tag));

typedef void((*send_data_callback_t)(const void* buffer));

typedef void((*persist_data_callback_t)(const char* id, Operation_t operation, const char* index, const void* buffer, uint64_t version));

EXPORTED void syscollector_init(const unsigned int inverval,
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
EXPORTED void syscollector_start();

// Sync protocol C wrapper functions
EXPORTED void syscollector_init_sync(const char* moduleName, const char* syncDbPath, const MQ_Functions* mqFuncs, unsigned int syncEndDelay, unsigned int timeout, unsigned int retries,
                                     size_t maxEps);
EXPORTED bool syscollector_sync_module(Mode_t mode);
EXPORTED void syscollector_persist_diff(const char* id, Operation_t operation, const char* index, const char* data, uint64_t version);
EXPORTED bool syscollector_parse_response(const unsigned char* data, size_t length);
EXPORTED bool syscollector_notify_data_clean(const char** indices, size_t indices_count);
EXPORTED void syscollector_delete_database();

// Query function
EXPORTED size_t syscollector_query(const char* query, char** output);

#ifdef __cplusplus
}
#endif

typedef void(*syscollector_init_func)(const unsigned int inverval,
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

typedef void(*syscollector_start_func)();
typedef void(*syscollector_stop_func)();

// Sync protocol C wrapper functions
typedef void(*syscollector_init_sync_func)(const char* moduleName, const char* syncDbPath, const MQ_Functions* mqFuncs, unsigned int syncEndDelay, unsigned int timeout, unsigned int retries,
                                           size_t maxEps);
typedef bool(*syscollector_sync_module_func)(Mode_t mode);
typedef void(*syscollector_persist_diff_func)(const char* id, Operation_t operation, const char* index, const char* data, uint64_t version);
typedef bool(*syscollector_parse_response_func)(const unsigned char* data, size_t length);
typedef bool(*syscollector_notify_data_clean_func)(const char** indices, size_t indices_count);
typedef void(*syscollector_delete_database_func)();

#endif //_SYSCOLLECTOR_H
