/*
 * Wazuh SysCollector
 * Copyright (C) 2015, Wazuh Inc.
 * November 15, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "syscollector.hpp"
#include "sysInfo.hpp"
#include "dbsync.hpp"
#include <iostream>
#include <chrono>

#ifdef __cplusplus
extern "C" {
#endif
#include "../../wm_syscollector.h"
#include "../../module_query_errors.h"

void syscollector_init(const unsigned int inverval,
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
                       const bool notifyOnFirstScan)
{
    std::function<void(const std::string&)> callbackDiffWrapper
    {
        [callbackDiff](const std::string & data)
        {
            callbackDiff(data.c_str());
        }
    };

    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackPersistDiffWrapper
    {
        [callbackPersistDiff](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            callbackPersistDiff(id.c_str(), operation, index.c_str(), data.c_str(), version);
        }
    };

    std::function<void(const modules_log_level_t, const std::string&)> callbackLogWrapper
    {
        [callbackLog](const modules_log_level_t level, const std::string & data)
        {
            callbackLog(level, data.c_str(), WM_SYS_LOGTAG);
        }
    };

    std::function<void(const std::string&)> callbackErrorLogWrapper
    {
        [callbackLog](const std::string & data)
        {
            callbackLog(LOG_ERROR, data.c_str(), WM_SYS_LOGTAG);
        }
    };

    DBSync::initialize(callbackErrorLogWrapper);

    try
    {
        Syscollector::instance().init(std::make_shared<SysInfo>(),
                                      std::move(callbackDiffWrapper),
                                      std::move(callbackPersistDiffWrapper),
                                      std::move(callbackLogWrapper),
                                      dbPath,
                                      normalizerConfigPath,
                                      normalizerType,
                                      inverval,
                                      scanOnStart,
                                      hardware,
                                      os,
                                      network,
                                      packages,
                                      ports,
                                      portsAll,
                                      processes,
                                      hotfixes,
                                      groups,
                                      users,
                                      services,
                                      browserExtensions,
                                      notifyOnFirstScan);
    }
    catch (const std::exception& ex)
    {
        callbackErrorLogWrapper(ex.what());
        // DO NOT re-throw - this is called from C code which cannot catch C++ exceptions
        // The module will be in a failed state and subsequent calls will be no-ops
    }
}

void syscollector_start()
{
    Syscollector::instance().start();
}

void syscollector_stop()
{
    Syscollector::instance().destroy();
}

void syscollector_init_sync(const char* moduleName, const char* syncDbPath, const MQ_Functions* mqFuncs)
{
    if (moduleName && syncDbPath && mqFuncs)
    {
        try
        {
            Syscollector::instance().initSyncProtocol(std::string(moduleName), std::string(syncDbPath), *mqFuncs);
        }
        catch (const std::exception& ex)
        {
            // Log error but don't crash - module will continue without sync protocol
            auto callbackErrorLogWrapper = [](const std::string & data)
            {
                // Use syscollector's logging - this will reach the C logging system
                fprintf(stderr, "Syscollector sync protocol initialization failed: %s\n", data.c_str());
            };
            callbackErrorLogWrapper(ex.what());
        }
    }
}

bool syscollector_sync_module(Mode_t mode, unsigned int timeout, unsigned int retries, unsigned int maxEps)
{
    Mode syncMode = (mode == MODE_FULL) ? Mode::FULL : Mode::DELTA;
    return Syscollector::instance().syncModule(syncMode, std::chrono::seconds(timeout), retries, maxEps);
}

void syscollector_persist_diff(const char* id, Operation_t operation, const char* index, const char* data, uint64_t version)
{
    if (id && index && data)
    {
        Operation cppOperation = (operation == OPERATION_CREATE) ? Operation::CREATE :
                                 (operation == OPERATION_MODIFY) ? Operation::MODIFY :
                                 (operation == OPERATION_DELETE) ? Operation::DELETE_ : Operation::NO_OP;
        Syscollector::instance().persistDifference(std::string(id), cppOperation, std::string(index), std::string(data), version);
    }
}

bool syscollector_parse_response(const unsigned char* data, size_t length)
{
    if (data)
    {
        return Syscollector::instance().parseResponseBuffer(data, length);
    }

    return false;
}

bool syscollector_notify_data_clean(const char** indices, size_t indices_count, unsigned int timeout, unsigned int retries, size_t max_eps)
{
    if (indices && indices_count > 0)
    {
        std::vector<std::string> indicesVec;
        indicesVec.reserve(indices_count);

        for (size_t i = 0; i < indices_count; ++i)
        {
            if (indices[i])
            {
                indicesVec.emplace_back(indices[i]);
            }
        }

        if (!indicesVec.empty())
        {
            return Syscollector::instance().notifyDataClean(indicesVec, std::chrono::seconds(timeout), retries, max_eps);
        }
    }

    return false;
}

void syscollector_delete_database()
{
    Syscollector::instance().deleteDatabase();
}

/// @brief Query handler for Syscollector module.
///
/// Handles query commands sent to the Syscollector module from other modules.
/// Supports commands like "pause", "resume", and "status".
///
/// @param json_query Json query command string
/// @param output Pointer to output string (caller must free with os_free)
/// @return Length of the output string
size_t syscollector_query(const char* json_query, char** output)
{
    if (!json_query || !output)
    {
        return 0;
    }

    try
    {
        std::string result = Syscollector::instance().query(std::string(json_query));
        *output = strdup(result.c_str());
        return strlen(*output);
    }
    catch (const std::exception& ex)
    {
        std::string error = "{\"error\":" + std::to_string(MQ_ERR_EXCEPTION) + ",\"message\":\"Exception in query handler: " + std::string(ex.what()) + "\"}";
        *output = strdup(error.c_str());
        return strlen(*output);
    }
}

#ifdef __cplusplus
}
#endif
