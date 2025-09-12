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

void syscollector_start(const unsigned int inverval,
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

    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&)> callbackPersistDiffWrapper
    {
        [callbackPersistDiff](const std::string & id, Operation_t operation, const std::string & index, const std::string & data)
        {
            callbackPersistDiff(id.c_str(), operation, index.c_str(), data.c_str());
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
    }
}
void syscollector_stop()
{
    Syscollector::instance().destroy();
}

void syscollector_init_sync(const char* moduleName, const char* syncDbPath, const MQ_Functions* mqFuncs)
{
    if (moduleName && syncDbPath && mqFuncs)
    {
        Syscollector::instance().initSyncProtocol(std::string(moduleName), std::string(syncDbPath), *mqFuncs);
    }
}

bool syscollector_sync_module(Mode_t mode, unsigned int timeout, unsigned int retries, unsigned int maxEps)
{
    Mode syncMode = (mode == MODE_FULL) ? Mode::FULL : Mode::DELTA;
    return Syscollector::instance().syncModule(syncMode, std::chrono::seconds(timeout), retries, maxEps);
}

void syscollector_persist_diff(const char* id, Operation_t operation, const char* index, const char* data)
{
    if (id && index && data)
    {
        Operation cppOperation = (operation == OPERATION_CREATE) ? Operation::CREATE :
                                 (operation == OPERATION_MODIFY) ? Operation::MODIFY :
                                 (operation == OPERATION_DELETE) ? Operation::DELETE_ : Operation::NO_OP;
        Syscollector::instance().persistDifference(std::string(id), cppOperation, std::string(index), std::string(data));
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

#ifdef __cplusplus
}
#endif
