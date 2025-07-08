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

#ifdef __cplusplus
extern "C" {
#endif
#include "../../wm_syscollector.h"

void syscollector_start(const unsigned int inverval,
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
                        const bool hotfixes,
                        const bool groups,
                        const bool users)
{
    std::function<void(const std::string&)> callbackDiffWrapper
    {
        [callbackDiff](const std::string & data)
        {
            callbackDiff(data.c_str());
        }
    };

    std::function<void(const std::string&)> callbackSyncWrapper
    {
        [callbackSync](const std::string & data)
        {
            callbackSync(data.c_str());
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
                                      std::move(callbackSyncWrapper),
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
                                      users);
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

int syscollector_sync_message(const char* data)
{
    int ret{-1};

    try
    {
        Syscollector::instance().push(data);
        ret = 0;
    }
    catch (...)
    {
    }

    return ret;
}


#ifdef __cplusplus
}
#endif
