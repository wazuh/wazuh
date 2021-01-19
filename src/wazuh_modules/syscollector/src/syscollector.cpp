/*
 * Wazuh SysCollector
 * Copyright (C) 2015-2020, Wazuh Inc.
 * November 15, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syscollector.h"
#include "syscollector.hpp"
#include "sysInfo.hpp"
#include <iostream>

#ifdef __cplusplus
extern "C" {
#endif
void syscollector_start(const unsigned int inverval,
                        send_data_callback_t callbackDiff,
                        send_data_callback_t callbackSync,
                        log_error_callback_t callbackLogError,
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
                        const bool hotfixes)
{
    std::function<void(const std::string&)> callbackDiffWrapper
    {
        [callbackDiff](const std::string& data)
        {
            callbackDiff(data.c_str());
        }
    };

    std::function<void(const std::string&)> callbackSyncWrapper
    {
        [callbackSync](const std::string& data)
        {
            callbackSync(data.c_str());
        }
    };

    std::function<void(const std::string&)> callbackLogErrorWrapper
    {
        [callbackLogError](const std::string& data)
        {
            callbackLogError(data.c_str());
        }
    };
    try
    {
        Syscollector::instance().init(std::make_shared<SysInfo>(),
                                      callbackDiffWrapper,
                                      callbackSyncWrapper,
                                      callbackLogErrorWrapper,
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
                                      hotfixes);
    }
    catch(const std::exception& ex)
    {
        callbackLogErrorWrapper(ex.what());
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
    catch(...)
    {
    }
    return ret;
}


#ifdef __cplusplus
}
#endif