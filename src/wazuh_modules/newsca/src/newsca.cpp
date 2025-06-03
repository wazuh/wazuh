/*
 * Wazuh NewSca
 * Copyright (C) 2015, Wazuh Inc.
 * November 15, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "newsca.hpp"
#include "dbsync.hpp"
#include "sysInfo.hpp"
#include <iostream>

#ifdef __cplusplus
extern "C"
{
#endif
#include "../../wm_newsca.h"

    void newsca_start(const unsigned int inverval,
                      send_data_callback_t callbackDiff,
                      send_data_callback_t callbackSync,
                      log_callback_t callbackLog,
                      const char* dbPath,
                      const char* normalizerConfigPath,
                      const char* normalizerType)
    {
        std::function<void(const std::string&)> callbackDiffWrapper {[callbackDiff](const std::string& data)
                                                                     {
                                                                         callbackDiff(data.c_str());
                                                                     }};

        std::function<void(const std::string&)> callbackSyncWrapper {[callbackSync](const std::string& data)
                                                                     {
                                                                         callbackSync(data.c_str());
                                                                     }};

        std::function<void(const modules_log_level_t, const std::string&)> callbackLogWrapper {
            [callbackLog](const modules_log_level_t level, const std::string& data)
            {
                callbackLog(level, data.c_str(), WM_NEWSCA_LOGTAG);
            }};

        std::function<void(const std::string&)> callbackErrorLogWrapper {
            [callbackLog](const std::string& data)
            {
                callbackLog(LOG_ERROR, data.c_str(), WM_NEWSCA_LOGTAG);
            }};

        DBSync::initialize(callbackErrorLogWrapper);

        try
        {
            NewSca::instance().init(std::make_shared<SysInfo>(),
                                    std::move(callbackDiffWrapper),
                                    std::move(callbackSyncWrapper),
                                    std::move(callbackLogWrapper),
                                    dbPath,
                                    normalizerConfigPath,
                                    normalizerType,
                                    inverval);
        }
        catch (const std::exception& ex)
        {
            callbackErrorLogWrapper(ex.what());
        }
    }
    void newsca_stop()
    {
        NewSca::instance().destroy();
    }

    int newsca_sync_message(const char* data)
    {
        int ret {-1};

        try
        {
            NewSca::instance().push(data);
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
