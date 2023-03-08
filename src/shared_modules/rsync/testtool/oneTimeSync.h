/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * September 18, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _ONE_TIME_SYNC_H_
#define _ONE_TIME_SYNC_H_

#include "json.hpp"
#include "rsync.h"
#include "dbsync.h"


class OneTimeSync final
{
    public:
        OneTimeSync(const nlohmann::json& config,
                    const nlohmann::json& inputData,
                    const std::string& outputFolder,
                    const size_t maxQueueSize);
        ~OneTimeSync();
        void syncData();
        void pushData();
        void startSync();
    private:
        static void rsyncCallback(const void* buffer, size_t bufferSize, void* userData);
        static void syncCallback(ReturnTypeCallback result_type, const cJSON* result_json, void* user_data);

        const RSYNC_HANDLE m_rsyncHandle;
        const DBSYNC_HANDLE m_dbSyncHandle;
        const nlohmann::json m_inputData;
        const std::string m_outputFolder;
};


#endif //_ONE_TIME_SYNC_H_