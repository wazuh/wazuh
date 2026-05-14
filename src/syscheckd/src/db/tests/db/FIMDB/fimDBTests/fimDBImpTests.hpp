/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * November 23, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FIMDB_IMP_TEST_H
#define _FIMDB_IMP_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "fimDB.hpp"
#include "dbItem.hpp"
#include "fimCommonDefs.h"

class MockDBSyncHandler: public DBSync
{

    public:
        MockDBSyncHandler(const HostType hostType,
                          const DbEngineType dbType,
                          const std::string& path,
                          const std::string& sqlStatement): DBSync(hostType, dbType, path, sqlStatement) {};
        ~MockDBSyncHandler() {};
        MOCK_METHOD(void, setTableMaxRow, (const std::string&, const long long), (override));
        MOCK_METHOD(void, insertData, (const nlohmann::json&), (override));
        MOCK_METHOD(void, deleteRows, (const nlohmann::json&), (override));
        MOCK_METHOD(void, syncRow, (const nlohmann::json&, ResultCallbackData), (override));
        MOCK_METHOD(void, selectRows, (const nlohmann::json&, ResultCallbackData), (override));
};

class MockRSyncHandler: public RemoteSync
{

    public:
        MockRSyncHandler() {};
        ~MockRSyncHandler() {};
        MOCK_METHOD(void, registerSyncID, (const std::string&, const DBSYNC_HANDLE, const nlohmann::json&, SyncCallbackData), (override));
        MOCK_METHOD(void, startSync, (const DBSYNC_HANDLE, const nlohmann::json&, SyncCallbackData), (override));
        MOCK_METHOD(void, pushMessage, (const std::vector<uint8_t>&), (override));
};

class MockFIMDB: public FIMDB
{
    public:
        MockFIMDB() {};
        ~MockFIMDB() {};

        void stopIntegrity()
        {
            FIMDB::stopIntegrity();
        }

        void teardown()
        {
            FIMDB::teardown();
        }

        void runIntegrity()
        {
            FIMDB::runIntegrity();
        }

        void syncAlgorithm()
        {
            FIMDB::syncAlgorithm();
        }

        void setTimeLastSyncMsg()
        {
            FIMDB::setTimeLastSyncMsg();
        }

        MOCK_METHOD(time_t, getCurrentTime, (), (const override));
};

class MockLoggingCall
{
    public:
        MOCK_METHOD(void, loggingFunction, (const modules_log_level_t, const std::string&), ());
};

class MockSyncMsg
{
    public:
        MOCK_METHOD(void, syncMsg, (const std::string&, const std::string&), ());
};

#endif //_FIMDB_IMP_TEST_H
