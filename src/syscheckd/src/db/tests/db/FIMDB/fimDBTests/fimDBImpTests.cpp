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

#ifndef _FIMDB_CPP_UNIT_TEST
#define _FIMDB_CPP_UNIT_TEST

#include "fimDBImpTests.hpp"
#include <thread>
#include "fimDBSpecialization.h"

constexpr auto MOCK_DB_PATH {"temp_fimdb_ut.db"};
constexpr auto MOCK_DB_MEM {":memory:"};
MockLoggingCall* mockLog;
MockSyncMsg* mockSync;

void mockLoggingFunction(const modules_log_level_t logLevel, const char* tag)
{
    mockLog->loggingFunction(logLevel, tag);
}

void mockSyncMessage(const char* log, const char* tag)
{
    mockSync->syncMsg(log, tag);
}

class FimDBWinFixture : public ::testing::Test
{
    protected:
        MockDBSyncHandler* mockDBSync;
        MockRSyncHandler* mockRSync;
        MockFIMDB fimDBMock;
        unsigned int mockIntervalSync;
        unsigned int mockMaxRowsFile;
        unsigned int mockMaxRowsReg;
        unsigned int syncResponseTimeout;
        unsigned int syncMaxInterval;
        bool syncRegistryEnabled;

        void SetUp() override
        {
            constexpr auto MOCK_SQL_STATEMENT
            {
                R"(CREATE TABLE mock_db (
                mock_text TEXT,
                PRIMARY KEY (mock_text))
                )"
            };

            mockIntervalSync = 900;
            mockMaxRowsFile = 1000;
            mockMaxRowsReg = 1000;
            syncResponseTimeout = 30;
            syncMaxInterval = 2000;
            syncRegistryEnabled = 1;

            std::function<void(const std::string&)> callbackSyncFileWrapper
            {
                [](const std::string & msg)
                {
                    mockSyncMessage(FIM_COMPONENT_FILE, msg.c_str());
                }
            };

            std::function<void(const std::string&)> callbackSyncRegistryWrapper
            {
                [](const std::string & msg)
                {
                    mockSyncMessage(FIM_COMPONENT_REGISTRY_KEY, msg.c_str());
                }
            };

            std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper
            {
                [](modules_log_level_t level, const std::string & log)
                {
                    mockLoggingFunction(level, log.c_str());
                }
            };

            std::shared_ptr<DBSync> dbsyncHandler = std::make_unique<MockDBSyncHandler>(HostType::AGENT, DbEngineType::SQLITE3,
                                                                                        MOCK_DB_PATH, MOCK_SQL_STATEMENT);
            std::shared_ptr<RemoteSync> rsyncHandler = std::make_shared<MockRSyncHandler>();
            mockDBSync = (MockDBSyncHandler*) dbsyncHandler.get();
            mockRSync = (MockRSyncHandler*) rsyncHandler.get();
            mockLog = new MockLoggingCall();
            mockSync = new MockSyncMsg();

            fimDBMock.init(mockIntervalSync,
                           syncMaxInterval,
                           syncResponseTimeout,
                           callbackSyncFileWrapper,
                           callbackSyncRegistryWrapper,
                           callbackLogWrapper,
                           dbsyncHandler,
                           rsyncHandler,
                           mockMaxRowsFile,
                           mockMaxRowsReg,
                           syncRegistryEnabled);
        }

        void TearDown() override
        {
            fimDBMock.teardown();
            std::remove(MOCK_DB_PATH);
            delete mockLog;
            delete mockSync;
        };
};

class FimDBFixture : public ::testing::Test
{
    protected:
        MockDBSyncHandler* mockDBSync;
        MockRSyncHandler* mockRSync;
        MockFIMDB fimDBMock;
        unsigned int mockIntervalSync;
        unsigned int mockMaxRowsFile;
        unsigned int mockMaxRowsReg;
        unsigned int syncResponseTimeout;
        unsigned int syncMaxInterval;
        bool syncRegistryEnabled;

        void SetUp() override
        {
            constexpr auto MOCK_SQL_STATEMENT
            {
                R"(CREATE TABLE mock_db (
                mock_text TEXT,
                PRIMARY KEY (mock_text))
                )"
            };

            mockIntervalSync = 900;
            mockMaxRowsFile = 1000;
            mockMaxRowsReg = 1000;
            syncResponseTimeout = 30;
            syncMaxInterval = 2000;
            syncRegistryEnabled = 1;

            std::function<void(const std::string&)> callbackSyncFileWrapper
            {
                [](const std::string & msg)
                {
                    mockSyncMessage(FIM_COMPONENT_FILE, msg.c_str());
                }
            };

            std::function<void(const std::string&)> callbackSyncRegistryWrapper
            {
                [](const std::string & msg)
                {
                    mockSyncMessage(FIM_COMPONENT_REGISTRY_KEY, msg.c_str());
                }
            };

            std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper
            {
                [](modules_log_level_t level, const std::string & log)
                {
                    mockLoggingFunction(level, log.c_str());
                }
            };

            std::shared_ptr<DBSync> dbsyncHandler = std::make_unique<MockDBSyncHandler>(HostType::AGENT, DbEngineType::SQLITE3,
                                                                                        MOCK_DB_PATH, MOCK_SQL_STATEMENT);
            std::shared_ptr<RemoteSync> rsyncHandler = std::make_shared<MockRSyncHandler>();
            mockDBSync = (MockDBSyncHandler*) dbsyncHandler.get();
            mockRSync = (MockRSyncHandler*) rsyncHandler.get();
            mockLog = new MockLoggingCall();
            mockSync = new MockSyncMsg();

            EXPECT_CALL((*mockDBSync), setTableMaxRow("file_entry", mockMaxRowsFile));

#ifdef WIN32
            EXPECT_CALL((*mockDBSync), setTableMaxRow("registry_key", mockMaxRowsReg));
            EXPECT_CALL((*mockDBSync), setTableMaxRow("registry_data", mockMaxRowsReg));
#endif

            fimDBMock.init(mockIntervalSync,
                           syncMaxInterval,
                           syncResponseTimeout,
                           callbackSyncFileWrapper,
                           callbackSyncRegistryWrapper,
                           callbackLogWrapper,
                           dbsyncHandler,
                           rsyncHandler,
                           mockMaxRowsFile,
                           mockMaxRowsReg,
                           syncRegistryEnabled);
        }

        void TearDown() override
        {
            fimDBMock.teardown();
            std::remove(MOCK_DB_PATH);
            delete mockLog;
            delete mockSync;
        };
};

TEST_F(FimDBFixture, dbSyncHandlerInitSuccess)
{
    ASSERT_NE(fimDBMock.DBSyncHandler()->handle(), nullptr);
}

TEST_F(FimDBFixture, insertItemSuccess)
{
    nlohmann::json itemJson;
    ResultCallbackData callback;
    EXPECT_CALL(*mockDBSync, syncRow(itemJson, testing::_));
    fimDBMock.updateItem(itemJson, callback);
}

TEST_F(FimDBFixture, removeItemSuccess)
{
    nlohmann::json itemJson;
    EXPECT_CALL(*mockDBSync, deleteRows(itemJson));
    fimDBMock.removeItem(itemJson);
}

TEST_F(FimDBFixture, updateItemSuccess)
{
    nlohmann::json itemJson;
    ResultCallbackData callback;
    EXPECT_CALL(*mockDBSync, syncRow(itemJson, testing::_));
    fimDBMock.updateItem(itemJson, callback);
}

TEST_F(FimDBFixture, registerSyncIDSuccess)
{
    EXPECT_CALL(*mockRSync, registerSyncID(testing::_, testing::_, testing::_, testing::_)).Times(testing::AtLeast(1));

    fimDBMock.registerRSync();

}

#ifdef WIN32
TEST_F(FimDBFixture, registerSyncIDSuccessWindows)
{
    EXPECT_CALL(*mockRSync, registerSyncID(testing::_, testing::_, testing::_, testing::_)).Times(testing::AtLeast(3));

    fimDBMock.registerRSync();

}
#endif

TEST_F(FimDBFixture, registerSyncIDError)
{
    EXPECT_CALL(*mockRSync, registerSyncID(testing::_, testing::_, testing::_, testing::_)).Times(testing::AtLeast(1));

    fimDBMock.registerRSync();
}

TEST_F(FimDBFixture, loopRSyncSuccess)
{
    std::mutex test_mutex;

    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "FIM sync module started."));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG, "Executing FIM sync."));
    EXPECT_CALL(*mockRSync, startSync(testing::_, testing::_, testing::_)).Times(testing::AtLeast(1));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG, "Finished FIM sync."));
    EXPECT_CALL(*mockRSync, registerSyncID(testing::_, testing::_, testing::_, testing::_)).Times(testing::AtLeast(1));

    fimDBMock.runIntegrity();
}

TEST_F(FimDBFixture, syncAlgorithmLoop)
{
    EXPECT_CALL(fimDBMock, getCurrentTime()).WillOnce(testing::Return(15)).WillOnce(testing::Return(30));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG_VERBOSE, "Sync still in progress. Skipped next sync and increased interval to '1800s'"));

    fimDBMock.setTimeLastSyncMsg();
    fimDBMock.syncAlgorithm();

    EXPECT_CALL(fimDBMock, getCurrentTime()).WillOnce(testing::Return(15)).WillOnce(testing::Return(30));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG_VERBOSE, "Sync still in progress. Skipped next sync and increased interval to '2000s'"));

    fimDBMock.setTimeLastSyncMsg();
    fimDBMock.syncAlgorithm();

    EXPECT_CALL(fimDBMock, getCurrentTime()).WillOnce(testing::Return(15)).WillOnce(testing::Return(60));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG_VERBOSE, "Previous sync was successful. Sync interval is reset to: '900s'"));

    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG, "Executing FIM sync."));
    EXPECT_CALL(*mockRSync, startSync(testing::_, testing::_, testing::_)).Times(testing::AtLeast(1));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG, "Finished FIM sync."));

    fimDBMock.setTimeLastSyncMsg();
    fimDBMock.syncAlgorithm();
}

TEST_F(FimDBFixture, executeQuerySuccess)
{
    nlohmann::json itemJson;
    ResultCallbackData callback;
    EXPECT_CALL(*mockDBSync, selectRows(itemJson, testing::_));
    fimDBMock.executeQuery(itemJson, callback);
}

TEST_F(FimDBFixture, executeQueryFailMaxRows)
{
    nlohmann::json itemJson;
    ResultCallbackData callback;
    EXPECT_CALL(*mockDBSync, selectRows(itemJson, testing::_));
    fimDBMock.executeQuery(itemJson, callback);
}

TEST_F(FimDBFixture, executeQueryFailException)
{
    nlohmann::json itemJson;
    ResultCallbackData callback;
    EXPECT_CALL(*mockDBSync, selectRows(itemJson, testing::_));
    fimDBMock.executeQuery(itemJson, callback);
}

TEST_F(FimDBFixture, fimSyncPushMsgSuccess)
{
    const std::string data("testing msg");
    auto rawData{data};
    const auto buff{reinterpret_cast<const uint8_t*>(rawData.c_str())};

    EXPECT_CALL(fimDBMock, getCurrentTime()).WillOnce(testing::Return(100));
    EXPECT_CALL(*mockRSync, pushMessage(std::vector<uint8_t> {buff, buff + rawData.size()}));

    fimDBMock.pushMessage(data);
}

TEST_F(FimDBFixture, fimSyncPushMsgException)
{
    const std::string data("testing msg");
    auto rawData{data};
    const auto buff{reinterpret_cast<const uint8_t*>(rawData.c_str())};

    EXPECT_CALL(fimDBMock, getCurrentTime()).WillOnce(testing::Return(100));
    EXPECT_CALL(*mockRSync, pushMessage(std::vector<uint8_t> {buff, buff + rawData.size()})).WillOnce(testing::Throw(std::exception()));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, testing::_));

    fimDBMock.pushMessage(data);
}

TEST_F(FimDBFixture, logAnExceptionErr)
{
    EXPECT_CALL(*mockLog, loggingFunction(testing::_, testing::_));
    fimDBMock.logFunction(LOG_DEBUG_VERBOSE, "This is an error");
}

TEST(FimDB, notInitalizedDbSyncException)
{
    MockFIMDB fimDBMock;
    EXPECT_THROW(
    {
        ASSERT_EQ(fimDBMock.DBSyncHandler()->handle(), nullptr);
    }, std::runtime_error);
}

TEST_F(FimDBFixture, loopRSyncInvalidCallOrder)
{
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "FIM sync module started."));
    fimDBMock.stopIntegrity();
    fimDBMock.runIntegrity();
}

#endif
