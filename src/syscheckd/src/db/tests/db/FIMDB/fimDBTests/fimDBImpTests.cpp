/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
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

        void SetUp() override
        {
            constexpr auto MOCK_SQL_STATEMENT
            {
                R"(CREATE TABLE mock_db (
                mock_text TEXT,
                PRIMARY KEY (mock_text))
                )"
            };

            mockIntervalSync = 1000;
            mockMaxRowsFile = 1000;
            mockMaxRowsReg = 1000;

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
                    mockSyncMessage(FIM_COMPONENT_REGISTRY, msg.c_str());
                }
            };

            std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper
            {
                [](modules_log_level_t level, const std::string & log)
                {
                    mockLoggingFunction(level, log.c_str());
                }
            };

            std::unique_ptr<DBSync> dbsyncHandler = std::make_unique<MockDBSyncHandler>(HostType::AGENT, DbEngineType::SQLITE3,
                                                                                        MOCK_DB_PATH, MOCK_SQL_STATEMENT);
            std::unique_ptr<RemoteSync> rsyncHandler = std::make_unique<MockRSyncHandler>();
            mockDBSync = (MockDBSyncHandler*) dbsyncHandler.get();
            mockRSync = (MockRSyncHandler*) rsyncHandler.get();
            mockLog = new MockLoggingCall();
            mockSync = new MockSyncMsg();
            EXPECT_CALL((*mockDBSync), setTableMaxRow("file_entry", mockMaxRowsFile));

            EXPECT_CALL((*mockDBSync), setTableMaxRow("registry_key", mockMaxRowsReg));
            EXPECT_CALL((*mockDBSync), setTableMaxRow("registry_data", mockMaxRowsReg));

            fimDBMock.init(mockIntervalSync,
                           callbackSyncFileWrapper,
                           callbackSyncRegistryWrapper,
                           callbackLogWrapper,
                           std::move(dbsyncHandler),
                           std::move(rsyncHandler),
                           mockMaxRowsFile,
                           mockMaxRowsReg,
                           true);
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

        void SetUp() override
        {
            constexpr auto MOCK_SQL_STATEMENT
            {
                R"(CREATE TABLE mock_db (
                mock_text TEXT,
                PRIMARY KEY (mock_text))
                )"
            };

            mockIntervalSync = 1000;
            mockMaxRowsFile = 1000;
            mockMaxRowsReg = 1000;

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
                    mockSyncMessage(FIM_COMPONENT_REGISTRY, msg.c_str());
                }
            };

            std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper
            {
                [](modules_log_level_t level, const std::string & log)
                {
                    mockLoggingFunction(level, log.c_str());
                }
            };

            std::unique_ptr<DBSync> dbsyncHandler = std::make_unique<MockDBSyncHandler>(HostType::AGENT, DbEngineType::SQLITE3,
                                                                                        MOCK_DB_PATH, MOCK_SQL_STATEMENT);
            std::unique_ptr<RemoteSync> rsyncHandler = std::make_unique<MockRSyncHandler>();
            mockDBSync = (MockDBSyncHandler*) dbsyncHandler.get();
            mockRSync = (MockRSyncHandler*) rsyncHandler.get();
            mockLog = new MockLoggingCall();
            mockSync = new MockSyncMsg();
            EXPECT_CALL((*mockDBSync), setTableMaxRow("file_entry", mockMaxRowsFile));

            fimDBMock.init(mockIntervalSync,
                           callbackSyncFileWrapper,
                           callbackSyncRegistryWrapper,
                           callbackLogWrapper,
                           std::move(dbsyncHandler),
                           std::move(rsyncHandler),
                           mockMaxRowsFile,
                           mockMaxRowsReg,
                           false);
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
    ASSERT_NE(fimDBMock.DBSyncHandle(), nullptr);
}

TEST_F(FimDBFixture, setFileLimitSuccess)
{
    EXPECT_CALL((*mockDBSync), setTableMaxRow("file_entry", mockMaxRowsFile));
    fimDBMock.setFileLimit();
}

TEST_F(FimDBFixture, setFileLimitNoTableData)
{
    EXPECT_CALL(*mockDBSync, setTableMaxRow("file_entry", mockMaxRowsFile)).
    WillOnce(testing::Throw(DbSync::dbsync_error(6, "dbEngine: Empty table metadata."))); // EMPTY_TABLE_METADATA

    try
    {
        fimDBMock.setFileLimit();
    }
    catch (DbSync::dbsync_error& err)
    {
        ASSERT_EQ((std::string)(err.what()), "dbEngine: Empty table metadata.");
    }
}

TEST_F(FimDBWinFixture, setValueLimitSuccess)
{
    EXPECT_CALL(*mockDBSync, setTableMaxRow("registry_data", mockMaxRowsReg));
    fimDBMock.setValueLimit();
}

TEST_F(FimDBWinFixture, setRegistryLimitSuccess)
{
    EXPECT_CALL(*mockDBSync, setTableMaxRow("registry_key", mockMaxRowsReg));
    fimDBMock.setRegistryLimit();
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

TEST_F(FimDBWinFixture, registerSyncIDSuccess)
{
    EXPECT_CALL(*mockRSync, registerSyncID("fim_file", mockDBSync->handle(), nlohmann::json::parse(FIM_FILE_SYNC_CONFIG_STATEMENT), testing::_));
    EXPECT_CALL(*mockRSync, registerSyncID("fim_registry", mockDBSync->handle(), nlohmann::json::parse(FIM_REGISTRY_SYNC_CONFIG_STATEMENT), testing::_));

    fimDBMock.registerRSync();
}

TEST_F(FimDBFixture, registerSyncIDSuccess)
{
    EXPECT_CALL(*mockRSync, registerSyncID("fim_file", mockDBSync->handle(), nlohmann::json::parse(FIM_FILE_SYNC_CONFIG_STATEMENT), testing::_));

    fimDBMock.registerRSync();

}

TEST_F(FimDBFixture, registerSyncIDError)
{
    EXPECT_CALL(*mockRSync, registerSyncID("fim_file", mockDBSync->handle(), nlohmann::json::parse(FIM_FILE_SYNC_CONFIG_STATEMENT), testing::_));

    fimDBMock.registerRSync();

}

TEST_F(FimDBWinFixture, loopWinRSyncSuccess)
{
    std::mutex test_mutex;

    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "FIM sync module started."));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "Executing FIM sync."));
    EXPECT_CALL(*mockRSync, startSync(mockDBSync->handle(), nlohmann::json::parse(FIM_FILE_START_CONFIG_STATEMENT), testing::_));
    EXPECT_CALL(*mockRSync, startSync(mockDBSync->handle(), nlohmann::json::parse(FIM_REGISTRY_START_CONFIG_STATEMENT), testing::_));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "Finished FIM sync."));

    std::unique_lock<std::mutex> lock{test_mutex};
    std::thread syncThread(&FIMDB::loopRSync, &fimDBMock, std::ref(lock));

    fimDBMock.stopIntegrity();

    syncThread.join();

}

TEST_F(FimDBFixture, loopRSyncSuccess)
{
    std::mutex test_mutex;

    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "FIM sync module started."));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "Executing FIM sync."));
    EXPECT_CALL(*mockRSync, startSync(mockDBSync->handle(), nlohmann::json::parse(FIM_FILE_START_CONFIG_STATEMENT), testing::_));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "Finished FIM sync."));

    std::unique_lock<std::mutex> lock{test_mutex};
    std::thread syncThread(&FIMDB::loopRSync, &fimDBMock, std::ref(lock));

    fimDBMock.stopIntegrity();

    syncThread.join();

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

    EXPECT_CALL(*mockRSync, pushMessage(std::vector<uint8_t> {buff, buff + rawData.size()}));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG_VERBOSE, "Message pushed: " + data));

    fimDBMock.pushMessage(data);
}

TEST_F(FimDBFixture, fimSyncPushMsgException)
{
    const std::string data("testing msg");
    auto rawData{data};
    const auto buff{reinterpret_cast<const uint8_t*>(rawData.c_str())};

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
        ASSERT_EQ(fimDBMock.DBSyncHandle(), nullptr);
    }, std::runtime_error);
}

TEST_F(FimDBFixture, fimRunIntegritySuccess)
{

    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "FIM sync module started."));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "Executing FIM sync."));
    EXPECT_CALL(*mockRSync, startSync(mockDBSync->handle(), nlohmann::json::parse(FIM_FILE_START_CONFIG_STATEMENT), testing::_));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "Finished FIM sync."));
    EXPECT_CALL(*mockRSync, registerSyncID("fim_file", mockDBSync->handle(), nlohmann::json::parse(FIM_FILE_SYNC_CONFIG_STATEMENT), testing::_));
    EXPECT_NO_THROW(
    {
        std::thread integrityThread(&FIMDB::runIntegrity, &fimDBMock);

        fimDBMock.stopIntegrity();
        integrityThread.join();
    });
}


#endif
