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

void mockLoggingFunction(const modules_log_level_t logLevel, const char* tag)
{
    mockLog->loggingFunction(logLevel, tag);
}

class FimDBWinFixture : public ::testing::Test
{
    protected:
        MockDBSyncHandler* mockDBSync;
        MockFIMDB fimDBMock;
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

            mockMaxRowsFile = 1000;
            mockMaxRowsReg = 1000;

            std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper
            {
                [](modules_log_level_t level, const std::string & log)
                {
                    mockLoggingFunction(level, log.c_str());
                }
            };

            std::shared_ptr<DBSync> dbsyncHandler = std::make_unique<MockDBSyncHandler>(HostType::AGENT, DbEngineType::SQLITE3,
                                                                                        MOCK_DB_PATH, MOCK_SQL_STATEMENT);
            mockDBSync = (MockDBSyncHandler*) dbsyncHandler.get();
            mockLog = new MockLoggingCall();

            fimDBMock.init(callbackLogWrapper,
                           dbsyncHandler,
                           mockMaxRowsFile,
                           mockMaxRowsReg);
        }

        void TearDown() override
        {
            fimDBMock.teardown();
            std::remove(MOCK_DB_PATH);
            delete mockLog;
        };
};

class FimDBFixture : public ::testing::Test
{
    protected:
        MockDBSyncHandler* mockDBSync;
        MockFIMDB fimDBMock;
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

            mockMaxRowsFile = 1000;
            mockMaxRowsReg = 1000;

            std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper
            {
                [](modules_log_level_t level, const std::string & log)
                {
                    mockLoggingFunction(level, log.c_str());
                }
            };

            std::shared_ptr<DBSync> dbsyncHandler = std::make_unique<MockDBSyncHandler>(HostType::AGENT, DbEngineType::SQLITE3,
                                                                                        MOCK_DB_PATH, MOCK_SQL_STATEMENT);
            mockDBSync = (MockDBSyncHandler*) dbsyncHandler.get();
            mockLog = new MockLoggingCall();

            EXPECT_CALL((*mockDBSync), setTableMaxRow("file_entry", mockMaxRowsFile));

#ifdef WIN32
            EXPECT_CALL((*mockDBSync), setTableMaxRow("registry_key", mockMaxRowsReg));
            EXPECT_CALL((*mockDBSync), setTableMaxRow("registry_data", mockMaxRowsReg));
#endif

            fimDBMock.init(callbackLogWrapper,
                           dbsyncHandler,
                           mockMaxRowsFile,
                           mockMaxRowsReg);
        }

        void TearDown() override
        {
            fimDBMock.teardown();
            std::remove(MOCK_DB_PATH);
            delete mockLog;
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

#endif
