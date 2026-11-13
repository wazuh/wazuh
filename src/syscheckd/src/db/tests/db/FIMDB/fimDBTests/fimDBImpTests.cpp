/*
 * Wazuh Syscheck
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FIMDB_CPP_UNIT_TEST
#define _FIMDB_CPP_UNIT_TEST

#include "fimDBImpTests.hpp"
#include "fimDBSpecialization.h"
#include <atomic>
#include <chrono>
#include <future>
#include <thread>

constexpr auto MOCK_DB_PATH {"temp_fimdb_ut.db"};
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
                )"};

            mockMaxRowsFile = 1000;
            mockMaxRowsReg = 1000;

            std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper
            {
                [](modules_log_level_t level, const std::string & log)
                {
                    mockLoggingFunction(level, log.c_str());
                }};

            std::shared_ptr<DBSync> dbsyncHandler = std::make_unique<MockDBSyncHandler>(
                                                        HostType::AGENT, DbEngineType::SQLITE3, MOCK_DB_PATH, MOCK_SQL_STATEMENT);
            mockDBSync = (MockDBSyncHandler*)dbsyncHandler.get();
            mockLog = new MockLoggingCall();

            fimDBMock.init(callbackLogWrapper, dbsyncHandler, mockMaxRowsFile, mockMaxRowsReg);
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
                )"};

            mockMaxRowsFile = 1000;
            mockMaxRowsReg = 1000;

            std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper
            {
                [](modules_log_level_t level, const std::string & log)
                {
                    mockLoggingFunction(level, log.c_str());
                }};

            std::shared_ptr<DBSync> dbsyncHandler = std::make_unique<MockDBSyncHandler>(
                                                        HostType::AGENT, DbEngineType::SQLITE3, MOCK_DB_PATH, MOCK_SQL_STATEMENT);
            mockDBSync = (MockDBSyncHandler*)dbsyncHandler.get();
            mockLog = new MockLoggingCall();

            EXPECT_CALL((*mockDBSync), setTableMaxRow("file_entry", mockMaxRowsFile));

#ifdef WIN32
            EXPECT_CALL((*mockDBSync), setTableMaxRow("registry_key", mockMaxRowsReg));
            EXPECT_CALL((*mockDBSync), setTableMaxRow("registry_data", mockMaxRowsReg));
#endif

            fimDBMock.init(callbackLogWrapper, dbsyncHandler, mockMaxRowsFile, mockMaxRowsReg);
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

TEST_F(FimDBFixture, executeQueryWhileStopping)
{
    nlohmann::json itemJson;
    ResultCallbackData callback;
    EXPECT_CALL(*mockDBSync, selectRows(testing::_, testing::_)).Times(0);
    EXPECT_CALL(*mockLog, loggingFunction(LOG_DEBUG, "Query not executed: FIMDB is not initialized or is shutting down"));
    fimDBMock.teardown();
    fimDBMock.executeQuery(itemJson, callback);
}

TEST_F(FimDBFixture, logAnExceptionErr)
{
    EXPECT_CALL(*mockLog, loggingFunction(testing::_, testing::_));
    fimDBMock.logFunction(LOG_DEBUG_VERBOSE, "This is an error");
}

TEST_F(FimDBFixture, closeAndDeleteDatabaseSuccess)
{
    EXPECT_CALL(*mockDBSync, closeAndDeleteDatabase());
    fimDBMock.closeAndDeleteDatabase();
}

TEST_F(FimDBFixture, removeItemReportsAfterTheRemoval)
{
    nlohmann::json itemJson;
    auto reported {false};
    EXPECT_CALL(*mockDBSync, deleteRows(itemJson)).WillOnce(testing::InvokeWithoutArgs([&reported]()
    {
        EXPECT_FALSE(reported);
    }));
    fimDBMock.removeItem(itemJson, [&reported]()
    {
        reported = true;
    });
    EXPECT_TRUE(reported);
}

TEST_F(FimDBFixture, setTableVersionRunsOneStatement)
{
    EXPECT_CALL(*mockDBSync, setEachEntryVersion("file_entry", 10));
    EXPECT_CALL(*mockDBSync, selectRows(testing::_, testing::_)).Times(0);
    EXPECT_CALL(*mockDBSync, syncRow(testing::_, testing::_)).Times(0);
    EXPECT_TRUE(fimDBMock.setTableVersion("file_entry", 10));
}

TEST_F(FimDBFixture, setTableVersionWaitsForUpdateItemInFlight)
{
    std::promise<void> entered;
    std::promise<void> release;
    std::atomic<bool> rowWritten {false};

    EXPECT_CALL(*mockDBSync, syncRow(testing::_, testing::_)).WillOnce(testing::InvokeWithoutArgs([&]()
    {
        entered.set_value();
        release.get_future().wait();
        rowWritten = true;
    }));
    EXPECT_CALL(*mockDBSync, setEachEntryVersion("file_entry", 10)).WillOnce(testing::InvokeWithoutArgs([&]()
    {
        EXPECT_TRUE(rowWritten);
    }));

    std::thread updater
    {
        [this]()
        {
            nlohmann::json itemJson;
            ResultCallbackData callback;
            fimDBMock.updateItem(itemJson, callback);
        }};
    ASSERT_EQ(entered.get_future().wait_for(std::chrono::seconds(10)), std::future_status::ready);

    auto versionSet {std::async(std::launch::async, [this]()
    {
        return fimDBMock.setTableVersion("file_entry", 10, std::chrono::seconds(10));
    })};
    EXPECT_EQ(versionSet.wait_for(std::chrono::milliseconds(200)), std::future_status::timeout);

    release.set_value();
    EXPECT_TRUE(versionSet.get());
    updater.join();
}

TEST_F(FimDBFixture, setTableVersionGivesUpWhileUpdateItemInFlight)
{
    std::promise<void> entered;
    std::promise<void> release;

    EXPECT_CALL(*mockDBSync, syncRow(testing::_, testing::_)).WillOnce(testing::InvokeWithoutArgs([&]()
    {
        entered.set_value();
        release.get_future().wait();
    }));
    EXPECT_CALL(*mockDBSync, setEachEntryVersion(testing::_, testing::_)).Times(0);

    std::thread updater
    {
        [this]()
        {
            nlohmann::json itemJson;
            ResultCallbackData callback;
            fimDBMock.updateItem(itemJson, callback);
        }};
    ASSERT_EQ(entered.get_future().wait_for(std::chrono::seconds(10)), std::future_status::ready);

    EXPECT_FALSE(fimDBMock.setTableVersion("file_entry", 10, std::chrono::milliseconds(100)));

    release.set_value();
    updater.join();
}

TEST_F(FimDBFixture, setTableVersionGivesUpWhileARemovalIsBeingReported)
{
    std::promise<void> entered;
    std::promise<void> release;

    EXPECT_CALL(*mockDBSync, deleteRows(testing::_));
    EXPECT_CALL(*mockDBSync, setEachEntryVersion(testing::_, testing::_)).Times(0);

    std::thread remover
    {
        [&]()
        {
            nlohmann::json itemJson;
            fimDBMock.removeItem(itemJson, [&]()
            {
                entered.set_value();
                release.get_future().wait();
            });
        }};
    ASSERT_EQ(entered.get_future().wait_for(std::chrono::seconds(10)), std::future_status::ready);

    EXPECT_FALSE(fimDBMock.setTableVersion("file_entry", 10, std::chrono::milliseconds(100)));

    release.set_value();
    remover.join();
}

TEST_F(FimDBFixture, quiesceWaitsForUpdateItemInFlight)
{
    std::promise<void> entered;
    std::promise<void> release;

    EXPECT_CALL(*mockDBSync, syncRow(testing::_, testing::_)).WillOnce(testing::InvokeWithoutArgs([&]()
    {
        entered.set_value();
        release.get_future().wait();
    }));

    std::thread updater
    {
        [this]()
        {
            nlohmann::json itemJson;
            ResultCallbackData callback;
            fimDBMock.updateItem(itemJson, callback);
        }};
    ASSERT_EQ(entered.get_future().wait_for(std::chrono::seconds(10)), std::future_status::ready);

    auto quiesced {std::async(std::launch::async, [this]()
    {
        fimDBMock.quiesce();
    })};
    EXPECT_EQ(quiesced.wait_for(std::chrono::milliseconds(200)), std::future_status::timeout);

    release.set_value();
    EXPECT_EQ(quiesced.wait_for(std::chrono::seconds(10)), std::future_status::ready);
    updater.join();
}

TEST_F(FimDBFixture, nothingIsWrittenAfterQuiesce)
{
    nlohmann::json itemJson;
    ResultCallbackData callback;
    auto reported {false};

    EXPECT_CALL(*mockDBSync, syncRow(testing::_, testing::_)).Times(0);
    EXPECT_CALL(*mockDBSync, deleteRows(testing::_)).Times(0);
    EXPECT_CALL(*mockDBSync, setEachEntryVersion(testing::_, testing::_)).Times(0);

    fimDBMock.quiesce();

    fimDBMock.updateItem(itemJson, callback);
    fimDBMock.removeItem(itemJson);
    fimDBMock.removeItem(itemJson, [&reported]()
    {
        reported = true;
    });
    EXPECT_FALSE(reported);
    EXPECT_FALSE(fimDBMock.setTableVersion("file_entry", 10));

    // The database stays open until the teardown
    ASSERT_NE(fimDBMock.DBSyncHandler()->handle(), nullptr);
}

TEST(FimDB, setTableVersionNotInitialized)
{
    MockFIMDB fimDBMock;
    EXPECT_FALSE(fimDBMock.setTableVersion("file_entry", 10));
}

TEST(FimDB, notInitalizedDbSyncException)
{
    MockFIMDB fimDBMock;
    EXPECT_THROW({ ASSERT_EQ(fimDBMock.DBSyncHandler()->handle(), nullptr); }, std::runtime_error);
}

#endif
