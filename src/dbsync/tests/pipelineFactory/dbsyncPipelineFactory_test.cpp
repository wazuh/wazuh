/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 16, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <iostream>
#include "dbsync_implementation.h"
#include "dbsyncPipelineFactory.h"
#include "dbsyncPipelineFactory_test.h"
#include "db_exception.h"

constexpr auto DATABASE_TEMP {"TEMP.db"};

using namespace DbSync;
void DBSyncPipelineFactoryTest::SetUp()
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    m_dbHandle = DBSyncImplementation::instance().initialize(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql);
};

void DBSyncPipelineFactoryTest::TearDown()
{
    m_pipelineFactory.release();
    DBSyncImplementation::instance().release();
};

TEST_F(DBSyncPipelineFactoryTest, CreatePipelineOk)
{
    const auto json{ nlohmann::json::parse(R"({"tables": ["processes"]})") };

    const int threadNumber{ 1 };
    const int maxQueueSize{ 1000 };
    const auto pipeHandle
    {
        m_pipelineFactory.create(m_dbHandle,
                                 json[0]["tables"].dump().c_str(),
                                 threadNumber,
                                 maxQueueSize,
                                 [](ReturnTypeCallback, const nlohmann::json&){})
    };
    ASSERT_NE(nullptr, pipeHandle);
    ASSERT_NE(nullptr, m_pipelineFactory.pipeline(pipeHandle));
}
TEST_F(DBSyncPipelineFactoryTest, CreatePipelineInvalidHandle)
{
    const DBSYNC_HANDLE handle{ nullptr };
    const auto json{ nlohmann::json::parse(R"({"tables": ["processes"]})") };
    const unsigned int threadNumber{ 1 };
    const unsigned int maxQueueSize{ 1000 };
    EXPECT_THROW
    (
        m_pipelineFactory.create(handle,
                                 json[0]["tables"].dump().c_str(),
                                 threadNumber,
                                 maxQueueSize,
                                 [](ReturnTypeCallback, const nlohmann::json&){}),
        DbSync::dbsync_error
    );
}

TEST_F(DBSyncPipelineFactoryTest, CreatePipelineInvalidTxnContext)
{
    const auto json{ nlohmann::json::parse(R"({"tables": [""]})") };
    const unsigned int threadNumber{ 1 };
    const unsigned int maxQueueSize{ 1000 };
    EXPECT_THROW
    (
        m_pipelineFactory.create(m_dbHandle,
                                 json[0]["tables"].dump().c_str(),
                                 threadNumber,
                                 maxQueueSize,
                                 [](ReturnTypeCallback, const nlohmann::json&){}),
        DbSync::dbsync_error
    );
}

TEST_F(DBSyncPipelineFactoryTest, CreatePipelineInvalidCallback)
{
    const auto json{ nlohmann::json::parse(R"({"tables": ["processes"]})") };
    const unsigned int threadNumber{ 1 };
    const unsigned int maxQueueSize{ 1000 };
    EXPECT_THROW
    (
        m_pipelineFactory.create(m_dbHandle,
                                 json[0]["tables"].dump().c_str(),
                                 threadNumber,
                                 maxQueueSize,
                                 nullptr),
        DbSync::dbsync_error
    );
}

TEST_F(DBSyncPipelineFactoryTest, GetPipelineInvalidTxnContext)
{
    EXPECT_THROW
    (
        m_pipelineFactory.pipeline(nullptr),
        DbSync::dbsync_error
    );
}


TEST_F(DBSyncPipelineFactoryTest, PipelineSyncRow)
{
    const auto jsonInput{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};
    const nlohmann::json expectedResult{ jsonInput };

    const auto resultFnc
    {
        [&expectedResult](ReturnTypeCallback /*result_type*/, const nlohmann::json& result)
        {
            ASSERT_EQ(expectedResult[0], result);
        }
    };
    const auto json{ nlohmann::json::parse(R"({"tables": ["processes"]})") };
    const int threadNumber{ 1 };
    const int maxQueueSize{ 1000 };
    const auto pipeHandle
    {
        m_pipelineFactory.create(m_dbHandle,
                                 json[0]["tables"].dump().c_str(),
                                 threadNumber,
                                 maxQueueSize,
                                 resultFnc)
    };
    ASSERT_NE(nullptr, pipeHandle);
    const auto pipeline{ m_pipelineFactory.pipeline(pipeHandle) };
    pipeline->syncRow(jsonInput);
    pipeline->getDeleted(nullptr);
    m_pipelineFactory.destroy(pipeHandle);
}

TEST_F(DBSyncPipelineFactoryTest, PipelineSyncRowMaxQueueSize)
{
    const auto jsonInput{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})" };
    const nlohmann::json expectedResult{ jsonInput };
    const auto resultFnc
    {
        [&expectedResult](ReturnTypeCallback /*result_type*/, const nlohmann::json& result)
        {
            ASSERT_EQ(expectedResult[0], result);
        }
    };
    const auto json{ nlohmann::json::parse(R"({"tables": ["processes"]})") };
    const int threadNumber{ 1 };
    const int maxQueueSize{ 0 };
    const auto pipeHandle
    {
        m_pipelineFactory.create(m_dbHandle,
                                 json[0]["tables"].dump().c_str(),
                                 threadNumber,
                                 maxQueueSize,
                                 resultFnc)
    };
    ASSERT_NE(nullptr, pipeHandle);
    const auto pipeline{ m_pipelineFactory.pipeline(pipeHandle) };
    pipeline->syncRow(jsonInput);
    pipeline->getDeleted(nullptr);
    m_pipelineFactory.destroy(pipeHandle);
}

TEST_F(DBSyncPipelineFactoryTest, DestroyInvalidPipeline)
{
    EXPECT_THROW
    (
        m_pipelineFactory.destroy(nullptr),
        DbSync::dbsync_error
    );
}
