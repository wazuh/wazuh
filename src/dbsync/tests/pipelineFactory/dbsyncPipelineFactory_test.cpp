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
#include "dbsyncPipelineFactory.h"
#include "dbsyncPipelineFactory_test.h"
#include "db_exception.h"

void DBSyncPipelineFactoryTest::SetUp()
{
};

void DBSyncPipelineFactoryTest::TearDown()
{
    m_pipelineFactory.release();
};

TEST_F(DBSyncPipelineFactoryTest, CreatePipelineOk)
{
    const DBSYNC_HANDLE handle{ reinterpret_cast<DBSYNC_HANDLE*>(0x100) };
    const DbSync::TxnContext txnContext{ reinterpret_cast<DBSYNC_HANDLE*>(0x100) };
    const int threadNumber{ 1 };
    const int maxQueueSize{ 1000 };
    const auto pipeHandle
    {
        m_pipelineFactory.create(handle,
                                 txnContext,
                                 threadNumber,
                                 maxQueueSize,
                                 [](ReturnTypeCallback, cJSON*){})
    };
    ASSERT_NE(nullptr, pipeHandle);
    ASSERT_NE(nullptr, m_pipelineFactory.pipeline(pipeHandle));
}

TEST_F(DBSyncPipelineFactoryTest, CreatePipelineInvalidHandle)
{
    const DBSYNC_HANDLE handle{ nullptr };
    const DbSync::TxnContext txnContext{ reinterpret_cast<DBSYNC_HANDLE*>(0x100) };
    const unsigned int threadNumber{ 1 };
    const unsigned int maxQueueSize{ 1000 };
    EXPECT_THROW
    (
        m_pipelineFactory.create(handle,
                                 txnContext,
                                 threadNumber,
                                 maxQueueSize,
                                 [](ReturnTypeCallback, cJSON*){}),
        DbSync::dbsync_error
    );
}

TEST_F(DBSyncPipelineFactoryTest, CreatePipelineInvalidTxnContext)
{
    const DBSYNC_HANDLE handle{ reinterpret_cast<DBSYNC_HANDLE*>(0x100) };
    const DbSync::TxnContext txnContext{ nullptr };
    const unsigned int threadNumber{ 1 };
    const unsigned int maxQueueSize{ 1000 };
    EXPECT_THROW
    (
        m_pipelineFactory.create(handle,
                                 txnContext,
                                 threadNumber,
                                 maxQueueSize,
                                 [](ReturnTypeCallback, cJSON*){}),
        DbSync::dbsync_error
    );
}

TEST_F(DBSyncPipelineFactoryTest, CreatePipelineInvalidCallback)
{
    const DBSYNC_HANDLE handle{ reinterpret_cast<DBSYNC_HANDLE*>(0x100) };
    const DbSync::TxnContext txnContext{ reinterpret_cast<DBSYNC_HANDLE*>(0x100) };
    const unsigned int threadNumber{ 1 };
    const unsigned int maxQueueSize{ 1000 };
    EXPECT_THROW
    (
        m_pipelineFactory.create(handle,
                                 txnContext,
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
    const std::string jsonInput{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})" };
    const std::string expectedResult{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})" };
    auto resultFnc
    {
        [expectedResult](ReturnTypeCallback /*result_type*/, cJSON* json)
        {
            char * result_json = cJSON_PrintUnformatted(json);
            const std::string result{result_json};
            ASSERT_EQ(expectedResult, result);
            cJSON_free(result_json);
        }
    };
    const DBSYNC_HANDLE handle{ reinterpret_cast<DBSYNC_HANDLE*>(0x100) };
    const DbSync::TxnContext txnContext{ reinterpret_cast<DBSYNC_HANDLE*>(0x100) };
    const int threadNumber{ 1 };
    const int maxQueueSize{ 1000 };
    const auto pipeHandle
    {
        m_pipelineFactory.create(handle,
                                 txnContext,
                                 threadNumber,
                                 maxQueueSize,
                                 resultFnc)
    };
    ASSERT_NE(nullptr, pipeHandle);
    const auto pipeline{ m_pipelineFactory.pipeline(pipeHandle) };
    pipeline->syncRow(jsonInput.c_str());
    pipeline->getDeleted(nullptr);
    m_pipelineFactory.destroy(pipeHandle);
}

TEST_F(DBSyncPipelineFactoryTest, PipelineSyncRowMaxQueueSize)
{
    const std::string jsonInput{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})" };
    const std::string expectedResult{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})" };
    auto resultFnc
    {
        [expectedResult](ReturnTypeCallback /*result_type*/, cJSON* json)
        {
            char * result_json = cJSON_PrintUnformatted(json);
            const std::string result{result_json};
            ASSERT_EQ(expectedResult, result);
            cJSON_free(result_json);
        }
    };
    const DBSYNC_HANDLE handle{ reinterpret_cast<DBSYNC_HANDLE*>(0x100) };
    const DbSync::TxnContext txnContext{ reinterpret_cast<DBSYNC_HANDLE*>(0x100) };
    const int threadNumber{ 1 };
    const int maxQueueSize{ 0 };
    const auto pipeHandle
    {
        m_pipelineFactory.create(handle,
                                 txnContext,
                                 threadNumber,
                                 maxQueueSize,
                                 resultFnc)
    };
    ASSERT_NE(nullptr, pipeHandle);
    const auto pipeline{ m_pipelineFactory.pipeline(pipeHandle) };
    pipeline->syncRow(jsonInput.c_str());
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