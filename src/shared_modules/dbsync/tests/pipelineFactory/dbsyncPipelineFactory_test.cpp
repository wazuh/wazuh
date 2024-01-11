/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
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
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    m_dbHandle = DBSyncImplementation::instance().initialize(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql, DbManagement::VOLATILE, {});
};

void DBSyncPipelineFactoryTest::TearDown()
{
    m_pipelineFactory.release();
    DBSyncImplementation::instance().release();
};

class CallbackWrapper
{
    public:
        CallbackWrapper() = default;
        ~CallbackWrapper() = default;
        MOCK_METHOD(void, callback, (ReturnTypeCallback result_type, const nlohmann::json&), ());
};

TEST_F(DBSyncPipelineFactoryTest, CreatePipelineOk)
{
    const auto& json{ nlohmann::json::parse(R"({"tables": ["processes"]})") };

    const int threadNumber{ 1 };
    const int maxQueueSize{ 1000 };
    const auto pipeHandle
    {
        m_pipelineFactory.create(m_dbHandle,
                                 json["tables"],
                                 threadNumber,
                                 maxQueueSize,
        [](ReturnTypeCallback, const nlohmann::json&) {})
    };
    ASSERT_NE(nullptr, pipeHandle);
    ASSERT_NE(nullptr, m_pipelineFactory.pipeline(pipeHandle));
}

TEST_F(DBSyncPipelineFactoryTest, CreatePipelineInvalidHandle)
{
    const DBSYNC_HANDLE handle{ nullptr };
    const auto& json{ nlohmann::json::parse(R"({"tables": ["processes"]})") };
    const unsigned int threadNumber{ 1 };
    const unsigned int maxQueueSize{ 1000 };
    EXPECT_THROW(m_pipelineFactory.create(handle, json["tables"], threadNumber, maxQueueSize,
    [](ReturnTypeCallback, const nlohmann::json&) {}), DbSync::dbsync_error);
}

TEST_F(DBSyncPipelineFactoryTest, CreatePipelineInvalidTxnContext)
{
    const auto& json{ nlohmann::json::parse(R"({"tables": [""]})") };
    const unsigned int threadNumber{ 1 };
    const unsigned int maxQueueSize{ 1000 };
    EXPECT_THROW
    (
        m_pipelineFactory.create(m_dbHandle,
                                 json["tables"],
                                 threadNumber,
                                 maxQueueSize,
    [](ReturnTypeCallback, const nlohmann::json&) {}),
    DbSync::dbsync_error
    );
}

TEST_F(DBSyncPipelineFactoryTest, CreatePipelineInvalidCallback)
{
    const auto& json{ nlohmann::json::parse(R"({"tables": ["processes"]})") };
    const unsigned int threadNumber{ 1 };
    const unsigned int maxQueueSize{ 1000 };
    EXPECT_THROW(m_pipelineFactory.create(m_dbHandle, json["tables"], threadNumber, maxQueueSize, nullptr), DbSync::dbsync_error);
}

TEST_F(DBSyncPipelineFactoryTest, GetPipelineInvalidTxnContext)
{
    EXPECT_THROW
    (
        m_pipelineFactory.pipeline(nullptr),
        DbSync::dbsync_error
    );
}

TEST_F(DBSyncPipelineFactoryTest, PipelineSyncRowInvalidData)
{
    CallbackWrapper wrapper;
    const auto& jsonInputNoTable{ R"({"data":[{"name":"System","pid":4,"tid":100}],"exception":"[json.exception.out_of_range.403] key 'table' not found"})"};
    const auto& jsonInputNoData{ R"({"exception":"[json.exception.out_of_range.403] key 'data' not found","table":"processes"})"};
    const auto resultFnc
    {
        [&wrapper](ReturnTypeCallback resultType, const nlohmann::json & result)
        {
            wrapper.callback(resultType, result);
        }
    };
    const auto& json{ nlohmann::json::parse(R"({"tables": ["processes"]})") };
    const int threadNumber{ 1 };
    const int maxQueueSize{ 1000 };
    const auto pipeHandle
    {
        m_pipelineFactory.create(m_dbHandle,
                                 json["tables"],
                                 threadNumber,
                                 maxQueueSize,
                                 resultFnc)
    };
    ASSERT_NE(nullptr, pipeHandle);
    EXPECT_CALL(wrapper, callback(DB_ERROR, nlohmann::json::parse(jsonInputNoTable))).Times(1);
    EXPECT_CALL(wrapper, callback(DB_ERROR, nlohmann::json::parse(jsonInputNoData))).Times(1);
    const auto pipeline{ m_pipelineFactory.pipeline(pipeHandle) };
    pipeline->syncRow(nlohmann::json::parse(jsonInputNoTable));
    pipeline->syncRow(nlohmann::json::parse(jsonInputNoData));
    pipeline->getDeleted(nullptr);
    m_pipelineFactory.destroy(pipeHandle);
}

TEST_F(DBSyncPipelineFactoryTest, PipelineSyncRow)
{
    CallbackWrapper wrapper;
    const auto& jsonInput{ R"({"table":"processes","data":[{"pid":4, "tid":100, "name":"System"}]})"};
    const auto& jsonInput1{ R"({"table":"processes","data":[{"pid":4, "tid":101, "name":"System1"}]})"};
    const auto& jsonInput2{ R"({"table":"processes","data":[{"pid":4, "tid":102}]})"};
    const auto resultFnc
    {
        [&wrapper](ReturnTypeCallback resultType, const nlohmann::json & result)
        {
            wrapper.callback(resultType, result);
        }
    };
    const auto& json{ nlohmann::json::parse(R"({"tables": ["processes"]})") };
    const int threadNumber{ 1 };
    const int maxQueueSize{ 1000 };
    const auto pipeHandle
    {
        m_pipelineFactory.create(m_dbHandle,
                                 json["tables"],
                                 threadNumber,
                                 maxQueueSize,
                                 resultFnc)
    };
    ASSERT_NE(nullptr, pipeHandle);
    const auto pipeline{ m_pipelineFactory.pipeline(pipeHandle) };
    EXPECT_CALL(wrapper, callback(INSERTED, nlohmann::json::parse(R"({"pid":4,"name":"System","tid":100})"))).Times(1);
    EXPECT_CALL(wrapper, callback(MODIFIED, nlohmann::json::parse(R"({"pid":4,"name":"System1","tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callback(MODIFIED, nlohmann::json::parse(R"({"pid":4,"tid":102})"))).Times(1);
    pipeline->syncRow(nlohmann::json::parse(jsonInput));
    pipeline->syncRow(nlohmann::json::parse(jsonInput));
    pipeline->syncRow(nlohmann::json::parse(jsonInput1));
    pipeline->syncRow(nlohmann::json::parse(jsonInput1));
    pipeline->syncRow(nlohmann::json::parse(jsonInput2));
    pipeline->syncRow(nlohmann::json::parse(jsonInput2));
    pipeline->getDeleted(nullptr);
    m_pipelineFactory.destroy(pipeHandle);
}

TEST_F(DBSyncPipelineFactoryTest, PipelineSyncRowMaxQueueSize)
{
    CallbackWrapper wrapper;
    const auto& jsonInput{ R"({"table":"processes","data":[{"pid":4, "tid":100, "name":"System"}]})"};
    const auto resultFnc
    {
        [&wrapper](ReturnTypeCallback resultType, const nlohmann::json & result)
        {
            wrapper.callback(resultType, result);
        }
    };
    const auto& json{ nlohmann::json::parse(R"({"tables": ["processes"]})") };
    const int threadNumber{ 1 };
    const int maxQueueSize{ 0 };
    const auto pipeHandle
    {
        m_pipelineFactory.create(m_dbHandle,
                                 json["tables"],
                                 threadNumber,
                                 maxQueueSize,
                                 resultFnc)
    };
    ASSERT_NE(nullptr, pipeHandle);
    const auto pipeline{ m_pipelineFactory.pipeline(pipeHandle) };
    EXPECT_CALL(wrapper, callback(INSERTED, nlohmann::json::parse(R"({"pid":4,"name":"System","tid":100})"))).Times(1);
    pipeline->syncRow(nlohmann::json::parse(jsonInput));
    pipeline->getDeleted(nullptr);
    m_pipelineFactory.destroy(pipeHandle);
}

TEST_F(DBSyncPipelineFactoryTest, PipelineSyncRowAndGetDeleted)
{
    CallbackWrapper wrapper;
    const auto& jsonInputNoTxn{ R"({"table":"processes","data":[{"pid":4, "tid":100, "name":"System"},{"pid":5, "tid":101, "name":"System1"},{"pid":7, "tid":101, "name":"System7"}]})"};
    const auto& jsonInputTxn1{ R"({"table":"processes","data":[{"pid":4, "tid":101, "name":"System"}]})"};
    const auto& jsonInputTxn2{ R"({"table":"processes","data":[{"pid":6, "tid":105, "name":"System2"}]})"};
    const auto resultFnc
    {
        [&wrapper](ReturnTypeCallback resultType, const nlohmann::json & result)
        {
            wrapper.callback(resultType, result);
        }
    };
    EXPECT_CALL(wrapper, callback(MODIFIED, nlohmann::json::parse(R"({"name":"System","pid":4,"tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callback(INSERTED, nlohmann::json::parse(R"({"pid":6,"name":"System2","tid":105})"))).Times(1);
    EXPECT_CALL(wrapper, callback(DELETED, nlohmann::json::parse(R"({"name":"System1","pid":5,"tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callback(DELETED, nlohmann::json::parse(R"({"name":"System7","pid":7,"tid":101})"))).Times(1);
    DBSyncImplementation::instance().syncRowData(m_dbHandle, nlohmann::json::parse(jsonInputNoTxn), nullptr);
    const auto& json{ nlohmann::json::parse(R"({"tables": ["processes"]})") };
    const int threadNumber{ 1 };
    const int maxQueueSize{ 1000 };
    const auto pipeHandle
    {
        m_pipelineFactory.create(m_dbHandle,
                                 json["tables"],
                                 threadNumber,
                                 maxQueueSize,
                                 resultFnc)
    };
    ASSERT_NE(nullptr, pipeHandle);
    const auto pipeline{ m_pipelineFactory.pipeline(pipeHandle) };
    pipeline->syncRow(nlohmann::json::parse(jsonInputTxn1));
    pipeline->syncRow(nlohmann::json::parse(jsonInputTxn2));
    pipeline->getDeleted(resultFnc);
    m_pipelineFactory.destroy(pipeHandle);
}

TEST_F(DBSyncPipelineFactoryTest, PipelineSyncRowAndGetDeletedSameData)
{
    CallbackWrapper wrapper;
    const auto& jsonInputNoTxn{ R"({"table":"processes","data":[{"pid":4, "tid":100, "name":"System"},{"pid":5, "tid":101, "name":"System1"},{"pid":7, "tid":101, "name":"System7"}]})"};
    const auto& jsonInputTxn1{ R"({"table":"processes","data":[{"pid":4, "tid":101, "name":"System"}]})"};
    const auto& jsonInputTxn2{ R"({"table":"processes","data":[{"pid":5, "tid":101, "name":"System1"}]})"};
    const auto& jsonInputTxn3{ R"({"table":"processes","data":[{"pid":6, "tid":105, "name":"System2"}]})"};
    const auto resultFnc
    {
        [&wrapper](ReturnTypeCallback resultType, const nlohmann::json & result)
        {
            wrapper.callback(resultType, result);
        }
    };
    EXPECT_CALL(wrapper, callback(MODIFIED, nlohmann::json::parse(R"({"name":"System","pid":4,"tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callback(INSERTED, nlohmann::json::parse(R"({"pid":6,"name":"System2","tid":105})"))).Times(1);
    EXPECT_CALL(wrapper, callback(DELETED, nlohmann::json::parse(R"({"name":"System7","pid":7,"tid":101})"))).Times(1);
    DBSyncImplementation::instance().syncRowData(m_dbHandle, nlohmann::json::parse(jsonInputNoTxn), nullptr);
    const auto& json{ nlohmann::json::parse(R"({"tables": ["processes"]})") };
    const int threadNumber{ 1 };
    const int maxQueueSize{ 1000 };
    const auto pipeHandle
    {
        m_pipelineFactory.create(m_dbHandle,
                                 json["tables"],
                                 threadNumber,
                                 maxQueueSize,
                                 resultFnc)
    };
    ASSERT_NE(nullptr, pipeHandle);
    const auto pipeline{ m_pipelineFactory.pipeline(pipeHandle) };
    pipeline->syncRow(nlohmann::json::parse(jsonInputTxn1));
    pipeline->syncRow(nlohmann::json::parse(jsonInputTxn2));
    pipeline->syncRow(nlohmann::json::parse(jsonInputTxn3));
    pipeline->getDeleted(resultFnc);
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
