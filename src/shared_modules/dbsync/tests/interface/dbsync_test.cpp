/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * July 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <iostream>
#include "json.hpp"
#include "dbsync_test.h"
#include "dbsync.h"
#include "dbsync.hpp"
#include "makeUnique.h"
#include "test_inputs.h"
#include "cjsonSmartDeleter.hpp"

constexpr auto DATABASE_TEMP {"TEMP.db"};
constexpr auto DATABASE_MEMORY {":memory:"};
constexpr auto DATABASE_PERMISSIONS
{
    0640u
};


class CallbackMock
{
    public:
        CallbackMock() = default;
        ~CallbackMock() = default;
        MOCK_METHOD(void, callbackMock, (ReturnTypeCallback result_type, const nlohmann::json&), ());
};

static void callback(const ReturnTypeCallback type,
                     const cJSON* json,
                     void* ctx)
{
    CallbackMock* wrapper { reinterpret_cast<CallbackMock*>(ctx)};
    const std::unique_ptr<char, CJsonSmartFree> spJsonBytes{ cJSON_PrintUnformatted(json) };
    wrapper->callbackMock(type, nlohmann::json::parse(spJsonBytes.get()));
}

static void logFunction(const char* msg)
{
    if (msg)
    {
        std::cout << msg << std::endl;
    }
}

void DBSyncTest::SetUp()
{
    dbsync_initialize(&logFunction);
};

void DBSyncTest::TearDown()
{
    EXPECT_NO_THROW(dbsync_teardown());
    std::remove(DATABASE_TEMP);
};

TEST_F(DBSyncTest, Initialization)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    // On windows, no change in permissions is expected
#ifndef _WIN32
    struct stat stStat {};
    ASSERT_EQ(0, stat(DATABASE_TEMP, &stStat));
    ASSERT_NE(0, S_ISREG(stStat.st_mode));
    EXPECT_EQ(DATABASE_PERMISSIONS, stStat.st_mode & 0777);
#endif
}

TEST_F(DBSyncTest, InitializationNullptr)
{
    const auto handle_1 { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, nullptr) };
    ASSERT_EQ(nullptr, handle_1);
    const auto handle_2 { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, nullptr, "valid") };
    ASSERT_EQ(nullptr, handle_2);
}

TEST_F(DBSyncTest, InitializationWithInvalidSqlStmt)
{
    const auto sqlWithoutTable{ "CREATE TABLE (`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle_1 { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sqlWithoutTable) };
    ASSERT_EQ(nullptr, handle_1);
}

TEST_F(DBSyncTest, InitializationWithWrongDBEngine)
{
    const auto sqlWithoutTable{ "CREATE TABLE (`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::UNDEFINED, DATABASE_TEMP, sqlWithoutTable) };
    ASSERT_EQ(nullptr, handle);
}

TEST_F(DBSyncTest, createTxn)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto tables { R"({"table": "processes"})" };
    const std::unique_ptr<DummyContext> dummyCtx { std::make_unique<DummyContext>()};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsonTables { cJSON_Parse(tables) };

    callback_data_t callbackData { callback, dummyCtx.get() };

    EXPECT_NO_THROW(dummyCtx->txnContext = dbsync_create_txn(handle, jsonTables.get(), 0, 100, callbackData));
    ASSERT_NE(nullptr, dummyCtx->txnContext);
}

TEST_F(DBSyncTest, createTxnNullptr)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto tables { R"({"table": "processes""})" };
    const std::unique_ptr<DummyContext> dummyCtx { std::make_unique<DummyContext>()};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsonTables { cJSON_Parse(tables) };

    callback_data_t callbackData { callback, dummyCtx.get() };
    callback_data_t callbackDataNullptr { callback, nullptr };

    ASSERT_NE(nullptr, handle);
    ASSERT_EQ(nullptr, dbsync_create_txn(nullptr, jsonTables.get(), 0, 100, callbackData));
    ASSERT_EQ(nullptr, dbsync_create_txn(handle, nullptr, 0, 100, callbackData));
    ASSERT_EQ(nullptr, dbsync_create_txn(handle, jsonTables.get(), 0, 100, callbackData));
    ASSERT_EQ(nullptr, dbsync_create_txn(handle, jsonTables.get(), 0, 0, callbackData));
    ASSERT_EQ(nullptr, dbsync_create_txn(handle, jsonTables.get(), 0, 100, callbackDataNullptr));
}

TEST_F(DBSyncTest, syncTxnRowNullptr)
{
    const auto insertionSqlStmt1{ R"({"table":"processes","data":[{"pid":7,"name":"Guake"}]})"}; // Insert
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert1{ cJSON_Parse(insertionSqlStmt1) };
    ASSERT_NE(0, dbsync_sync_txn_row(nullptr, jsInsert1.get()));
}

TEST_F(DBSyncTest, closeTxnNullptr)
{
    ASSERT_NE(0, dbsync_close_txn(nullptr));
}

TEST_F(DBSyncTest, dbsyncAddTableRelationshipDummy)
{
    ASSERT_EQ(-1, dbsync_add_table_relationship(nullptr, nullptr));
}

TEST_F(DBSyncTest, dbsyncAddTableRelationship)
{
    const auto sql { R"(CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `path` TEXT, `cmdline` TEXT, `state` TEXT, `cwd` TEXT, `root` TEXT, `uid` BIGINT, `gid` BIGINT, `euid` BIGINT, `egid` BIGINT, `suid` BIGINT, `sgid` BIGINT, `on_disk` INTEGER, `wired_size` BIGINT, `resident_size` BIGINT, `total_size` BIGINT, `user_time` BIGINT, `system_time` BIGINT, `disk_bytes_read` BIGINT, `disk_bytes_written` BIGINT, `start_time` BIGINT, `parent` BIGINT, `pgroup` BIGINT, `threads` INTEGER, `nice` INTEGER, `is_elevated_token` INTEGER, `elapsed_time` BIGINT, `handle_count` BIGINT, `percent_processor_time` BIGINT, `upid` BIGINT HIDDEN, `uppid` BIGINT HIDDEN, `cpu_type` INTEGER HIDDEN, `cpu_subtype` INTEGER HIDDEN, `phys_footprint` BIGINT HIDDEN, PRIMARY KEY (`pid`)) WITHOUT ROWID;CREATE TABLE processes_sockets(`socket_id` BIGINT, `pid` BIGINT, PRIMARY KEY (`socket_id`)) WITHOUT ROWID;)"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto insertDataProcess { R"(
        {
            "table": "processes",
            "data":[
                {
                    "pid":4,
                    "name":"System",
                    "path":"",
                    "cmdline":"",
                    "state":"",
                    "cwd":"",
                    "root":"",
                    "uid":-1,
                    "gid":-1,
                    "euid":-1,
                    "egid":-1,
                    "suid":-1,
                    "sgid":-1,
                    "on_disk":-1,
                    "wired_size":-1,
                    "resident_size":-1,
                    "total_size":-1,
                    "user_time":-1,
                    "system_time":-1,
                    "disk_bytes_read":-1,
                    "disk_bytes_written":-1,
                    "start_time":-1,
                    "parent":0,
                    "pgroup":-1,
                    "threads":164,
                    "nice":-1,
                    "is_elevated_token":false,
                    "elapsed_time":-1,
                    "handle_count":-1,
                    "percent_processor_time":-1
                 }
            ]
        }
    )"};

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsertProcess{ cJSON_Parse(insertDataProcess) };
    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsertProcess.get()));

    const auto insertDataSocket{ R"(
        {
        "table": "processes_sockets",
            "data":[
                {
                    "pid":4,
                    "socket_id":1
                }
            ]
        }
    )"};

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsertSocket{ cJSON_Parse(insertDataSocket) };
    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsertSocket.get()));

    const auto relationshipJson{ R"(
        {
            "base_table":"processes",
            "relationed_tables":
            [
                {
                    "table": "processes_sockets",
                    "field_match":
                    {
                        "pid": "pid"
                    }
                }
            ]
        })"};

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsRelationship{ cJSON_Parse(relationshipJson) };
    EXPECT_EQ(0, dbsync_add_table_relationship(handle, jsRelationship.get()));


    const auto deleteProcess{ R"(
        {
            "table": "processes",
            "query": {
                "data":[
                {
                    "pid":4
                }],
                "where_filter_opt":""
            }
        })"};

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsDeleteProcess{ cJSON_Parse(deleteProcess) };
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsDeleteProcess.get()));

}

TEST_F(DBSyncTest, AddTableRelationshipIncorrectJSON)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto addRelationshipIncorrectJson{ R"(
    {
            "base_table":"processes",
            "relationed_tables":
            [
                {
                    "incorrect": "processes_sockets",
                    "incorrect":
                    {
                        "incorrect": "pid"
                    }
                }
            ]
        })"};

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsAddRelationshipIncorrectJson{ cJSON_Parse(addRelationshipIncorrectJson) };
    EXPECT_NE(0, dbsync_add_table_relationship(handle, jsAddRelationshipIncorrectJson.get()));
}
TEST_F(DBSyncTest, InsertData)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
}

TEST_F(DBSyncTest, InsertDataWithCompoundPKs)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`, `tid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":"100"},
                                                                 {"pid":5,"name":"User1", "tid":101},
                                                                 {"pid":6,"name":"User2", "tid":102}]})"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
}

TEST_F(DBSyncTest, InsertMoreCompleteData)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `threads` INTEGER, `cpu_usage` DOUBLE, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System", "threads":5, "cpu_usage":17.50}]})"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
}

TEST_F(DBSyncTest, InsertDataWithWrongColumnType)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `threads` INTEGER, `cpu_usage` DOUBLE, `blob` BLOB, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System", "threads":5, "cpu_usage":17.50, "blob":1}]})"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_NE(0, dbsync_insert_data(handle, jsInsert.get()));
}

TEST_F(DBSyncTest, InsertDataWithInvalidInput)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto inputNoData{ R"({"table":"processes"})"};
    const auto inputNoTable{ R"({"data":[{"pid":4,"name":"System", "tid":101}]})"};
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInputNoData{ cJSON_Parse(inputNoData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInputNoTable{ cJSON_Parse(inputNoTable) };

    EXPECT_NE(0, dbsync_insert_data(handle, jsInputNoData.get()));
    EXPECT_NE(0, dbsync_insert_data(handle, jsInputNoTable.get()));
}

TEST_F(DBSyncTest, InsertDataNullptr)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    EXPECT_NE(0, dbsync_insert_data(handle, nullptr));
}

TEST_F(DBSyncTest, InsertDataInvalidHandle)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_NE(0, dbsync_insert_data(reinterpret_cast<void*>(0xffffffff), jsInsert.get()));
}

TEST_F(DBSyncTest, GetDeletedRowsInvalidInput)
{
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_NE(0, dbsync_get_deleted_rows(nullptr, callbackData));
}

TEST_F(DBSyncTest, GetDeletedRowsOnlyPKs)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `euser` TEXT, PRIMARY KEY (`pid`,`name`)) WITHOUT ROWID;"};
    const auto table { R"({"table":"processes"})" };
    auto syncSqlStmt1 = SyncRowQuery::builder().table("processes")
                        .data(nlohmann::json::parse(R"({"pid":4,"name":"System","euser":"wazuh"})"))
                        .query();
    auto syncSqlStmt2 = SyncRowQuery::builder().table("processes")
                        .data(nlohmann::json::parse(R"({"pid":7,"name":"Guake","euser":"wazuh"})"))
                        .query();
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsonTables { cJSON_Parse(table) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSync1 { cJSON_Parse(syncSqlStmt1.dump().c_str()) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSync2{ cJSON_Parse(syncSqlStmt2.dump().c_str()) };
    const std::unique_ptr<DummyContext> dummyCtx { std::make_unique<DummyContext>()};

    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };

    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"System","pid":4,"euser":"wazuh"})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"Guake","pid":7,"euser":"wazuh"})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(DELETED, nlohmann::json::parse(R"({"euser":"wazuh","name":"System","pid":4})"))).Times(1);

    dummyCtx->handle = dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql);
    ASSERT_NE(nullptr, dummyCtx->handle);

    EXPECT_EQ(0, dbsync_sync_row(dummyCtx->handle, jsSync1.get(), callbackData));

    EXPECT_NO_THROW(dummyCtx->txnContext = dbsync_create_txn(dummyCtx->handle, jsonTables.get(), 0, 100, callbackData));
    ASSERT_NE(nullptr, dummyCtx->txnContext);

    EXPECT_EQ(0, dbsync_sync_txn_row(dummyCtx->txnContext, jsSync2.get()));

    EXPECT_EQ(0, dbsync_get_deleted_rows(dummyCtx->txnContext, callbackData));
}

TEST_F(DBSyncTest, GetDeletedRowsAllAttributes)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `euser` TEXT, PRIMARY KEY (`pid`,`name`)) WITHOUT ROWID;"};
    const auto table { R"({"table":"processes"})" };
    auto syncSqlStmt1 = SyncRowQuery::builder().table("processes")
                        .data(nlohmann::json::parse(R"({"pid":4,"name":"System","euser":"wazuh"})"))
                        .query();
    auto syncSqlStmt2 = SyncRowQuery::builder().table("processes")
                        .data(nlohmann::json::parse(R"({"pid":7,"name":"Guake","euser":"wazuh"})"))
                        .query();
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsonTables { cJSON_Parse(table) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSync1 { cJSON_Parse(syncSqlStmt1.dump().c_str()) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSync2{ cJSON_Parse(syncSqlStmt2.dump().c_str()) };
    const std::unique_ptr<DummyContext> dummyCtx { std::make_unique<DummyContext>()};

    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };

    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"System","pid":4,"euser":"wazuh"})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"Guake","pid":7,"euser":"wazuh"})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(DELETED, nlohmann::json::parse(R"({"name":"System","pid":4,"euser":"wazuh"})"))).Times(1);

    dummyCtx->handle = dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql);
    ASSERT_NE(nullptr, dummyCtx->handle);

    EXPECT_EQ(0, dbsync_sync_row(dummyCtx->handle, jsSync1.get(), callbackData));

    dummyCtx->txnContext = dbsync_create_txn(dummyCtx->handle, jsonTables.get(), 0, 100, callbackData);
    ASSERT_NE(nullptr, dummyCtx->handle);

    EXPECT_EQ(0, dbsync_sync_txn_row(dummyCtx->txnContext, jsSync2.get()));

    EXPECT_EQ(0, dbsync_get_deleted_rows(dummyCtx->txnContext, callbackData));
}

TEST_F(DBSyncTest, UpdateData)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    cJSON* jsResponse { nullptr };

    EXPECT_EQ(0, dbsync_update_with_snapshot(handle, jsInsert.get(), &jsResponse));
    EXPECT_NE(nullptr, jsResponse);
    EXPECT_NO_THROW(dbsync_free_result(&jsResponse));
}

TEST_F(DBSyncTest, UpdateDataBadInputs)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};
    const auto badSqlStmt{ R"("pid":4,"name":"System")"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsertWithoutTable{ cJSON_Parse(badSqlStmt) };

    cJSON* jsResponse { nullptr };

    // Failure cases
    EXPECT_NE(0, dbsync_update_with_snapshot(reinterpret_cast<void*>(0xffffffff), jsInsert.get(), nullptr));
    EXPECT_NE(0, dbsync_update_with_snapshot(handle, jsInsertWithoutTable.get(), &jsResponse));
    EXPECT_NE(0, dbsync_update_with_snapshot(nullptr, jsInsertWithoutTable.get(), nullptr));
    EXPECT_NE(0, dbsync_update_with_snapshot(handle, nullptr, nullptr));
    EXPECT_NE(0, dbsync_update_with_snapshot(handle, jsInsert.get(), nullptr));
    EXPECT_NO_THROW(dbsync_free_result(&jsResponse));
}

TEST_F(DBSyncTest, UpdateDataCb)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };

    EXPECT_EQ(0, dbsync_update_with_snapshot_cb(handle, jsInsert.get(), callbackData));
}

TEST_F(DBSyncTest, UpdateDataCbBadInputs)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    callback_data_t callbackData { nullptr, nullptr };

    // Failure cases
    EXPECT_NE(0, dbsync_update_with_snapshot_cb(reinterpret_cast<void*>(0xffffffff), jsInsert.get(), callbackData));
    EXPECT_NE(0, dbsync_update_with_snapshot_cb(handle, nullptr, callbackData));
    EXPECT_NE(0, dbsync_update_with_snapshot_cb(handle, jsInsert.get(), callbackData));
}


TEST_F(DBSyncTest, UpdateDataCbEmptyInputs)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({ "incorrect":"incorrect" })"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };

    // Failure cases
    EXPECT_NE(0, dbsync_update_with_snapshot_cb(handle, jsInsert.get(), callbackData));
}

TEST(DBSyncTestInit, InitializeWithNullFnct)
{
    dbsync_initialize(nullptr);

    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    cJSON* jsResponse { nullptr };

    EXPECT_EQ(0, dbsync_update_with_snapshot(handle, jsInsert.get(), &jsResponse));
    EXPECT_NE(nullptr, jsResponse);
    EXPECT_NO_THROW(dbsync_free_result(&jsResponse));
}

TEST_F(DBSyncTest, FreeNullptrResult)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    cJSON* jsResponse { nullptr };

    EXPECT_NO_THROW(dbsync_free_result(&jsResponse));
}

TEST_F(DBSyncTest, UpdateDataWithLessFields)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT,`path` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    cJSON* jsResponse { nullptr };

    EXPECT_EQ(0, dbsync_update_with_snapshot(handle, jsInsert.get(), &jsResponse));
    EXPECT_NE(nullptr, jsResponse);
    EXPECT_NO_THROW(dbsync_free_result(&jsResponse));
}

TEST_F(DBSyncTest, SetMaxRows)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);
    EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 100));
    EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 0));
}

TEST_F(DBSyncTest, TryToInsertMoreThanMaxRows)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}, {"pid":3,"name":"cmd"}]})"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 1));
    EXPECT_NE(0, dbsync_insert_data(handle, jsInsert.get()));

    EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 0));
    EXPECT_NE(0, dbsync_insert_data(handle, jsInsert.get()));

    const auto deleteProcess{ R"(
        {
            "table": "processes",
            "query": {
                "data":[
                {
                    "pid":4
                }],
                "where_filter_opt":""
            }
        })"};

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsDeleteProcess{ cJSON_Parse(deleteProcess) };
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsDeleteProcess.get()));

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
}

TEST_F(DBSyncTest, TryToUpdateMaxRowsElements)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}, {"pid":3,"name":"cmd"}]})"};
    const auto updateSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"Cmd"}, {"pid":3,"name":"System"}]})"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 2));
    EXPECT_NE(0, dbsync_set_table_max_rows(handle, "proceses", 2));

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };
    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));

    cJSON* jsResponse { nullptr };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsUpdate{ cJSON_Parse(updateSqlStmt) };
    EXPECT_EQ(0, dbsync_update_with_snapshot(handle, jsUpdate.get(), &jsResponse));
    EXPECT_NE(nullptr, jsResponse);
    EXPECT_NO_THROW(dbsync_free_result(&jsResponse));
}

TEST_F(DBSyncTest, TryToUpdateMoreThanMaxRowsElements)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}, {"pid":3,"name":"cmd"}]})"};
    const auto updateSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"Cmd"}, {"pid":3,"name":"System"}, {"pid":5,"name":"powershell"}]})"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 2));

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };
    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));

    cJSON* jsResponse { nullptr };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsUpdate{ cJSON_Parse(updateSqlStmt) };
    EXPECT_NE(0, dbsync_update_with_snapshot(handle, jsUpdate.get(), &jsResponse));
    EXPECT_EQ(nullptr, jsResponse);

    EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 10));
    EXPECT_EQ(0, dbsync_update_with_snapshot(handle, jsUpdate.get(), &jsResponse));
    EXPECT_NE(nullptr, jsResponse);
    EXPECT_NO_THROW(dbsync_free_result(&jsResponse));

    // Failure cases
    EXPECT_NE(0, dbsync_set_table_max_rows(nullptr, "processes", 10));
    EXPECT_NE(0, dbsync_set_table_max_rows(nullptr, "", 10));
}

TEST_F(DBSyncTest, SetMaxRowsBadData)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);
    EXPECT_NE(0, dbsync_set_table_max_rows(reinterpret_cast<void*>(0xffffffff), "dummy", 100));
    EXPECT_NE(0, dbsync_set_table_max_rows(handle, "dummy", 100));
}

TEST_F(DBSyncTest, syncRowInsertAndModified)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":4,"name":"System", "tid":100})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":5,"name":"System", "tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":6,"name":"System", "tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(MODIFIED, nlohmann::json::parse(R"({"name":"System","pid":4,"tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(MODIFIED, nlohmann::json::parse(R"({"pid":4,"name":"Systemmm","tid":105})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":7,"name":"Guake"})"))).Times(1);

    const auto insertionSqlStmt1{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":100},
                                                                  {"pid":5,"name":"System", "tid":101},
                                                                  {"pid":6,"name":"System", "tid":102}]})"}; // Insert
    const auto updateSqlStmt1{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":101}]})"};    // Update
    const auto updateSqlStmt2{ R"({"table":"processes","data":[{"pid":4,"name":"Systemmm", "tid":105}]})"};  // Update
    const auto insertSqlStmt3{ R"({"table":"processes","data":[{"pid":7,"name":"Guake"}]})"};                // Insert

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert1{ cJSON_Parse(insertionSqlStmt1) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsUpdate1{ cJSON_Parse(updateSqlStmt1) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsUpdate2{ cJSON_Parse(updateSqlStmt2) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert2{ cJSON_Parse(insertSqlStmt3) };

    callback_data_t callbackData { callback, &wrapper };
    callback_data_t callbackEmpty { nullptr, nullptr };

    EXPECT_EQ(0, dbsync_sync_row(handle, jsInsert1.get(), callbackData));  // Expect an insert event
    EXPECT_EQ(0, dbsync_sync_row(handle, jsUpdate1.get(), callbackData));  // Expect a modified event
    EXPECT_EQ(0, dbsync_sync_row(handle, jsUpdate2.get(), callbackData));  // Expect a modified event
    EXPECT_EQ(0, dbsync_sync_row(handle, jsInsert2.get(), callbackData));  // Expect an insert event
    EXPECT_EQ(0, dbsync_sync_row(handle, jsInsert2.get(), callbackData));  // Same as above but EXPECT_CALL Times is 1
    // Failure cases
    EXPECT_NE(0, dbsync_sync_row(nullptr, jsInsert2.get(), callbackData));
    EXPECT_NE(0, dbsync_sync_row(handle, nullptr, callbackData));
    EXPECT_NE(0, dbsync_sync_row(handle, jsInsert2.get(), callbackEmpty));
}

TEST_F(DBSyncTest, syncRowInsertAndModifiedWithOldData)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };

    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":4,"name":"System","tid":100})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":5,"name":"System","tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":6,"name":"System","tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(MODIFIED, nlohmann::json::parse(R"({"new":{"name":"System","pid":4,"tid":101},"old":{"pid":4,"tid":100}})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(MODIFIED, nlohmann::json::parse(R"({"new":{"name":"Systemmm","pid":4,"tid":105},"old":{"name":"System","pid":4,"tid":101}})"))).Times(1);


    auto insertionQuery1 = InsertQuery::builder().table("processes")
                           .data(nlohmann::json::parse(R"({"pid":4,"name":"System", "tid":100})"))
                           .data(nlohmann::json::parse(R"({"pid":5,"name":"System", "tid":101})"))
                           .data(nlohmann::json::parse(R"({"pid":6,"name":"System", "tid":102})"));
    auto updateQuery1 = SyncRowQuery::builder().table("processes")
                        .returnOldData()
                        .data(nlohmann::json::parse(R"({"pid":4,"name":"System", "tid":101})"));
    auto updateQuery2 = SyncRowQuery::builder().table("processes")
                        .returnOldData()
                        .data(nlohmann::json::parse(R"({"pid":4,"name":"Systemmm", "tid":105})"));

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert1{ cJSON_Parse(insertionQuery1.query().dump().c_str()) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsUpdate1{ cJSON_Parse(updateQuery1.query().dump().c_str()) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsUpdate2{ cJSON_Parse(updateQuery2.query().dump().c_str()) };


    EXPECT_EQ(0, dbsync_sync_row(handle, jsInsert1.get(), callbackData));  // Expect an insert event
    EXPECT_EQ(0, dbsync_sync_row(handle, jsUpdate1.get(), callbackData));  // Expect a modified event
    EXPECT_EQ(0, dbsync_sync_row(handle, jsUpdate2.get(), callbackData));  // Expect a modified event
}

TEST_F(DBSyncTest, syncRowIgnoreFields)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);


    auto insertionQuery = InsertQuery::builder().table("processes")
                          .data(nlohmann::json::parse(R"({"pid":4,"name":"System", "tid":100})"))
                          .data(nlohmann::json::parse(R"({"pid":5,"name":"System", "tid":101})"))
                          .data(nlohmann::json::parse(R"({"pid":6,"name":"System", "tid":102})"));
    auto updateQuery1 = SyncRowQuery::builder().table("processes")
                        .ignoreColumn("tid")
                        .data(nlohmann::json::parse(R"({"pid":4,"name":"System", "tid":101})"));
    auto updateQuery2 = SyncRowQuery::builder().table("processes")
                        .ignoreColumn("tid")
                        .ignoreColumn("name")
                        .data(nlohmann::json::parse(R"({"pid":4,"name":"Systemmm", "tid":105})"));
    auto updateQuery3 = SyncRowQuery::builder().table("processes")
                        .ignoreColumn("tid")
                        .data(nlohmann::json::parse(R"({"pid":4,"name":"SystemIsDown", "tid":106})"));

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert1{ cJSON_Parse(insertionQuery.query().dump().c_str()) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsUpdate1{ cJSON_Parse(updateQuery1.query().dump().c_str()) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsUpdate2{ cJSON_Parse(updateQuery2.query().dump().c_str()) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsUpdate3{ cJSON_Parse(updateQuery3.query().dump().c_str()) };


    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };

    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":4,"name":"System","tid":100})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":5,"name":"System","tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":6,"name":"System","tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(MODIFIED, nlohmann::json::parse(R"({"pid":4, "name":"SystemIsDown", "tid":106})"))).Times(1);

    EXPECT_EQ(0, dbsync_sync_row(handle, jsInsert1.get(), callbackData));  // Expect an insert event
    EXPECT_EQ(0, dbsync_sync_row(handle, jsUpdate1.get(), callbackData));  // Expect an update event
    EXPECT_EQ(0, dbsync_sync_row(handle, jsUpdate2.get(), callbackData));  // Expect an update event
    EXPECT_EQ(0, dbsync_sync_row(handle, jsUpdate3.get(), callbackData));  // Expect an update event
}



TEST_F(DBSyncTest, syncRowInvalidData)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto inputNoData{ R"({"table":"processes"})"};
    const auto inputNoTable{ R"({"data":[{"pid":4,"name":"System", "tid":101}]})"};

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInputNoData{ cJSON_Parse(inputNoData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInputNoTable{ cJSON_Parse(inputNoTable) };

    callback_data_t callbackData { callback, nullptr };

    EXPECT_NE(0, dbsync_sync_row(handle, jsInputNoData.get(), callbackData));
    EXPECT_NE(0, dbsync_sync_row(handle, jsInputNoTable.get(), callbackData));
    EXPECT_NE(0, dbsync_sync_row(reinterpret_cast<void*>(0xffffffff), jsInputNoTable.get(), callbackData));
}

TEST_F(DBSyncTest, selectRowsDataAllNoFilter)
{
    CallbackMock wrapper;

    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` UNSIGNED BIGINT,`cpu_percentage` DOUBLE, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto selectData
    {
        R"({"table":"processes",
           "query":{"column_list":["*"],
           "row_filter":"",
           "distinct_opt":false,
           "order_by_opt":"tid",
           "count_opt":100}})"
    };

    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100, "cpu_percentage":10.7},
                                                                 {"pid":115,"name":"System2", "tid":101, "cpu_percentage":55.4},
                                                                 {"pid":120,"name":"System3", "tid":101, "cpu_percentage":22.1},
                                                                 {"pid":125,"name":"System3", "tid":102, "cpu_percentage":90.3},
                                                                 {"pid":300,"name":"System5", "tid":102, "cpu_percentage":30.5}]})"}; // Insert

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":4,"name":"System1", "tid":100, "cpu_percentage":10.7})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":115,"name":"System2", "tid":101, "cpu_percentage":55.4})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":120,"name":"System3", "tid":101, "cpu_percentage":22.1})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":125,"name":"System3", "tid":102, "cpu_percentage":90.3})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":300,"name":"System5", "tid":102, "cpu_percentage":30.5})"))).Times(1);

    callback_data_t callbackData { callback, &wrapper };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
    EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
}

TEST_F(DBSyncTest, selectRowsDataAllFilterPid)
{
    CallbackMock wrapper;

    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto selectData
    {
        R"({"table":"processes",
           "query":{"column_list":["*"],
           "row_filter":"WHERE pid>120",
           "distinct_opt":false,
           "order_by_opt":"tid",
           "count_opt":100}})"
    };

    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
                                                                 {"pid":115,"name":"System2", "tid":101},
                                                                 {"pid":120,"name":"System3", "tid":101},
                                                                 {"pid":125,"name":"System3", "tid":102},
                                                                 {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":125,"name":"System3", "tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":300,"name":"System5", "tid":102})"))).Times(1);

    callback_data_t callbackData { callback, &wrapper };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
    EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
}

TEST_F(DBSyncTest, selectRowsDataAllFilterPidOr)
{
    CallbackMock wrapper;

    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto selectData
    {
        R"({"table":"processes",
           "query":{"column_list":["*"],
           "row_filter":"WHERE pid=120 OR pid=300",
           "distinct_opt":false,
           "order_by_opt":"tid",
           "count_opt":100}})"
    };

    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
                                                                 {"pid":115,"name":"System2", "tid":101},
                                                                 {"pid":120,"name":"System3", "tid":101},
                                                                 {"pid":125,"name":"System3", "tid":102},
                                                                 {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":120,"name":"System3", "tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":300,"name":"System5", "tid":102})"))).Times(1);

    callback_data_t callbackData { callback, &wrapper };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
    EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
}

TEST_F(DBSyncTest, selectRowsDataAllFilterPidBetween)
{
    CallbackMock wrapper;

    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto selectData
    {
        R"({"table":"processes",
           "query":{"column_list":["*"],
           "row_filter":"WHERE pid BETWEEN 120 AND 300",
           "distinct_opt":false,
           "order_by_opt":"tid",
           "count_opt":100}})"
    };

    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
                                                                 {"pid":115,"name":"System2", "tid":101},
                                                                 {"pid":120,"name":"System3", "tid":101},
                                                                 {"pid":125,"name":"System3", "tid":102},
                                                                 {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":120,"name":"System3", "tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":125,"name":"System3", "tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":300,"name":"System5", "tid":102})"))).Times(1);

    callback_data_t callbackData { callback, &wrapper };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
    EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
}

TEST_F(DBSyncTest, selectCount)
{
    CallbackMock wrapper;

    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto selectData
    {
        R"({"table":"processes",
           "query":{"column_list":["count(*) AS count"],
           "row_filter":"",
           "distinct_opt":false,
           "order_by_opt":"",
           "count_opt":100}})"
    };

    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
                                                                 {"pid":115,"name":"System2", "tid":101},
                                                                 {"pid":120,"name":"System3", "tid":101},
                                                                 {"pid":125,"name":"System3", "tid":102},
                                                                 {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"count":5})"))).Times(1);

    callback_data_t callbackData { callback, &wrapper };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
    EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
}

TEST_F(DBSyncTest, selectInnerJoin)
{
    CallbackMock wrapper;

    const auto sql
    {
        "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `fid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"
        "CREATE TABLE files(`inode` BIGINT, `path` TEXT, `size` BIGINT, PRIMARY KEY (`inode`)) WITHOUT ROWID;"
    };
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto selectData
    {
        R"({"table":"processes",
           "query":{"column_list":["pid,name,fid,path,size"],
           "row_filter":"INNER JOIN files ON processes.fid=files.inode WHERE pid BETWEEN 100 AND 200",
           "distinct_opt":false,
           "order_by_opt":"",
           "count_opt":100}})"
    };

    const auto insertPidsSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "fid":100},
                                                                  {"pid":115,"name":"System2", "fid":101},
                                                                  {"pid":225,"name":"System3", "fid":102}]})"}; // Insert pids
    const auto insertFilesSqlStmt{ R"({"table":"files","data":[{"inode":100,"path":"/usr/bin/System1", "size":123456},
                                                               {"inode":101,"path":"/usr/bin/System2", "size":654321},
                                                               {"inode":102,"path":"/usr/bin/System3", "size":321654}]})"}; // Insert files

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsertPids{ cJSON_Parse(insertPidsSqlStmt) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsertFiles{ cJSON_Parse(insertFilesSqlStmt) };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":115,"name":"System2", "fid":101, "path":"/usr/bin/System2", "size":654321})"))).Times(1);

    callback_data_t callbackData { callback, &wrapper };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsertPids.get()));
    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsertFiles.get()));
    EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
}

TEST_F(DBSyncTest, selectRowsDataAllFilterPid1)
{
    CallbackMock wrapper;

    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto selectData
    {
        R"({"table":"processes",
           "query":{"column_list":["*"],
           "row_filter":"WHERE (pid>120 AND pid<200) ",
           "distinct_opt":false,
           "order_by_opt":"tid",
           "count_opt":100}})"
    };

    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
                                                                 {"pid":115,"name":"System2", "tid":101},
                                                                 {"pid":120,"name":"System3", "tid":101},
                                                                 {"pid":125,"name":"System3", "tid":102},
                                                                 {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":125,"name":"System3", "tid":102})"))).Times(1);

    callback_data_t callbackData { callback, &wrapper };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
    EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
}

TEST_F(DBSyncTest, selectRowsDataAllFilterPidTid)
{
    CallbackMock wrapper;

    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto selectData
    {
        R"({"table":"processes",
           "query":{"column_list":["*"],
           "row_filter":"WHERE (pid>120 AND tid!=101) ",
           "distinct_opt":false,
           "order_by_opt":"tid",
           "count_opt":100}})"
    };

    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
                                                                 {"pid":115,"name":"System2", "tid":101},
                                                                 {"pid":120,"name":"System3", "tid":101},
                                                                 {"pid":125,"name":"System3", "tid":102},
                                                                 {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":125,"name":"System3", "tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":300,"name":"System5", "tid":102})"))).Times(1);

    callback_data_t callbackData { callback, &wrapper };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
    EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
}

TEST_F(DBSyncTest, selectRowsDataNameOnlyFilterPidTid)
{
    CallbackMock wrapper;

    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto selectData
    {
        R"({"table":"processes",
           "query":{"column_list":["name"],
           "row_filter":"WHERE (pid>120 AND tid!=101) ",
           "distinct_opt":false,
           "order_by_opt":"tid",
           "count_opt":100}})"
    };

    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
                                                                 {"pid":115,"name":"System2", "tid":101},
                                                                 {"pid":120,"name":"System3", "tid":101},
                                                                 {"pid":125,"name":"System3", "tid":102},
                                                                 {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System3"})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System5"})"))).Times(1);

    callback_data_t callbackData { callback, &wrapper };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
    EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
}


TEST_F(DBSyncTest, selectRowsDataNameOnly)
{
    CallbackMock wrapper;

    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto selectData
    {
        R"({"table":"processes",
           "query":{"column_list":["name"],
           "row_filter":"",
           "distinct_opt":false,
           "order_by_opt":"tid",
           "count_opt":100}})"
    };

    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
                                                                 {"pid":115,"name":"System2", "tid":101},
                                                                 {"pid":120,"name":"System3", "tid":101},
                                                                 {"pid":125,"name":"System3", "tid":102},
                                                                 {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System1"})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System2"})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System3"})"))).Times(2);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System5"})"))).Times(1);

    callback_data_t callbackData { callback, &wrapper };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
    EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
}

TEST_F(DBSyncTest, selectRowsDataNameOnlyFilterPid)
{
    CallbackMock wrapper;

    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto selectData
    {
        R"({"table":"processes",
           "query":{"column_list":["name"],
           "row_filter":"WHERE pid<120",
           "distinct_opt":false,
           "order_by_opt":"tid",
           "count_opt":100}})"
    };

    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
                                                                 {"pid":115,"name":"System2", "tid":101},
                                                                 {"pid":120,"name":"System3", "tid":101},
                                                                 {"pid":125,"name":"System3", "tid":102},
                                                                 {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System1"})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System2"})"))).Times(1);

    callback_data_t callbackData { callback, &wrapper };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
    EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
}

TEST_F(DBSyncTest, selectRowsDataNameTidOnly)
{
    CallbackMock wrapper;

    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto selectData
    {
        R"({"table":"processes",
           "query":{"column_list":["name","tid"],
           "row_filter":"",
           "distinct_opt":false,
           "order_by_opt":"tid",
           "count_opt":100}})"
    };

    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
                                                                 {"pid":115,"name":"System2", "tid":101},
                                                                 {"pid":120,"name":"System3", "tid":101},
                                                                 {"pid":125,"name":"System3", "tid":102},
                                                                 {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System1","tid":100})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System2","tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System3","tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System3","tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System5","tid":102})"))).Times(1);

    callback_data_t callbackData { callback, &wrapper };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
    EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
}

TEST_F(DBSyncTest, selectRowsDataNameTidOnlyPid)
{
    CallbackMock wrapper;

    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto selectData
    {
        R"({"table":"processes",
           "query":{"column_list":["name","tid"],
           "row_filter":"WHERE pid>100",
           "distinct_opt":false,
           "order_by_opt":"tid",
           "count_opt":100}})"
    };

    const auto selectDataWithoutTable
    {
        R"({"query":{"column_list":["name","tid"],
           "row_filter":"pid>100",
           "distinct_opt":false,
           "order_by_opt":"tid",
           "count_opt":100}})"
    };

    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
                                                                 {"pid":115,"name":"System2", "tid":101},
                                                                 {"pid":120,"name":"System3", "tid":101},
                                                                 {"pid":125,"name":"System3", "tid":102},
                                                                 {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSelectDataWithoutTable{ cJSON_Parse(selectDataWithoutTable) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System2","tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System3","tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System3","tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System5","tid":102})"))).Times(1);

    callback_data_t callbackData { callback, &wrapper };
    callback_data_t callbackEmpty { nullptr, nullptr };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
    EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
    // Failure cases
    EXPECT_NE(0, dbsync_select_rows(reinterpret_cast<void*>(0xffffffff), jsSelectData.get(), callbackData));
    EXPECT_NE(0, dbsync_select_rows(handle, jsSelectDataWithoutTable.get(), callbackData));
    EXPECT_NE(0, dbsync_select_rows(nullptr, jsSelectData.get(), callbackData));
    EXPECT_NE(0, dbsync_select_rows(handle, nullptr, callbackData));
    EXPECT_NE(0, dbsync_select_rows(handle, jsSelectData.get(), callbackEmpty));
}

TEST_F(DBSyncTest, deleteSingleAndComposedData)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":4,"name":"System", "tid":100})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":5,"name":"System", "tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":6,"name":"System", "tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":7,"name":"System", "tid":103})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":8,"name":"System", "tid":104})"))).Times(1);

    const auto initialData{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":100},
                                                            {"pid":5,"name":"System", "tid":101},
                                                            {"pid":6,"name":"System", "tid":102},
                                                            {"pid":7,"name":"System", "tid":103},
                                                            {"pid":8,"name":"System", "tid":104}]})"};

    const auto singleRowToDelete
    {
        R"({"table":"processes",
           "query":{"data":[{"pid":4,"name":"System", "tid":101}],
           "where_filter_opt":""}})"
    };

    const auto composedRowsToDelete
    {
        R"({"table":"processes",
           "query":{"data":[{"pid":5,"name":"Systemmm", "tid":101},
                            {"pid":7,"name":"Systemmm", "tid":103},
                            {"pid":8,"name":"Systemmm", "tid":104}],
                    "where_filter_opt":""}})"
    };

    const auto unexistentRowToDelete
    {
        R"({"table":"processes",
           "query":{"data":[{"pid":9,"name":"Systemmm", "tid":101}],
           "where_filter_opt":""}})"
    };

    const auto dataWithoutTable
    {
        R"({"query":{"data":[{"pid":9,"name":"Systemmm", "tid":101}],
           "where_filter_opt":""})"
    };

    callback_data_t callbackData { callback, &wrapper };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInitialData{ cJSON_Parse(initialData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSingleDeletion{ cJSON_Parse(singleRowToDelete) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsComposedDeletion{ cJSON_Parse(composedRowsToDelete) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsUnexistentDeletion{ cJSON_Parse(unexistentRowToDelete) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsWithoutTable{ cJSON_Parse(dataWithoutTable) };

    EXPECT_EQ(0, dbsync_sync_row(handle, jsInitialData.get(), callbackData));  // Expect an insert event

    EXPECT_EQ(0, dbsync_delete_rows(handle, jsSingleDeletion.get()));
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsComposedDeletion.get()));
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsUnexistentDeletion.get()));
    // Failure cases
    EXPECT_NE(0, dbsync_delete_rows(nullptr, jsSingleDeletion.get()));
    EXPECT_NE(0, dbsync_delete_rows(handle, nullptr));
    EXPECT_NE(0, dbsync_delete_rows(handle, jsWithoutTable.get()));
    EXPECT_NE(0, dbsync_delete_rows(reinterpret_cast<void*>(0xffffffff), jsSingleDeletion.get()));
}

TEST_F(DBSyncTest, deleteSingleDataByCompoundPK)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`, `tid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":4,"name":"System", "tid":100})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":5,"name":"System", "tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":6,"name":"System", "tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":7,"name":"System", "tid":103})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":8,"name":"System", "tid":104})"))).Times(1);
    const auto initialData{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":100},
                                                            {"pid":5,"name":"System", "tid":101},
                                                            {"pid":6,"name":"System", "tid":102},
                                                            {"pid":7,"name":"System", "tid":103},
                                                            {"pid":8,"name":"System", "tid":104}]})"};

    const auto singleRowToDelete
    {
        R"({"table":"processes",
           "query":{"data":[{"pid":4, "tid":100}],
           "where_filter_opt":""}})"
    };

    const auto singleRowWithoutCompleteCompoundPK
    {
        R"({"table":"processes",
           "query":{"data":[{"tid":101}],
                    "where_filter_opt":""}})"
    };

    callback_data_t callbackData { callback, &wrapper };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInitialData{ cJSON_Parse(initialData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsSingleDeletion{ cJSON_Parse(singleRowToDelete) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsMissingPKPID{ cJSON_Parse(singleRowWithoutCompleteCompoundPK) };

    EXPECT_EQ(0, dbsync_sync_row(handle, jsInitialData.get(), callbackData));  // Expect an insert event
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsSingleDeletion.get()));
    EXPECT_NE(0, dbsync_delete_rows(handle, jsMissingPKPID.get()));
}

TEST_F(DBSyncTest, deleteRowsByFilter)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":4,"name":"System", "tid":100})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":5,"name":"User1", "tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":6,"name":"User2", "tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":7,"name":"User3", "tid":103})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":8,"name":"User4", "tid":104})"))).Times(1);

    const auto initialData{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":100},
                                                            {"pid":5,"name":"User1", "tid":101},
                                                            {"pid":6,"name":"User2", "tid":102},
                                                            {"pid":7,"name":"User3", "tid":103},
                                                            {"pid":8,"name":"User4", "tid":104}]})"};

    const auto rowDeleteByPIDFilter
    {
        R"({"table":"processes",
           "query":{"data":[],
           "where_filter_opt":"pid=5"}})"
    };

    const auto rowDeleteByTIDFilter
    {
        R"({"table":"processes",
           "query":{"data":[],
           "where_filter_opt":"tid>=103"}})"
    };

    const auto rowDeleteByNameFilter
    {
        R"({"table":"processes",
           "query":{"data":[],
           "where_filter_opt":"name LIKE '%User2%'"}})"
    };

    callback_data_t callbackData { callback, &wrapper };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInitialData{ cJSON_Parse(initialData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsrowDeleteByPIDFilter{ cJSON_Parse(rowDeleteByPIDFilter) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsrowDeleteByTIDFilter{ cJSON_Parse(rowDeleteByTIDFilter) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsrowDeleteByNameFilter{ cJSON_Parse(rowDeleteByNameFilter) };

    EXPECT_EQ(0, dbsync_sync_row(handle, jsInitialData.get(), callbackData));  // Expect an insert event
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsrowDeleteByPIDFilter.get()));
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsrowDeleteByTIDFilter.get()));
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsrowDeleteByNameFilter.get()));
}

TEST_F(DBSyncTest, deleteRowsWithDataMorePriorityThanFilter)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":4,"name":"System", "tid":100})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":5,"name":"User1", "tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":6,"name":"User2", "tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":7,"name":"User3", "tid":103})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":8,"name":"User4", "tid":104})"))).Times(1);

    const auto initialData{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":100},
                                                            {"pid":5,"name":"User1", "tid":101},
                                                            {"pid":6,"name":"User2", "tid":102},
                                                            {"pid":7,"name":"User3", "tid":103},
                                                            {"pid":8,"name":"User4", "tid":104}]})"};

    const auto rowDeletePID4
    {
        R"({"table":"processes",
           "query":{"data":[{"pid":4,"name":"System", "tid":100}],
           "where_filter_opt":""}})"
    };

    const auto rowDeletePID6
    {
        R"({"table":"processes",
           "query":{"data":[{"pid":6,"name":"User2", "tid":102}],
           "where_filter_opt":"tid>=103"}})"
    };

    const auto rowDeletePID8
    {
        R"({"table":"processes",
           "query":{"data":[{"pid":8,"name":"User4", "tid":104}],
           "where_filter_opt":"name LIKE '%User2%'"}})"
    };

    callback_data_t callbackData { callback, &wrapper };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInitialData{ cJSON_Parse(initialData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsRowDeletePID4{ cJSON_Parse(rowDeletePID4) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsRowDeletePID6{ cJSON_Parse(rowDeletePID6) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsRowDeletePID8{ cJSON_Parse(rowDeletePID8) };

    EXPECT_EQ(0, dbsync_sync_row(handle, jsInitialData.get(), callbackData));  // Expect an insert event
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsRowDeletePID4.get()));
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsRowDeletePID6.get()));
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsRowDeletePID8.get()));
}

TEST_F(DBSyncTest, deleteRowsWithNoDataAndFilterShouldFail)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":4,"name":"System", "tid":100})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":5,"name":"User1", "tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":6,"name":"User2", "tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":7,"name":"User3", "tid":103})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":8,"name":"User4", "tid":104})"))).Times(1);

    const auto initialData{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":100},
                                                            {"pid":5,"name":"User1", "tid":101},
                                                            {"pid":6,"name":"User2", "tid":102},
                                                            {"pid":7,"name":"User3", "tid":103},
                                                            {"pid":8,"name":"User4", "tid":104}]})"};

    const auto rowEmpty
    {
        R"({"table":"processes",
           "query":{"data":[],
           "where_filter_opt":""}})"
    };

    callback_data_t callbackData { callback, &wrapper };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInitialData{ cJSON_Parse(initialData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsRowEmpty{ cJSON_Parse(rowEmpty) };

    EXPECT_EQ(0, dbsync_sync_row(handle, jsInitialData.get(), callbackData));  // Expect an insert event
    EXPECT_NE(0, dbsync_delete_rows(handle, jsRowEmpty.get()));
}

TEST_F(DBSyncTest, deleteRowsWithWhereInFilterShouldFail)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":4,"name":"System", "tid":100})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":5,"name":"User1", "tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":6,"name":"User2", "tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":7,"name":"User3", "tid":103})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"pid":8,"name":"User4", "tid":104})"))).Times(1);

    const auto initialData{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":100},
                                                            {"pid":5,"name":"User1", "tid":101},
                                                            {"pid":6,"name":"User2", "tid":102},
                                                            {"pid":7,"name":"User3", "tid":103},
                                                            {"pid":8,"name":"User4", "tid":104}]})"};

    const auto rowWithWhere
    {
        R"({"table":"processes",
           "query":{"data":[],
           "where_filter_opt":"WHERE name LIKE '%User2%'"}})"
    };

    const auto rowWithSpace
    {
        R"({"table":"processes",
           "query":{"data":[],
           "where_filter_opt":" "}})"
    };

    callback_data_t callbackData { callback, &wrapper };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInitialData{ cJSON_Parse(initialData) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsRowWithWhere{ cJSON_Parse(rowWithWhere) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsRowWithSpace{ cJSON_Parse(rowWithSpace) };

    EXPECT_EQ(0, dbsync_sync_row(handle, jsInitialData.get(), callbackData));  // Expect an insert event
    EXPECT_NE(0, dbsync_delete_rows(handle, jsRowWithWhere.get())); // WHERE in 'where_filter_opt' should fail
    EXPECT_NE(0, dbsync_delete_rows(handle, jsRowWithSpace.get())); // space in 'where_filter_opt' should fail
}

TEST_F(DBSyncTest, selectCountCPP)
{
    CallbackMock wrapper;
    std::unique_ptr<DBSync> dbSync;

    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    EXPECT_NO_THROW(dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql));

    const auto selectData
    {
        R"({"table":"processes",
           "query":{"column_list":["count(*) AS count"],
           "row_filter":"",
           "distinct_opt":false,
           "order_by_opt":"",
           "count_opt":100}})"
    };

    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
                                                                 {"pid":115,"name":"System2", "tid":101},
                                                                 {"pid":120,"name":"System3", "tid":101},
                                                                 {"pid":125,"name":"System3", "tid":102},
                                                                 {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

    const auto rowDeletePID4
    {
        R"({"table":"processes",
           "query":{"data":[{"pid":4}],
           "where_filter_opt":""}})"
    };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"count":5})"))).Times(1);

    ResultCallbackData selectCallbackData
    {
        [&wrapper](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            wrapper.callbackMock(type, jsonResult);
        }
    };

    EXPECT_NO_THROW(dbSync->insertData(nlohmann::json::parse(insertionSqlStmt)));
    EXPECT_NO_THROW(dbSync->selectRows(nlohmann::json::parse(selectData), selectCallbackData));
    EXPECT_NO_THROW(dbSync->deleteRows(nlohmann::json::parse(rowDeletePID4)));
}

TEST_F(DBSyncTest, TryToInsertMoreThanMaxRowsCPP)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}, {"pid":3,"name":"cmd"}]})"};
    std::unique_ptr<DBSync> dbSync;

    EXPECT_NO_THROW(dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql));

    EXPECT_NO_THROW(dbSync->setTableMaxRow("processes", 1));
    EXPECT_ANY_THROW(dbSync->insertData(nlohmann::json::parse(insertionSqlStmt)));

    EXPECT_NO_THROW(dbSync->setTableMaxRow("processes", 0));
    EXPECT_ANY_THROW(dbSync->insertData(nlohmann::json::parse(insertionSqlStmt)));

    const auto rowDeletePID4
    {
        R"({"table":"processes",
           "query":{"data":[{"pid":4}],
           "where_filter_opt":""}})"
    };

    EXPECT_NO_THROW(dbSync->deleteRows(nlohmann::json::parse(rowDeletePID4)));
    EXPECT_NO_THROW(dbSync->insertData(nlohmann::json::parse(insertionSqlStmt)));
}

TEST_F(DBSyncTest, createTxnCPP)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto tables { R"({"table": "processes"})" };
    const std::unique_ptr<DummyContext> dummyCtx { std::make_unique<DummyContext>()};
    std::unique_ptr<DBSync> dbSync;

    EXPECT_NO_THROW(dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql));

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"System","pid":4})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"Guake","pid":7})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(DELETED, nlohmann::json::parse(R"({"name":"System","pid":4})"))).Times(1);

    ResultCallbackData callbackData
    {
        [&wrapper](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            wrapper.callbackMock(type, jsonResult);
        }
    };

    const auto insertionSqlStmt1{ R"(
        {
            "table":"processes",
            "data":
                [
                    {"pid":4,"name":"System"}
                ]
        })"}; // Insert

    EXPECT_NO_THROW(dbSync->syncRow(nlohmann::json::parse(insertionSqlStmt1), callbackData));  // Expect an insert event

    std::unique_ptr<DBSyncTxn> dbSyncTxn;
    EXPECT_NO_THROW(dbSyncTxn = std::make_unique<DBSyncTxn>(dbSync->handle(), nlohmann::json::parse(tables), 0, 100, callbackData));

    const auto insertionSqlStmt2{ R"({"table":"processes","data":[{"pid":7,"name":"Guake"}]})" }; // Insert
    EXPECT_NO_THROW(dbSyncTxn->syncTxnRow(nlohmann::json::parse(insertionSqlStmt2)));

    EXPECT_NO_THROW(dbSyncTxn->getDeletedRows(callbackData));
}


TEST_F(DBSyncTest, createTxnCPP1)
{
    constexpr auto sql
    {
        R"(CREATE TABLE processes (
        pid BIGINT,
        name TEXT,
        state TEXT,
        ppid BIGINT,
        utime BIGINT,
        stime BIGINT,
        cmd TEXT,
        argvs TEXT,
        euser TEXT,
        ruser TEXT,
        suser TEXT,
        egroup TEXT,
        rgroup TEXT,
        sgroup TEXT,
        fgroup TEXT,
        priority BIGINT,
        nice BIGINT,
        size BIGINT,
        vm_size BIGINT,
        resident BIGINT,
        share BIGINT,
        start_time BIGINT,
        pgrp BIGINT,
        session BIGINT,
        nlwp BIGINT,
        tgid BIGINT,
        tty BIGINT,
        processor BIGINT,
        PRIMARY KEY (pid)) WITHOUT ROWID;)"
    };
    const auto tables { R"({"table": "processes"})" };
    const std::unique_ptr<DummyContext> dummyCtx { std::make_unique<DummyContext>()};
    std::unique_ptr<DBSync> dbSync;

    EXPECT_NO_THROW(dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql));
    const auto& data1{nlohmann::json::parse(input1)};
    const auto& data2{nlohmann::json::parse(input2)};
    const auto& diffData{nlohmann::json::parse(diffResult)};
    nlohmann::json insertionSqlStmt1;
    insertionSqlStmt1["table"] = "processes";
    insertionSqlStmt1["data"] = data1;
    nlohmann::json insertionSqlStmt2;
    insertionSqlStmt2["table"] = "processes";
    insertionSqlStmt2["data"] = data2;

    CallbackMock wrapper;

    for (const auto& entry : data1)
    {
        EXPECT_CALL(wrapper, callbackMock(INSERTED, entry)).Times(1);
    }

    for (const auto& entry : diffData)
    {
        EXPECT_CALL(wrapper, callbackMock(MODIFIED, entry)).Times(1);
    }

    ResultCallbackData callbackData
    {
        [&wrapper](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            wrapper.callbackMock(type, jsonResult);
        }
    };
    EXPECT_NO_THROW(dbSync->syncRow(insertionSqlStmt1, callbackData));  // Expect an insert event

    std::unique_ptr<DBSyncTxn> dbSyncTxn;
    EXPECT_NO_THROW(dbSyncTxn = std::make_unique<DBSyncTxn>(dbSync->handle(), nlohmann::json::parse(tables), 0, 4096, callbackData));

    EXPECT_NO_THROW(dbSyncTxn->syncTxnRow(insertionSqlStmt2));

    EXPECT_NO_THROW(dbSyncTxn->getDeletedRows(callbackData));
}


TEST_F(DBSyncTest, createTxnCPP2)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `time` BIGINT, PRIMARY KEY (`pid`, `time`)) WITHOUT ROWID;"};
    const auto tables { R"({"table": "processes"})" };
    const std::unique_ptr<DummyContext> dummyCtx { std::make_unique<DummyContext>()};
    std::unique_ptr<DBSync> dbSync;

    EXPECT_NO_THROW(dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql));

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"System","pid":4, "time":100100})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"Guake","pid":7,"time":100101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(DELETED, nlohmann::json::parse(R"({"name":"System","pid":4,"time":100100})"))).Times(1);

    ResultCallbackData callbackData
    {
        [&wrapper](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            wrapper.callbackMock(type, jsonResult);
        }
    };

    auto syncSqlStmt1 = SyncRowQuery::builder().table("processes")
                        .data(nlohmann::json::parse(R"({"pid":4,"name":"System", "time":100100})"))
                        .query();
    auto syncSqlStmt2 = SyncRowQuery::builder().table("processes")
                        .data(nlohmann::json::parse(R"({"pid":7,"name":"Guake","time":100101})"))
                        .query();

    EXPECT_NO_THROW(dbSync->syncRow(syncSqlStmt1, callbackData));

    std::unique_ptr<DBSyncTxn> dbSyncTxn;
    EXPECT_NO_THROW(dbSyncTxn = std::make_unique<DBSyncTxn>(dbSync->handle(), nlohmann::json::parse(tables), 0, 100, callbackData));

    EXPECT_NO_THROW(dbSyncTxn->syncTxnRow(syncSqlStmt2));

    EXPECT_NO_THROW(dbSyncTxn->getDeletedRows(callbackData));
}

TEST_F(DBSyncTest, createTxnCPP3)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `time` BIGINT, PRIMARY KEY (`pid`, `time`)) WITHOUT ROWID;"};
    const auto tables { R"({"table": "processes"})" };
    const std::unique_ptr<DummyContext> dummyCtx { std::make_unique<DummyContext>()};
    std::unique_ptr<DBSync> dbSync;

    EXPECT_NO_THROW(dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql));

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"System","pid":4, "time":100100})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"Guake","pid":7,"time":100101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(DELETED, nlohmann::json::parse(R"({"pid":4,"time":100100,"name":"System"})"))).Times(1);

    ResultCallbackData callbackData
    {
        [&wrapper](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            wrapper.callbackMock(type, jsonResult);
        }
    };

    auto syncSqlStmt1 = SyncRowQuery::builder().table("processes")
                        .data(nlohmann::json::parse(R"({"pid":4,"name":"System", "time":100100})"))
                        .query();
    auto syncSqlStmt2 = SyncRowQuery::builder().table("processes")
                        .data(nlohmann::json::parse(R"({"pid":7,"name":"Guake","time":100101})"))
                        .query();

    EXPECT_NO_THROW(dbSync->syncRow(syncSqlStmt1, callbackData));

    std::unique_ptr<DBSyncTxn> dbSyncTxn;
    EXPECT_NO_THROW(dbSyncTxn = std::make_unique<DBSyncTxn>(dbSync->handle(), nlohmann::json::parse(tables), 0, 100, callbackData));

    EXPECT_NO_THROW(dbSyncTxn->syncTxnRow(syncSqlStmt2));

    EXPECT_NO_THROW(dbSyncTxn->getDeletedRows(callbackData));
}

TEST_F(DBSyncTest, teardownCPP)
{
    std::unique_ptr<DBSync> dbSync;
    const auto sql { R"(CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `path` TEXT, `cmdline` TEXT, `state` TEXT, `cwd` TEXT, `root` TEXT, `uid` BIGINT, `gid` BIGINT, `euid` BIGINT, `egid` BIGINT, `suid` BIGINT, `sgid` BIGINT, `on_disk` INTEGER, `wired_size` BIGINT, `resident_size` BIGINT, `total_size` BIGINT, `user_time` BIGINT, `system_time` BIGINT, `disk_bytes_read` BIGINT, `disk_bytes_written` BIGINT, `start_time` BIGINT, `parent` BIGINT, `pgroup` BIGINT, `threads` INTEGER, `nice` INTEGER, `is_elevated_token` INTEGER, `elapsed_time` BIGINT, `handle_count` BIGINT, `percent_processor_time` BIGINT, `upid` BIGINT HIDDEN, `uppid` BIGINT HIDDEN, `cpu_type` INTEGER HIDDEN, `cpu_subtype` INTEGER HIDDEN, `phys_footprint` BIGINT HIDDEN, PRIMARY KEY (`pid`)) WITHOUT ROWID;CREATE TABLE processes_sockets(`socket_id` BIGINT, `pid` BIGINT, PRIMARY KEY (`socket_id`)) WITHOUT ROWID;)"};
    EXPECT_NO_THROW(dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql));
    ASSERT_NO_THROW(dbSync->teardown());
}

TEST_F(DBSyncTest, dbsyncAddTableRelationshipCPP)
{
    const auto sql { R"(CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `path` TEXT, `cmdline` TEXT, `state` TEXT, `cwd` TEXT, `root` TEXT, `uid` BIGINT, `gid` BIGINT, `euid` BIGINT, `egid` BIGINT, `suid` BIGINT, `sgid` BIGINT, `on_disk` INTEGER, `wired_size` BIGINT, `resident_size` BIGINT, `total_size` BIGINT, `user_time` BIGINT, `system_time` BIGINT, `disk_bytes_read` BIGINT, `disk_bytes_written` BIGINT, `start_time` BIGINT, `parent` BIGINT, `pgroup` BIGINT, `threads` INTEGER, `nice` INTEGER, `is_elevated_token` INTEGER, `elapsed_time` BIGINT, `handle_count` BIGINT, `percent_processor_time` BIGINT, `upid` BIGINT HIDDEN, `uppid` BIGINT HIDDEN, `cpu_type` INTEGER HIDDEN, `cpu_subtype` INTEGER HIDDEN, `phys_footprint` BIGINT HIDDEN, PRIMARY KEY (`pid`)) WITHOUT ROWID;CREATE TABLE processes_sockets(`socket_id` BIGINT, `pid` BIGINT, PRIMARY KEY (`socket_id`)) WITHOUT ROWID;)"};
    std::unique_ptr<DBSync> dbSync;
    EXPECT_NO_THROW(dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql));

    const auto insertDataProcess{ R"(
        {
            "table": "processes",
            "data":[
                {
                    "pid":4,
                    "name":"System",
                    "path":"",
                    "cmdline":"",
                    "state":"",
                    "cwd":"",
                    "root":"",
                    "uid":-1,
                    "gid":-1,
                    "euid":-1,
                    "egid":-1,
                    "suid":-1,
                    "sgid":-1,
                    "on_disk":-1,
                    "wired_size":-1,
                    "resident_size":-1,
                    "total_size":-1,
                    "user_time":-1,
                    "system_time":-1,
                    "disk_bytes_read":-1,
                    "disk_bytes_written":-1,
                    "start_time":-1,
                    "parent":0,
                    "pgroup":-1,
                    "threads":164,
                    "nice":-1,
                    "is_elevated_token":false,
                    "elapsed_time":-1,
                    "handle_count":-1,
                    "percent_processor_time":-1
                 }
            ]
        }
    )"};

    EXPECT_NO_THROW(dbSync->insertData(nlohmann::json::parse(insertDataProcess)));

    const auto insertDataSocket{ R"(
        {
        "table": "processes_sockets",
            "data":[
                {
                    "pid":4,
                    "socket_id":1
                }
            ]
        }
    )"};

    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsInsertSocket{ cJSON_Parse(insertDataSocket) };
    EXPECT_NO_THROW(dbSync->insertData(nlohmann::json::parse(insertDataSocket)));

    const auto relationshipJson { R"(
        {
            "base_table":"processes",
            "relationed_tables":
            [
                {
                    "table": "processes_sockets",
                    "field_match":
                    {
                        "pid": "pid"
                    }
                }
            ]
        })"};

    EXPECT_NO_THROW(dbSync->addTableRelationship(nlohmann::json::parse(relationshipJson)));

    const auto deleteProcess{ R"(
        {
            "table": "processes",
            "query": {
                "data":[
                {
                    "pid":4
                }],
                "where_filter_opt":""
            }
        })"};

    EXPECT_NO_THROW(dbSync->deleteRows(nlohmann::json::parse(deleteProcess)));

    const auto insertionSqlStmt1{ R"(
        {
            "table":"processes",
            "data":
                [
                    {"pid":4,"name":"System", "tid":100},
                    {"pid":5,"name":"System", "tid":101},
                    {"pid":6,"name":"System", "tid":102}
                ]
        })"}; // Insert

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"System","pid":4,"tid":100})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"System","pid":5,"tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"System","pid":6,"tid":102})"))).Times(1);

    ResultCallbackData callbackData
    {
        [&wrapper](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            wrapper.callbackMock(type, jsonResult);
        }
    };

    EXPECT_NO_THROW(dbSync->syncRow(nlohmann::json::parse(insertionSqlStmt1), callbackData));  // Expect an insert event
}

TEST_F(DBSyncTest, UpdateDataCPP)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt1{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};
    const auto insertionSqlStmt2{ R"({"table":"processes","data":[{"pid":5,"name":"Test"}]})"};

    std::unique_ptr<DBSync> dbSync;
    EXPECT_NO_THROW(dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql));

    nlohmann::json jsResponse;

    EXPECT_NO_THROW(dbSync->updateWithSnapshot(nlohmann::json::parse(insertionSqlStmt1), jsResponse));
    EXPECT_NE(nullptr, jsResponse);

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"Test","pid":5})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(DELETED, nlohmann::json::parse(R"({"pid":4})"))).Times(1);


    ResultCallbackData callbackData
    {
        [&wrapper](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            wrapper.callbackMock(type, jsonResult);
        }
    };

    EXPECT_NO_THROW(dbSync->updateWithSnapshot(nlohmann::json::parse(insertionSqlStmt2), callbackData));
}

TEST_F(DBSyncTest, constructorWithHandle)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};

    std::unique_ptr<DBSync> dbSync;
    EXPECT_NO_THROW(dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql));

    std::unique_ptr<DBSync> dbSyncHandled;
    EXPECT_NO_THROW(dbSyncHandled = std::make_unique<DBSync>(dbSync->handle()));

    EXPECT_EQ(dbSync->handle(), dbSyncHandled->handle());

}

TEST_F(DBSyncTest, txnDestructorOwnsHandle)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto tables { R"({"table": "processes"})" };
    auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ResultCallbackData callback { [](ReturnTypeCallback, const nlohmann::json&) {}};
    TXN_HANDLE txHandle = nullptr;
    {
        // Use the overload that creates TXN_HANDLE from within and as such, has ownership of it.
        DBSyncTxn tx(handle, nlohmann::json::parse(tables), 1, 100, callback);
        tx = tx.handle();
    }
    EXPECT_NE(dbsync_close_txn(txHandle), 0);
}

TEST_F(DBSyncTest, txnDestructorDoesNotOwnHandle)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto tables { R"({"table": "processes"})" };
    const std::unique_ptr<DummyContext> dummyCtx { std::make_unique<DummyContext>()};
    auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    const std::unique_ptr<cJSON, CJsonSmartDeleter> jsonTables { cJSON_Parse(tables) };
    callback_data_t callbackData { callback, dummyCtx.get() };
    TXN_HANDLE txHandle = dbsync_create_txn(handle, jsonTables.get(), 1, 100, callbackData);
    {
        // Use the overload that only takes a TXN_HANDLE and sets up the destructor to NOT release the handle.
        DBSyncTxn tx(txHandle);
        tx = tx.handle();
    }
    EXPECT_EQ(dbsync_close_txn(txHandle), 0);

}


TEST_F(DBSyncTest, teardown)
{
    EXPECT_NO_THROW(DBSync::teardown());
}

TEST(QueryBuilder, selectInsertDeleteQuery)
{
    CallbackMock wrapper;
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};

    std::unique_ptr<DBSync> dbSync;
    EXPECT_NO_THROW(dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_MEMORY, sql));

    auto selectQuery
    {
        SelectQuery::builder()
        .table("processes")
        .columnList({"pid", "name"})
        .rowFilter("WHERE pid = 4")
        .orderByOpt("pid")
        .distinctOpt(false)
        .countOpt(1)
        .build()
    };

    auto insertQuery
    {
        InsertQuery::builder()
        .table("processes")
        .data({{"pid", 4}, {"name", "System1"}, {"tid", 100}})
        .data({{"pid", 5}, {"name", "System2"}})
        .data({{"pid", 6}, {"tid", 103}})
        .build()
    };

    auto deleteQuery
    {
        DeleteQuery::builder()
        .table("processes")
        .data({{"pid", 6}})
        .rowFilter("")
        .build()
    };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System1","pid":4})"))).Times(4);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System2","pid":5})"))).Times(1);

    ResultCallbackData selectCallbackData
    {
        [&wrapper](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            wrapper.callbackMock(type, jsonResult);
        }
    };

    EXPECT_NO_THROW(dbSync->insertData(insertQuery.query()));
    EXPECT_NO_THROW(dbSync->deleteRows(deleteQuery.query()));
    EXPECT_NO_THROW(dbSync->selectRows(selectQuery.query(), selectCallbackData));
    selectQuery.rowFilter("");
    EXPECT_NO_THROW(dbSync->selectRows(selectQuery.query(), selectCallbackData));
    deleteQuery.reset();
    deleteQuery.rowFilter("pid=5");
    EXPECT_NO_THROW(dbSync->deleteRows(deleteQuery.query()));
    selectQuery.countOpt(2);
    EXPECT_NO_THROW(dbSync->selectRows(selectQuery.query(), selectCallbackData));
    insertQuery.reset();
    insertQuery.data({{"pid", 5}, {"name", "System2"}});
    EXPECT_NO_THROW(dbSync->insertData(insertQuery.query()));
    EXPECT_NO_THROW(dbSync->selectRows(selectQuery.query(), selectCallbackData));
}

TEST_F(DBSyncTest, TryInvalidValuesOnSetMaxRowsCPP)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    std::unique_ptr<DBSync> dbSync;

    EXPECT_NO_THROW(dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql));

    EXPECT_ANY_THROW(dbSync->setTableMaxRow("processes", -100));
}

TEST_F(DBSyncTest, TryToInsertMoreRowsWithFilledTableCPP)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt1{ R"({"table":"processes","data":[{"pid":4,"name":"System"}, {"pid":3,"name":"cmd"}]})"};
    const auto insertionSqlStmt2{ R"({"table":"processes","data":[{"pid":5,"name":"htop"}, {"pid":6,"name":"top"}]})"};
    std::unique_ptr<DBSync> dbSync;

    EXPECT_NO_THROW(dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql));

    EXPECT_NO_THROW(dbSync->insertData(nlohmann::json::parse(insertionSqlStmt1)));

    EXPECT_NO_THROW(dbSync->setTableMaxRow("processes", 2));
    EXPECT_ANY_THROW(dbSync->insertData(nlohmann::json::parse(insertionSqlStmt2)));
}

TEST_F(DBSyncTest, createTxnWithMaxRowsCPP)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto tables { R"({"table": "processes"})" };
    const std::unique_ptr<DummyContext> dummyCtx { std::make_unique<DummyContext>()};
    std::unique_ptr<DBSync> dbSync;

    EXPECT_NO_THROW(dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql));

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"System","pid":4})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"Guake","pid":7})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(MAX_ROWS, nlohmann::json::parse(R"({"data":[{"name":"Guake","pid":7},{"name":"Guake2","pid":8}],"table":"processes"})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(DELETED, nlohmann::json::parse(R"({"name":"System","pid":4})"))).Times(1);

    ResultCallbackData callbackData
    {
        [&wrapper](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            wrapper.callbackMock(type, jsonResult);
        }
    };

    const auto insertionSqlStmt1{ R"(
        {
            "table":"processes",
            "data":
                [
                    {"pid":4,"name":"System"}
                ]
        })"}; // Insert

    EXPECT_NO_THROW(dbSync->syncRow(nlohmann::json::parse(insertionSqlStmt1), callbackData));  // Expect an insert event

    std::unique_ptr<DBSyncTxn> dbSyncTxn;
    EXPECT_NO_THROW(dbSyncTxn = std::make_unique<DBSyncTxn>(dbSync->handle(), nlohmann::json::parse(tables), 0, 100, callbackData));

    const auto syncTxnData { R"(
        {
            "table":"processes",
            "data":
                [
                    {"pid":7,"name":"Guake"},
                    {"pid":8,"name":"Guake2"}
                ]
        })" }; // Insert


    EXPECT_NO_THROW(dbSync->setTableMaxRow("processes", 2));
    EXPECT_NO_THROW(dbSyncTxn->syncTxnRow(nlohmann::json::parse(syncTxnData)));
    EXPECT_NO_THROW(dbSyncTxn->getDeletedRows(callbackData));
}

TEST_F(DBSyncTest, createTxnAtomicOperation)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `time` BIGINT, PRIMARY KEY (`pid`, `time`)) WITHOUT ROWID;"};
    const auto tables { R"({"table": "processes"})" };
    std::unique_ptr<DBSync> dbSync;

    EXPECT_NO_THROW(dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql));

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"System","pid":4, "time":100100})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"({"name":"Guake","pid":7,"time":100101})"))).Times(1);

    ResultCallbackData callbackData
    {
        [&wrapper](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            wrapper.callbackMock(type, jsonResult);
        }
    };

    const auto insertionSqlStmt1{ R"({"table":"processes","data":[{"pid":4,"name":"System", "time":100100}]})"}; // Insert
    std::unique_ptr<DBSyncTxn> dbSyncTxn;
    EXPECT_NO_THROW(dbSyncTxn = std::make_unique<DBSyncTxn>(dbSync->handle(), nlohmann::json::parse(tables), 0, 100, callbackData));
    EXPECT_NO_THROW(dbSyncTxn->syncTxnRow(nlohmann::json::parse(insertionSqlStmt1)));

    const auto insertionSqlStmt2{ R"({"table":"processes","data":[{"pid":7,"name":"Guake","time":100101}]})" }; // Insert
    EXPECT_NO_THROW(dbSync->syncRow(nlohmann::json::parse(insertionSqlStmt2), callbackData));  // Expect an insert event

    EXPECT_NO_THROW(dbSyncTxn->getDeletedRows(callbackData));

    dbSyncTxn.reset();

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"count":2})"))).Times(1);

    const auto selectData
    {
        R"({"table":"processes",
           "query":{"column_list":["count(*) AS count"],
           "row_filter":"",
           "distinct_opt":false,
           "order_by_opt":"",
           "count_opt":100}})"
    };

    EXPECT_NO_THROW(dbSync->selectRows(nlohmann::json::parse(selectData), callbackData));
}

TEST_F(DBSyncTest, InitializationCPP)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `time` BIGINT, PRIMARY KEY (`pid`, `time`)) WITHOUT ROWID;"};
    std::unique_ptr<DBSync> dbSync;

    EXPECT_NO_THROW(dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql));

    // On windows, no change in permissions is expected
#ifndef _WIN32
    struct stat stStat {};
    ASSERT_EQ(0, stat(DATABASE_TEMP, &stStat));
    ASSERT_NE(0, S_ISREG(stStat.st_mode));
    EXPECT_EQ(DATABASE_PERMISSIONS, stStat.st_mode & 0777);
#endif
}

TEST_F(DBSyncTest, TestVolatileMode)
{
    const auto sql{"CREATE TABLE simple_test(`name` TEXT, `value` BIGINT, PRIMARY KEY (`name`));"};
    std::vector<std::string> updates;

    auto dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql, DbManagement::VOLATILE, updates);
    dbSync->insertData(nlohmann::json::parse(R"({"table":"simple_test","data":[{"name":"test1","value":1}]})"));

    auto selectQuery
    {
        SelectQuery::builder()
        .table("simple_test")
        .columnList({"name", "value"})
        .rowFilter("WHERE name = 'test1'")
        .orderByOpt("name")
        .distinctOpt(false)
        .countOpt(1)
        .build()
    };

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"test1","value":1})"))).Times(1);

    ResultCallbackData selectCallbackData
    {
        [&wrapper](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            wrapper.callbackMock(type, jsonResult);
        }
    };

    EXPECT_NO_THROW(dbSync->selectRows(selectQuery.query(), selectCallbackData));

    // We expect no data after re-initializing the DB in VOLATILE mode
    dbSync.reset();
    dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql, DbManagement::VOLATILE, updates);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse("{}"))).Times(0);

    EXPECT_NO_THROW(dbSync->selectRows(selectQuery.query(), selectCallbackData));
}

TEST_F(DBSyncTest, TestPersistentMode)
{
    const auto sql{"CREATE TABLE simple_test(`name` TEXT, `value` BIGINT, PRIMARY KEY (`name`));"};
    std::vector<std::string> updates;

    auto dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql, DbManagement::PERSISTENT, updates);
    dbSync->insertData(nlohmann::json::parse(R"({"table":"simple_test","data":[{"name":"test1","value":1}]})"));

    auto selectQuery
    {
        SelectQuery::builder()
        .table("simple_test")
        .columnList({"name", "value"})
        .rowFilter("WHERE name = 'test1'")
        .orderByOpt("name")
        .distinctOpt(false)
        .countOpt(1)
        .build()
    };

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"test1","value":1})"))).Times(1);

    ResultCallbackData selectCallbackData
    {
        [&wrapper](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            wrapper.callbackMock(type, jsonResult);
        }
    };

    EXPECT_NO_THROW(dbSync->selectRows(selectQuery.query(), selectCallbackData));

    // We expect the same data after re-initializing the DB in PERSISTENT mode
    dbSync.reset();
    dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql, DbManagement::PERSISTENT, updates);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"test1","value":1})"))).Times(1);

    EXPECT_NO_THROW(dbSync->selectRows(selectQuery.query(), selectCallbackData));
}

TEST_F(DBSyncTest, TestUpgrade)
{
    const auto sql{"CREATE TABLE simple_test(`name` TEXT, `value` BIGINT, PRIMARY KEY (`name`));"};
    std::vector<std::string> updates;

    auto dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql, DbManagement::PERSISTENT, updates);

    // After the re-initialization, we expect the upgrades to run
    const auto update1{"ALTER TABLE simple_test ADD COLUMN `new_column` TEXT;"};
    updates.push_back(update1);

    dbSync.reset();
    dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql, DbManagement::PERSISTENT, updates);

    dbSync->insertData(nlohmann::json::parse(R"({"table":"simple_test","data":[{"name":"test1","value":1,"new_column":"new_value"}]})"));

    auto selectQuery
    {
        SelectQuery::builder()
        .table("simple_test")
        .columnList({"name", "value", "new_column"})
        .rowFilter("WHERE name = 'test1'")
        .orderByOpt("name")
        .distinctOpt(false)
        .countOpt(1)
        .build()
    };

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"test1","value":1,"new_column":"new_value"})"))).Times(1);

    ResultCallbackData selectCallbackData
    {
        [&wrapper](ReturnTypeCallback type, const nlohmann::json & jsonResult)
        {
            wrapper.callbackMock(type, jsonResult);
        }
    };

    EXPECT_NO_THROW(dbSync->selectRows(selectQuery.query(), selectCallbackData));
}
