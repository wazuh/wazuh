/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
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
#include "makeUnique.h"

constexpr auto DATABASE_TEMP {"TEMP.db"};

class CallbackMock
{
public:
    CallbackMock() = default;
    ~CallbackMock() = default;
    MOCK_METHOD(void, callbackMock, (ReturnTypeCallback result_type, const nlohmann::json&), ());
};

struct CJsonDeleter final
{
    void operator()(char* json)
    {
        cJSON_free(json);
    }
};

static void callback(const ReturnTypeCallback type,
                     const cJSON* json,
                     void* ctx)
{
    CallbackMock* wrapper { reinterpret_cast<CallbackMock*>(ctx)};
    const std::unique_ptr<char, CJsonDeleter> spJsonBytes{ cJSON_PrintUnformatted(json) };
    wrapper->callbackMock(type, nlohmann::json::parse(spJsonBytes.get()));
}

struct smartDeleterJson
{
    void operator()(cJSON * data)
    {
        cJSON_Delete(data);
    }
};

struct CharDeleter
{
    void operator()(char* json)
    {
        cJSON_free(json);
    }
};

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
};

TEST_F(DBSyncTest, Initialization)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);
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
    const auto tables { R"({"tables": ["processes"]"})" };
    const std::unique_ptr<DummyContext> dummyCtx { std::make_unique<DummyContext>()};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };

    const std::unique_ptr<cJSON, smartDeleterJson> jsonTables { cJSON_Parse(tables) };

    callback_data_t callbackData { callback, dummyCtx.get() };

    EXPECT_NO_THROW(dummyCtx->txnContext = dbsync_create_txn(handle, jsonTables.get(), 0, 100, callbackData));
    ASSERT_NE(nullptr, dummyCtx);
}

TEST_F(DBSyncTest, createTxnNullptr)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto tables { R"({"tables": ["processes"]"})" };
    const std::unique_ptr<DummyContext> dummyCtx { std::make_unique<DummyContext>()};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };

    const std::unique_ptr<cJSON, smartDeleterJson> jsonTables { cJSON_Parse(tables) };

    callback_data_t callbackData { callback, dummyCtx.get() };
    callback_data_t callbackDataNullptr { callback, nullptr };

    ASSERT_EQ(nullptr, dbsync_create_txn(nullptr, jsonTables.get(), 0, 100, callbackData));
    ASSERT_EQ(nullptr, dbsync_create_txn(handle, nullptr, 0, 100, callbackData)); 
    ASSERT_EQ(nullptr, dbsync_create_txn(handle, jsonTables.get(), 0, 100, callbackData));
    ASSERT_EQ(nullptr, dbsync_create_txn(handle, jsonTables.get(), 0, 0, callbackData));
    ASSERT_EQ(nullptr, dbsync_create_txn(handle, jsonTables.get(), 0, 100, callbackDataNullptr));
}

TEST_F(DBSyncTest, syncTxnRowNullptr)
{
    const auto insertionSqlStmt1{ R"({"table":"processes","data":[{"pid":7,"name":"Guake"}]})"}; // Insert
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert1{ cJSON_Parse(insertionSqlStmt1) };
    ASSERT_NE(0, dbsync_sync_txn_row(nullptr, jsInsert1.get()));
}

TEST_F(DBSyncTest, closeTxnNullptr)
{
    ASSERT_NE(0, dbsync_close_txn(nullptr));
}

TEST_F(DBSyncTest, dbsyncAddTableRelationshipDummy)
{
    ASSERT_EQ(0, dbsync_add_table_relationship(nullptr, nullptr, nullptr, nullptr, nullptr));
}

TEST_F(DBSyncTest, InsertData)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};
    
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
}

TEST_F(DBSyncTest, InsertMoreCompleteData)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `threads` INTEGER, `cpu_usage` DOUBLE, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System", "threads":5, "cpu_usage":17.50}]})"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
}

TEST_F(DBSyncTest, InsertDataWithWrongColumnType)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `threads` INTEGER, `cpu_usage` DOUBLE, `blob` BLOB, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System", "threads":5, "cpu_usage":17.50, "blob":1}]})"};
    
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_NE(0, dbsync_insert_data(handle, jsInsert.get()));
}

TEST_F(DBSyncTest, InsertDataWithInvalidInput)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};

    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto inputNoData{ R"({"table":"processes"})"};
    const auto inputNoTable{ R"({"data":[{"pid":4,"name":"System", "tid":101}]})"};
    const std::unique_ptr<cJSON, smartDeleterJson> jsInputNoData{ cJSON_Parse(inputNoData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInputNoTable{ cJSON_Parse(inputNoTable) };

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

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_NE(0, dbsync_insert_data(reinterpret_cast<void *>(0xffffffff), jsInsert.get()));
}

TEST_F(DBSyncTest, GetDeletedRowsInvalidInput)
{
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_NE(0, dbsync_get_deleted_rows(nullptr, callbackData));
}

TEST_F(DBSyncTest, UpdateData)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};
    
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    cJSON * jsResponse { nullptr };
    
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

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsertWithoutTable{ cJSON_Parse(badSqlStmt) };

    cJSON * jsResponse { nullptr };

    // Failure cases
    EXPECT_NE(0, dbsync_update_with_snapshot(reinterpret_cast<void *>(0xffffffff), jsInsert.get(), nullptr));
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

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

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

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };
    
    callback_data_t callbackData { nullptr, nullptr };

    // Failure cases
    EXPECT_NE(0, dbsync_update_with_snapshot_cb(reinterpret_cast<void *>(0xffffffff), jsInsert.get(), callbackData));
    EXPECT_NE(0, dbsync_update_with_snapshot_cb(handle, nullptr, callbackData));
    EXPECT_NE(0, dbsync_update_with_snapshot_cb(handle, jsInsert.get(), callbackData));
}

TEST(DBSyncTestInit, InitializeWithNullFnct)
{
    dbsync_initialize(nullptr);

    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};
    
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    cJSON * jsResponse { nullptr };
    
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

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    cJSON * jsResponse { nullptr };
    
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

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 1));
    EXPECT_NE(0, dbsync_insert_data(handle, jsInsert.get()));

    EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 0));
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

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };
    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));

    cJSON * jsResponse { nullptr };
    const std::unique_ptr<cJSON, smartDeleterJson> jsUpdate{ cJSON_Parse(updateSqlStmt) };
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

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };
    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));

    cJSON * jsResponse { nullptr };
    const std::unique_ptr<cJSON, smartDeleterJson> jsUpdate{ cJSON_Parse(updateSqlStmt) };
    EXPECT_NE(0, dbsync_update_with_snapshot(handle, jsUpdate.get(), &jsResponse));
    EXPECT_EQ(nullptr, jsResponse);

    EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 0));
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
    EXPECT_NE(0, dbsync_set_table_max_rows(reinterpret_cast<void *>(0xffffffff), "dummy", 100));    
    EXPECT_NE(0, dbsync_set_table_max_rows(handle, "dummy", 100));
}

TEST_F(DBSyncTest, syncRowInsertAndModified)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    CallbackMock wrapper;
    EXPECT_CALL(wrapper, callbackMock(INSERTED,
                nlohmann::json::parse(R"([{"pid":4,"name":"System", "tid":100},
                                          {"pid":5,"name":"System", "tid":101},
                                          {"pid":6,"name":"System", "tid":102}])"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(MODIFIED, nlohmann::json::parse(R"({"pid":4, "tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(MODIFIED, nlohmann::json::parse(R"({"pid":4, "name":"Systemmm", "tid":105})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"([{"pid":7,"name":"Guake"}])"))).Times(1);

    const auto insertionSqlStmt1{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":100},
                                                                  {"pid":5,"name":"System", "tid":101},
                                                                  {"pid":6,"name":"System", "tid":102}]})"}; // Insert
    const auto updateSqlStmt1{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":101}]})"};    // Update
    const auto updateSqlStmt2{ R"({"table":"processes","data":[{"pid":4,"name":"Systemmm", "tid":105}]})"};  // Update
    const auto insertSqlStmt3{ R"({"table":"processes","data":[{"pid":7,"name":"Guake"}]})"};                // Insert
    
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert1{ cJSON_Parse(insertionSqlStmt1) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsUpdate1{ cJSON_Parse(updateSqlStmt1) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsUpdate2{ cJSON_Parse(updateSqlStmt2) };    
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert2{ cJSON_Parse(insertSqlStmt3) }; 
    
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

TEST_F(DBSyncTest, syncRowInvalidData)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const auto inputNoData{ R"({"table":"processes"})"};
    const auto inputNoTable{ R"({"data":[{"pid":4,"name":"System", "tid":101}]})"};

    const std::unique_ptr<cJSON, smartDeleterJson> jsInputNoData{ cJSON_Parse(inputNoData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInputNoTable{ cJSON_Parse(inputNoTable) };

    callback_data_t callbackData { callback, nullptr };

    EXPECT_NE(0, dbsync_sync_row(handle, jsInputNoData.get(), callbackData));
    EXPECT_NE(0, dbsync_sync_row(handle, jsInputNoTable.get(), callbackData));
    EXPECT_NE(0, dbsync_sync_row(reinterpret_cast<void *>(0xffffffff), jsInputNoTable.get(), callbackData));
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

    const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

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

    const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

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

    const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

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

    const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

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

    const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

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

    const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsertPids{ cJSON_Parse(insertPidsSqlStmt) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsertFiles{ cJSON_Parse(insertFilesSqlStmt) };

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

    const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

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

    const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

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

    const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

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

    const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

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

    const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

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

    const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

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

    const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsSelectDataWithoutTable{ cJSON_Parse(selectDataWithoutTable) };    
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System2","tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System3","tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System3","tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System5","tid":102})"))).Times(1);

    callback_data_t callbackData { callback, &wrapper };
    callback_data_t callbackEmpty { nullptr, nullptr };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
    EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
    // Failure cases
    EXPECT_NE(0, dbsync_select_rows(reinterpret_cast<void *>(0xffffffff), jsSelectData.get(), callbackData));
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
    EXPECT_CALL(wrapper, callbackMock(INSERTED,
                nlohmann::json::parse(R"([{"pid":4,"name":"System", "tid":100},
                                          {"pid":5,"name":"System", "tid":101},
                                          {"pid":6,"name":"System", "tid":102},
                                          {"pid":7,"name":"System", "tid":103},
                                          {"pid":8,"name":"System", "tid":104}])"))).Times(1);

    const auto initialData{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":100},
                                                            {"pid":5,"name":"System", "tid":101},
                                                            {"pid":6,"name":"System", "tid":102},
                                                            {"pid":7,"name":"System", "tid":103},
                                                            {"pid":8,"name":"System", "tid":104}]})"};

    const auto singleRowToDelete{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":101}]})"};
    const auto composedRowsToDelete{ R"({"table":"processes","data":[{"pid":5,"name":"Systemmm", "tid":105},
                                                                     {"pid":7,"name":"Systemmm", "tid":105},
                                                                     {"pid":8,"name":"Systemmm", "tid":105}]})"};
    const auto unexistentRowToDelete{ R"({"table":"processes","data":[{"pid":9,"name":"Systemmm", "tid":101}]})"};
    const auto dataWithoutTable{ R"({"data":[{"pid":9,"name":"Systemmm", "tid":101}]})"};

    callback_data_t callbackData { callback, &wrapper };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInitialData{ cJSON_Parse(initialData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsSingleDeletion{ cJSON_Parse(singleRowToDelete) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsComposedDeletion{ cJSON_Parse(composedRowsToDelete) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsUnexistentDeletion{ cJSON_Parse(unexistentRowToDelete) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsWithoutTable{ cJSON_Parse(dataWithoutTable) };

    EXPECT_EQ(0, dbsync_sync_row(handle, jsInitialData.get(), callbackData));  // Expect an insert event
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsSingleDeletion.get()));
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsComposedDeletion.get()));
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsUnexistentDeletion.get()));
    // Failure cases
    EXPECT_NE(0, dbsync_delete_rows(nullptr, jsSingleDeletion.get()));
    EXPECT_NE(0, dbsync_delete_rows(handle, nullptr));
    EXPECT_NE(0, dbsync_delete_rows(handle, jsWithoutTable.get()));
    EXPECT_NE(0, dbsync_delete_rows(reinterpret_cast<void *>(0xffffffff), jsSingleDeletion.get()));
}
