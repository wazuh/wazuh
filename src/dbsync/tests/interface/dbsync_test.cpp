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

TEST_F(DBSyncTest, InsertData)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};
    
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
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

TEST_F(DBSyncTest, UpdateData)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};
    
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    cJSON * json_response { nullptr };
    
    EXPECT_EQ(0, dbsync_update_with_snapshot(handle, jsInsert.get(), &json_response));
    EXPECT_NE(nullptr, json_response);
    EXPECT_NO_THROW(dbsync_free_result(&json_response));
}

TEST_F(DBSyncTest, FreeNullptrResult)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    cJSON* json_response { nullptr };

    EXPECT_NO_THROW(dbsync_free_result(&json_response));
}

TEST_F(DBSyncTest, UpdateDataWithLessFields)
{
    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT,`path` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};
    
    const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
    ASSERT_NE(nullptr, handle);

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    cJSON * json_response { nullptr };
    
    EXPECT_EQ(0, dbsync_update_with_snapshot(handle, jsInsert.get(), &json_response));
    EXPECT_NE(nullptr, json_response);
    EXPECT_NO_THROW(dbsync_free_result(&json_response));
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

    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };
    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));

    cJSON * json_response { nullptr };
    const std::unique_ptr<cJSON, smartDeleterJson> jsUpdate{ cJSON_Parse(updateSqlStmt) };
    EXPECT_EQ(0, dbsync_update_with_snapshot(handle, jsUpdate.get(), &json_response));
    EXPECT_NE(nullptr, json_response);
    EXPECT_NO_THROW(dbsync_free_result(&json_response));
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

    cJSON * json_response { nullptr };
    const std::unique_ptr<cJSON, smartDeleterJson> jsUpdate{ cJSON_Parse(updateSqlStmt) };
    EXPECT_NE(0, dbsync_update_with_snapshot(handle, jsUpdate.get(), &json_response));
    EXPECT_EQ(nullptr, json_response);

    EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 0));
    EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 10));
    EXPECT_EQ(0, dbsync_update_with_snapshot(handle, jsUpdate.get(), &json_response));
    EXPECT_NE(nullptr, json_response);
    EXPECT_NO_THROW(dbsync_free_result(&json_response));
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

    EXPECT_EQ(0, dbsync_sync_row(handle, jsInsert1.get(), callbackData));  // Expect an insert event
    EXPECT_EQ(0, dbsync_sync_row(handle, jsUpdate1.get(), callbackData));  // Expect a modified event
    EXPECT_EQ(0, dbsync_sync_row(handle, jsUpdate2.get(), callbackData));  // Expect a modified event
    EXPECT_EQ(0, dbsync_sync_row(handle, jsInsert2.get(), callbackData));  // Expect an insert event
    EXPECT_EQ(0, dbsync_sync_row(handle, jsInsert2.get(), callbackData));  // Same as above but EXPECT_CALL Times is 1
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
}
