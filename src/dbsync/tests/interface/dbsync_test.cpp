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

TEST_F(DBSyncTest, selectRowsDataAllNoFilter)
{
    CallbackMock wrapper;

    const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
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

    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
                                                                 {"pid":115,"name":"System2", "tid":101},
                                                                 {"pid":120,"name":"System3", "tid":101},
                                                                 {"pid":125,"name":"System3", "tid":102},
                                                                 {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

    const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":4,"name":"System1", "tid":100})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":115,"name":"System2", "tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":120,"name":"System3", "tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":125,"name":"System3", "tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":300,"name":"System5", "tid":102})"))).Times(1);

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

    const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
                                                                 {"pid":115,"name":"System2", "tid":101},
                                                                 {"pid":120,"name":"System3", "tid":101},
                                                                 {"pid":125,"name":"System3", "tid":102},
                                                                 {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

    const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System2","tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System3","tid":101})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System3","tid":102})"))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System5","tid":102})"))).Times(1);

    callback_data_t callbackData { callback, &wrapper };

    EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
    EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
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

    callback_data_t callbackData { callback, &wrapper };
    const std::unique_ptr<cJSON, smartDeleterJson> jsInitialData{ cJSON_Parse(initialData) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsSingleDeletion{ cJSON_Parse(singleRowToDelete) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsComposedDeletion{ cJSON_Parse(composedRowsToDelete) };
    const std::unique_ptr<cJSON, smartDeleterJson> jsUnexistentDeletion{ cJSON_Parse(unexistentRowToDelete) };

    EXPECT_EQ(0, dbsync_sync_row(handle, jsInitialData.get(), callbackData));  // Expect an insert event
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsSingleDeletion.get()));
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsComposedDeletion.get()));
    EXPECT_EQ(0, dbsync_delete_rows(handle, jsUnexistentDeletion.get()));
}