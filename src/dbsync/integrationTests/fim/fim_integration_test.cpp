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

#include <fstream>
#include <iostream>
#include "json.hpp"
#include "dbsync.h"
#include "fim_integration_test.h"
using ::testing::_;

constexpr auto DATABASE_TEMP {"FIM_TEMP.db"};

constexpr auto FIM_DB_SQL
{
    #include "fim_db.sql"
};

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

struct smartDeleterJson
{
    void operator()(cJSON * data)
    {
        cJSON_Delete(data);
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

static void logFunction(const char* msg)
{
    if (msg)
    {
        std::cout << msg << std::endl;
    }
}

DBSyncFimIntegrationTest::DBSyncFimIntegrationTest()
: m_dbHandle{ nullptr }
, m_fimSqlSchema{ FIM_DB_SQL}
{
    dbsync_initialize(&logFunction);
}

void DBSyncFimIntegrationTest::SetUp()
{
    m_dbHandle = dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, m_fimSqlSchema.c_str());
};

void DBSyncFimIntegrationTest::TearDown()
{
    EXPECT_NO_THROW(dbsync_teardown());
    std::remove(DATABASE_TEMP);
};

TEST_F(DBSyncFimIntegrationTest, Initialization)
{
    ASSERT_NE(nullptr, m_dbHandle);
}

TEST_F(DBSyncFimIntegrationTest, FIMDB_STMT_GET_PATH)
{
    const auto expectedResult
    {
        R"({"checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a",
            "dev":2051,
            "entry_type":0,
            "gid":0,
            "group_name":"root",
            "hash_md5":"4b531524aa13c8a54614100b570b3dc7",
            "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
            "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a",
            "inode":18277083,
            "inode_id":1877,
            "last_event":1596489275,
            "mode":0,
            "mtime":1578075431,
            "options":131583,
            "path":"/etc/wgetrc",
            "perm":"rw-r--r--",
            "scanned":0,
            "size":4925,
            "uid":0,
            "user_name":"root"}
            )"
    };
    const auto selectSql
    {
        R"({"table":"entry_path",
           "query":{"column_list":["path, inode_id, mode, last_event, entry_type, scanned, options, checksum, dev, inode, size, perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1, hash_sha256, mtime"],
           "row_filter":"INNER JOIN entry_data ON path ='/etc/wgetrc' AND entry_data.rowid = entry_path.inode_id",
           "distinct_opt":false,
           "order_by_opt":"",
           "count_opt":100}})"
    };
    const std::unique_ptr<cJSON, smartDeleterJson> jsSelect{ cJSON_Parse(selectSql) };
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(expectedResult))).Times(1);
    EXPECT_EQ(0, dbsync_select_rows(m_dbHandle, jsSelect.get(), callbackData));
}

TEST_F(DBSyncFimIntegrationTest, FIMDB_STMT_GET_LAST_PATH)
{
    const auto expectedResult
    {
        R"({"path":"/sbin"})"
    };
    const auto selectSql
    {
        R"({"table":"entry_path",
           "query":{"column_list":["path"],
           "row_filter":"",
           "distinct_opt":false,
           "order_by_opt":"path DESC",
           "count_opt":1}})"
    };
    const std::unique_ptr<cJSON, smartDeleterJson> jsSelect{ cJSON_Parse(selectSql) };
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(expectedResult))).Times(1);
    EXPECT_EQ(0, dbsync_select_rows(m_dbHandle, jsSelect.get(), callbackData));
}

TEST_F(DBSyncFimIntegrationTest, FIMDB_STMT_GET_FIRST_PATH)
{
    const auto expectedResult
    {
        R"({"path":"/bin"})"
    };
    const auto selectSql
    {
        R"({"table":"entry_path",
           "query":{"column_list":["path"],
           "row_filter":"",
           "distinct_opt":false,
           "order_by_opt":"path ASC",
           "count_opt":1}})"
    };
    const std::unique_ptr<cJSON, smartDeleterJson> jsSelect{ cJSON_Parse(selectSql) };
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(expectedResult))).Times(1);
    EXPECT_EQ(0, dbsync_select_rows(m_dbHandle, jsSelect.get(), callbackData));
}

TEST_F(DBSyncFimIntegrationTest, FIMDB_STMT_GET_ALL_ENTRIES)
{
    const auto selectSql
    {
        R"({"table":"entry_data",
           "query":{"column_list":["path,
                                    inode_id,
                                    mode,
                                    last_event,
                                    entry_type,
                                    scanned,
                                    options,
                                    checksum,
                                    dev,
                                    inode,
                                    size,
                                    perm,
                                    attributes,
                                    uid,
                                    gid,
                                    user_name,
                                    group_name,
                                    hash_md5,
                                    hash_sha1,
                                    hash_sha256,
                                    mtime"],
           "row_filter":"INNER JOIN entry_path ON inode_id = entry_data.rowid",
           "distinct_opt":false,
           "order_by_opt":"path ASC"}})"
    };
    const std::unique_ptr<cJSON, smartDeleterJson> jsSelect{ cJSON_Parse(selectSql) };
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_CALL(wrapper, callbackMock(SELECTED, _)).Times(1904);
    EXPECT_EQ(0, dbsync_select_rows(m_dbHandle, jsSelect.get(), callbackData));
}

TEST_F(DBSyncFimIntegrationTest, FIMDB_STMT_GET_PATH_COUNT)
{
    const auto expectedResult
    {
        "{\"count(inode_id)\":1}"
    };
    const auto selectSql
    {
        R"({"table":"entry_path",
           "query":{"column_list":["count(inode_id) "],
           "row_filter":"WHERE inode_id = (select inode_id from entry_path where path = '/etc/gssproxy/24-nfs-server.conf') ",
           "distinct_opt":false,
           "order_by_opt":""}})"
    };
    const std::unique_ptr<cJSON, smartDeleterJson> jsSelect{ cJSON_Parse(selectSql) };
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(expectedResult))).Times(1);
    EXPECT_EQ(0, dbsync_select_rows(m_dbHandle, jsSelect.get(), callbackData));
}

TEST_F(DBSyncFimIntegrationTest, FIMDB_STMT_GET_DATA_ROW)
{
    const auto expectedResult
    {
        R"({"rowid":1276})"
    };
    const auto selectSql
    {
        R"({"table":"entry_data",
           "query":{"column_list":["rowid"],
           "row_filter":"WHERE inode = 51436218 AND dev = 2051",
           "distinct_opt":false,
           "order_by_opt":""}})"
    };
    const std::unique_ptr<cJSON, smartDeleterJson> jsSelect{ cJSON_Parse(selectSql) };
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(expectedResult))).Times(1);
    EXPECT_EQ(0, dbsync_select_rows(m_dbHandle, jsSelect.get(), callbackData));
}

TEST_F(DBSyncFimIntegrationTest, FIMDB_STMT_GET_COUNT_RANGE)
{
    const auto expectedResult
    {
        "{\"count(*)\":13}"
    };
    const auto selectSql
    {
        R"({"table":"entry_path",
           "query":{"column_list":["count(*) "],
           "row_filter":"INNER JOIN entry_data ON entry_data.rowid = entry_path.inode_id WHERE path BETWEEN '/etc/yum.conf' and '/etc/yum.repos.d/CentOS-centosplus.repo' ORDER BY path",
           "distinct_opt":false,
           "order_by_opt":""}})"
    };
    const std::unique_ptr<cJSON, smartDeleterJson> jsSelect{ cJSON_Parse(selectSql) };
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(expectedResult))).Times(1);
    EXPECT_EQ(0, dbsync_select_rows(m_dbHandle, jsSelect.get(), callbackData));
}


TEST_F(DBSyncFimIntegrationTest, FIMDB_STMT_GET_PATH_RANGE)
{
    const auto expectedResult1
    {
        R"({"checksum":"e100589b9f75b293ea2fc718fb39ecedddf1f381",
            "dev":2051,"entry_type":0,"gid":0,"group_name":"root",
            "hash_md5":"d41d8cd98f00b204e9800998ecf8427e",
            "hash_sha1":"da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "hash_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "inode":18277013,"inode_id":1871,"last_event":1596489275,"mode":0,
            "mtime":1587758264,"options":131583,"path":"/etc/yum.conf",
            "perm":"rwxrwxrwx","scanned":0,"size":12,"uid":0,"user_name":"root"})"
    };
    const auto expectedResult2
    {
       R"({"checksum":"eeb46d0e85f635cd8595afc3447b21686c8fedb3",
           "dev":2051,"entry_type":0,"gid":0,"group_name":"root",
           "hash_md5":"349e00330684b1b1443904956aa0b241",
           "hash_sha1":"f945fe1ad48aa9c367d2a131a4f7a659db6c1967",
           "hash_sha256":"0e3a78178a75c13d71cfc2fafb3072a009733414a90802b2b67ccc7279e050cd",
           "inode":2078,"inode_id":604,"last_event":1596489275,"mode":0,
           "mtime":1591146169,"options":131583,"path":"/etc/yum.repos.d/CentOS-AppStream.repo",
           "perm":"rw-r--r--","scanned":1,"size":731,"uid":0,"user_name":"root"})"
    };
    const auto expectedResult3
    {
       R"({"checksum":"e24f1dfcba64d3dea78c6840893c77539f44638f",
           "dev":2051,"entry_type":0,"gid":0,"group_name":"root",
           "hash_md5":"7449031222431c7cbac19313af55aca4",
           "hash_sha1":"640746d2388b9500b300e2a45878e81e5473aa83",
           "hash_sha256":"ee7da6f7be6623cc6da7613777def9c9801073d725f686eb4e3812584e3e417d",
           "inode":2079,"inode_id":605,"last_event":1596489275,"mode":0,
           "mtime":1591146169,"options":131583,"path":"/etc/yum.repos.d/CentOS-Base.repo",
           "perm":"rw-r--r--","scanned":1,"size":712,"uid":0,"user_name":"root"})"
    };
    const auto selectSql
    {
        R"({"table":"entry_path",
           "query":{"column_list":["path,
                                    inode_id,
                                    mode,
                                    last_event,
                                    entry_type,
                                    scanned,
                                    options,
                                    checksum,
                                    dev,
                                    inode,
                                    size,
                                    perm,
                                    attributes,
                                    uid,
                                    gid,
                                    user_name,
                                    group_name,
                                    hash_md5,
                                    hash_sha1,
                                    hash_sha256,
                                    mtime"],
           "row_filter":"INNER JOIN entry_data ON entry_data.rowid = entry_path.inode_id WHERE path BETWEEN '/etc/yum.conf' and '/etc/yum.repos.d/CentOS-Base.repo' ORDER BY path",
           "distinct_opt":false,
           "order_by_opt":""}})"
    };
    const std::unique_ptr<cJSON, smartDeleterJson> jsSelect{ cJSON_Parse(selectSql) };
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(expectedResult1))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(expectedResult2))).Times(1);
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(expectedResult3))).Times(1);
    EXPECT_EQ(0, dbsync_select_rows(m_dbHandle, jsSelect.get(), callbackData));
}

TEST_F(DBSyncFimIntegrationTest, FIMDB_STMT_GET_PATHS_INODE)
{
    const auto expectedResult
    {
        R"({"path":"/etc/yum.repos.d/CentOS-Base.repo"})"
    };
    const auto selectSql
    {
        R"({"table":"entry_path",
           "query":{"column_list":["path"],
           "row_filter":"INNER JOIN entry_data ON entry_data.rowid=entry_path.inode_id WHERE entry_data.inode=2079 AND entry_data.dev=2051",
           "distinct_opt":false,
           "order_by_opt":""}})"
    };
    const std::unique_ptr<cJSON, smartDeleterJson> jsSelect{ cJSON_Parse(selectSql) };
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(expectedResult))).Times(1);
    EXPECT_EQ(0, dbsync_select_rows(m_dbHandle, jsSelect.get(), callbackData));
}

TEST_F(DBSyncFimIntegrationTest, FIMDB_STMT_GET_PATHS_INODE_COUNT)
{
    const auto expectedResult
    {
        "{\"count(*)\":1}"
    };
    const auto selectSql
    {
        R"({"table":"entry_path",
           "query":{"column_list":["count(*) "],
           "row_filter":"INNER JOIN entry_data ON entry_data.rowid=entry_path.inode_id WHERE entry_data.inode=2078 AND entry_data.dev=2051",
           "distinct_opt":false,
           "order_by_opt":""}})"
    };
    const std::unique_ptr<cJSON, smartDeleterJson> jsSelect{ cJSON_Parse(selectSql) };
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(expectedResult))).Times(1);
    EXPECT_EQ(0, dbsync_select_rows(m_dbHandle, jsSelect.get(), callbackData));
}

TEST_F(DBSyncFimIntegrationTest, FIMDB_STMT_GET_INODE_ID)
{
    const auto expectedResult
    {
        R"({"inode_id":605})"
    };
    const auto selectSql
    {
        R"({"table":"entry_path",
           "query":{"column_list":["inode_id"],
           "row_filter":"WHERE path = '/etc/yum.repos.d/CentOS-Base.repo'",
           "distinct_opt":false,
           "order_by_opt":""}})"
    };
    const std::unique_ptr<cJSON, smartDeleterJson> jsSelect{ cJSON_Parse(selectSql) };
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(expectedResult))).Times(1);
    EXPECT_EQ(0, dbsync_select_rows(m_dbHandle, jsSelect.get(), callbackData));
}

TEST_F(DBSyncFimIntegrationTest, FIMDB_STMT_GET_COUNT_PATH)
{
    const auto expectedResult
    {
        "{\"count(*)\":1906}"
    };
    const auto selectSql
    {
        R"({"table":"entry_path",
           "query":{"column_list":["count(*) "],
           "row_filter":"",
           "distinct_opt":false,
           "order_by_opt":""}})"
    };
    const std::unique_ptr<cJSON, smartDeleterJson> jsSelect{ cJSON_Parse(selectSql) };
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(expectedResult))).Times(1);
    EXPECT_EQ(0, dbsync_select_rows(m_dbHandle, jsSelect.get(), callbackData));
}

TEST_F(DBSyncFimIntegrationTest, FIMDB_STMT_GET_COUNT_DATA)
{
    const auto expectedResult
    {
        "{\"count(*)\":1906}"
    };
    const auto selectSql
    {
        R"({"table":"entry_data",
           "query":{"column_list":["count(*) "],
           "row_filter":"",
           "distinct_opt":false,
           "order_by_opt":""}})"
    };
    const std::unique_ptr<cJSON, smartDeleterJson> jsSelect{ cJSON_Parse(selectSql) };
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(expectedResult))).Times(1);
    EXPECT_EQ(0, dbsync_select_rows(m_dbHandle, jsSelect.get(), callbackData));
}

TEST_F(DBSyncFimIntegrationTest, FIMDB_STMT_GET_INODE)
{
    const auto expectedResult
    {
        R"({"inode":2079})"
    };
    const auto selectSql
    {
        R"({"table":"entry_data",
           "query":{"column_list":["inode"],
           "row_filter":"where rowid=(SELECT inode_id FROM entry_path WHERE path ='/etc/yum.repos.d/CentOS-Base.repo' ) ",
           "distinct_opt":false,
           "order_by_opt":""}})"
    };
    const auto selectJson{nlohmann::json::parse(selectSql)};
    const std::unique_ptr<cJSON, smartDeleterJson> jsSelect{ cJSON_Parse(selectSql) };
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    ASSERT_NE(nullptr, jsSelect.get());
    EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(expectedResult))).Times(1);
    EXPECT_EQ(0, dbsync_select_rows(m_dbHandle, jsSelect.get(), callbackData));
}


// TEST_F(DBSyncFimIntegrationTest, InsertData)
// {
//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};
    
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
// }

// TEST_F(DBSyncFimIntegrationTest, InsertDataNullptr)
// {
//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
   
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     EXPECT_NE(0, dbsync_insert_data(handle, nullptr));
// }

// TEST_F(DBSyncFimIntegrationTest, InsertDataInvalidHandle)
// {
//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};
    
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     EXPECT_NE(0, dbsync_insert_data(reinterpret_cast<void *>(0xffffffff), jsInsert.get()));
// }

// TEST_F(DBSyncFimIntegrationTest, UpdateData)
// {
//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};
    
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     cJSON * json_response { nullptr };
    
//     EXPECT_EQ(0, dbsync_update_with_snapshot(handle, jsInsert.get(), &json_response));
//     EXPECT_NE(nullptr, json_response);
//     EXPECT_NO_THROW(dbsync_free_result(&json_response));
// }

// TEST_F(DBSyncFimIntegrationTest, FreeNullptrResult)
// {
//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     cJSON* json_response { nullptr };

//     EXPECT_NO_THROW(dbsync_free_result(&json_response));
// }

// TEST_F(DBSyncFimIntegrationTest, UpdateDataWithLessFields)
// {
//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT,`path` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}]})"};
    
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     cJSON * json_response { nullptr };
    
//     EXPECT_EQ(0, dbsync_update_with_snapshot(handle, jsInsert.get(), &json_response));
//     EXPECT_NE(nullptr, json_response);
//     EXPECT_NO_THROW(dbsync_free_result(&json_response));
// }

// TEST_F(DBSyncFimIntegrationTest, SetMaxRows)
// {
//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);
//     EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 100));
//     EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 0));
// }

// TEST_F(DBSyncFimIntegrationTest, TryToInsertMoreThanMaxRows)
// {
//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}, {"pid":3,"name":"cmd"}]})"};

//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 1));
//     EXPECT_NE(0, dbsync_insert_data(handle, jsInsert.get()));

//     EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 0));
//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
// }

// TEST_F(DBSyncFimIntegrationTest, TryToUpdateMaxRowsElements)
// {
//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}, {"pid":3,"name":"cmd"}]})"};
//     const auto updateSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"Cmd"}, {"pid":3,"name":"System"}]})"};

//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 2));

//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };
//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));

//     cJSON * json_response { nullptr };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsUpdate{ cJSON_Parse(updateSqlStmt) };
//     EXPECT_EQ(0, dbsync_update_with_snapshot(handle, jsUpdate.get(), &json_response));
//     EXPECT_NE(nullptr, json_response);
//     EXPECT_NO_THROW(dbsync_free_result(&json_response));
// }

// TEST_F(DBSyncFimIntegrationTest, TryToUpdateMoreThanMaxRowsElements)
// {
//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System"}, {"pid":3,"name":"cmd"}]})"};
//     const auto updateSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"Cmd"}, {"pid":3,"name":"System"}, {"pid":5,"name":"powershell"}]})"};

//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 2));

//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };
//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));

//     cJSON * json_response { nullptr };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsUpdate{ cJSON_Parse(updateSqlStmt) };
//     EXPECT_NE(0, dbsync_update_with_snapshot(handle, jsUpdate.get(), &json_response));
//     EXPECT_EQ(nullptr, json_response);

//     EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 0));
//     EXPECT_EQ(0, dbsync_set_table_max_rows(handle, "processes", 10));
//     EXPECT_EQ(0, dbsync_update_with_snapshot(handle, jsUpdate.get(), &json_response));
//     EXPECT_NE(nullptr, json_response);
//     EXPECT_NO_THROW(dbsync_free_result(&json_response));
// }

// TEST_F(DBSyncFimIntegrationTest, syncRowInsertAndModified)
// {
//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     CallbackMock wrapper;
//     EXPECT_CALL(wrapper, callbackMock(INSERTED,
//                 nlohmann::json::parse(R"([{"pid":4,"name":"System", "tid":100},
//                                           {"pid":5,"name":"System", "tid":101},
//                                           {"pid":6,"name":"System", "tid":102}])"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(MODIFIED, nlohmann::json::parse(R"({"pid":4, "tid":101})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(MODIFIED, nlohmann::json::parse(R"({"pid":4, "name":"Systemmm", "tid":105})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(INSERTED, nlohmann::json::parse(R"([{"pid":7,"name":"Guake"}])"))).Times(1);

//     const auto insertionSqlStmt1{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":100},
//                                                                   {"pid":5,"name":"System", "tid":101},
//                                                                   {"pid":6,"name":"System", "tid":102}]})"}; // Insert
//     const auto updateSqlStmt1{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":101}]})"};    // Update
//     const auto updateSqlStmt2{ R"({"table":"processes","data":[{"pid":4,"name":"Systemmm", "tid":105}]})"};  // Update
//     const auto insertSqlStmt3{ R"({"table":"processes","data":[{"pid":7,"name":"Guake"}]})"};                // Insert    
    
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert1{ cJSON_Parse(insertionSqlStmt1) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsUpdate1{ cJSON_Parse(updateSqlStmt1) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsUpdate2{ cJSON_Parse(updateSqlStmt2) };    
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert2{ cJSON_Parse(insertSqlStmt3) }; 
    
//     callback_data_t callbackData { callback, &wrapper };

//     EXPECT_EQ(0, dbsync_sync_row(handle, jsInsert1.get(), callbackData));  // Expect an insert event
//     EXPECT_EQ(0, dbsync_sync_row(handle, jsUpdate1.get(), callbackData));  // Expect a modified event
//     EXPECT_EQ(0, dbsync_sync_row(handle, jsUpdate2.get(), callbackData));  // Expect a modified event
//     EXPECT_EQ(0, dbsync_sync_row(handle, jsInsert2.get(), callbackData));  // Expect an insert event
//     EXPECT_EQ(0, dbsync_sync_row(handle, jsInsert2.get(), callbackData));  // Same as above but EXPECT_CALL Times is 1
// }

// TEST_F(DBSyncFimIntegrationTest, syncRowInvalidData)
// {
//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const auto inputNoData{ R"({"table":"processes"})"};
//     const auto inputNoTable{ R"({"data":[{"pid":4,"name":"System", "tid":101}]})"};

//     const std::unique_ptr<cJSON, smartDeleterJson> jsInputNoData{ cJSON_Parse(inputNoData) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInputNoTable{ cJSON_Parse(inputNoTable) };

//     callback_data_t callbackData { callback, nullptr };

//     EXPECT_NE(0, dbsync_sync_row(handle, jsInputNoData.get(), callbackData));
//     EXPECT_NE(0, dbsync_sync_row(handle, jsInputNoTable.get(), callbackData));
// }

// TEST_F(DBSyncFimIntegrationTest, selectRowsDataAllNoFilter)
// {

//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const auto selectData
//     {
//         R"({"table":"processes",
//            "query":{"column_list":["*"],
//            "row_filter":"",
//            "distinct_opt":false,
//            "order_by_opt":"tid",
//            "count_opt":100}})"
//     };

//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
//                                                                  {"pid":115,"name":"System2", "tid":101},
//                                                                  {"pid":120,"name":"System3", "tid":101},
//                                                                  {"pid":125,"name":"System3", "tid":102},
//                                                                  {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

//     const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":4,"name":"System1", "tid":100})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":115,"name":"System2", "tid":101})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":120,"name":"System3", "tid":101})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":125,"name":"System3", "tid":102})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":300,"name":"System5", "tid":102})"))).Times(1);

//     CallbackMock wrapper;
//     callback_data_t callbackData { callback, &wrapper };

//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
//     EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
// }

// TEST_F(DBSyncFimIntegrationTest, selectRowsDataAllFilterPid)
// {
//     CallbackMock wrapper;

//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const auto selectData
//     {
//         R"({"table":"processes",
//            "query":{"column_list":["*"],
//            "row_filter":"WHERE pid>120",
//            "distinct_opt":false,
//            "order_by_opt":"tid",
//            "count_opt":100}})"
//     };

//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
//                                                                  {"pid":115,"name":"System2", "tid":101},
//                                                                  {"pid":120,"name":"System3", "tid":101},
//                                                                  {"pid":125,"name":"System3", "tid":102},
//                                                                  {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

//     const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":125,"name":"System3", "tid":102})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":300,"name":"System5", "tid":102})"))).Times(1);

//     callback_data_t callbackData { callback, &wrapper };

//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
//     EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
// }

// TEST_F(DBSyncFimIntegrationTest, selectRowsDataAllFilterPidOr)
// {
//     CallbackMock wrapper;

//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const auto selectData
//     {
//         R"({"table":"processes",
//            "query":{"column_list":["*"],
//            "row_filter":"WHERE pid=120 OR pid=300",
//            "distinct_opt":false,
//            "order_by_opt":"tid",
//            "count_opt":100}})"
//     };

//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
//                                                                  {"pid":115,"name":"System2", "tid":101},
//                                                                  {"pid":120,"name":"System3", "tid":101},
//                                                                  {"pid":125,"name":"System3", "tid":102},
//                                                                  {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

//     const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":120,"name":"System3", "tid":101})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":300,"name":"System5", "tid":102})"))).Times(1);

//     callback_data_t callbackData { callback, &wrapper };

//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
//     EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
// }

// TEST_F(DBSyncFimIntegrationTest, selectRowsDataAllFilterPidBetween)
// {
//     CallbackMock wrapper;

//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const auto selectData
//     {
//         R"({"table":"processes",
//            "query":{"column_list":["*"],
//            "row_filter":"WHERE pid BETWEEN 120 AND 300",
//            "distinct_opt":false,
//            "order_by_opt":"tid",
//            "count_opt":100}})"
//     };

//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
//                                                                  {"pid":115,"name":"System2", "tid":101},
//                                                                  {"pid":120,"name":"System3", "tid":101},
//                                                                  {"pid":125,"name":"System3", "tid":102},
//                                                                  {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

//     const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":120,"name":"System3", "tid":101})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":125,"name":"System3", "tid":102})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":300,"name":"System5", "tid":102})"))).Times(1);

//     callback_data_t callbackData { callback, &wrapper };

//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
//     EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
// }

// TEST_F(DBSyncFimIntegrationTest, selectCount)
// {
//     CallbackMock wrapper;

//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const auto selectData
//     {
//         R"({"table":"processes",
//            "query":{"column_list":["count(*) AS count"],
//            "row_filter":"",
//            "distinct_opt":false,
//            "order_by_opt":"",
//            "count_opt":100}})"
//     };

//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
//                                                                  {"pid":115,"name":"System2", "tid":101},
//                                                                  {"pid":120,"name":"System3", "tid":101},
//                                                                  {"pid":125,"name":"System3", "tid":102},
//                                                                  {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

//     const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"count":5})"))).Times(1);

//     callback_data_t callbackData { callback, &wrapper };

//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
//     EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
// }

// TEST_F(DBSyncFimIntegrationTest, selectInnerJoin)
// {
//     CallbackMock wrapper;

//     const auto sql
//     {
//         "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `fid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"
//         "CREATE TABLE files(`inode` BIGINT, `path` TEXT, `size` BIGINT, PRIMARY KEY (`inode`)) WITHOUT ROWID;"
//     };
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const auto selectData
//     {
//         R"({"table":"processes",
//            "query":{"column_list":["pid,name,fid,path,size"],
//            "row_filter":"INNER JOIN files ON processes.fid=files.inode WHERE pid BETWEEN 100 AND 200",
//            "distinct_opt":false,
//            "order_by_opt":"",
//            "count_opt":100}})"
//     };

//     const auto insertPidsSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "fid":100},
//                                                                   {"pid":115,"name":"System2", "fid":101},
//                                                                   {"pid":225,"name":"System3", "fid":102}]})"}; // Insert pids
//     const auto insertFilesSqlStmt{ R"({"table":"files","data":[{"inode":100,"path":"/usr/bin/System1", "size":123456},
//                                                                {"inode":101,"path":"/usr/bin/System2", "size":654321},
//                                                                {"inode":102,"path":"/usr/bin/System3", "size":321654}]})"}; // Insert files

//     const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsertPids{ cJSON_Parse(insertPidsSqlStmt) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsertFiles{ cJSON_Parse(insertFilesSqlStmt) };

//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":115,"name":"System2", "fid":101, "path":"/usr/bin/System2", "size":654321})"))).Times(1);

//     callback_data_t callbackData { callback, &wrapper };

//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsertPids.get()));
//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsertFiles.get()));
//     EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
// }

// TEST_F(DBSyncFimIntegrationTest, selectRowsDataAllFilterPid1)
// {
//     CallbackMock wrapper;

//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const auto selectData
//     {
//         R"({"table":"processes",
//            "query":{"column_list":["*"],
//            "row_filter":"WHERE (pid>120 AND pid<200) ",
//            "distinct_opt":false,
//            "order_by_opt":"tid",
//            "count_opt":100}})"
//     };

//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
//                                                                  {"pid":115,"name":"System2", "tid":101},
//                                                                  {"pid":120,"name":"System3", "tid":101},
//                                                                  {"pid":125,"name":"System3", "tid":102},
//                                                                  {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

//     const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":125,"name":"System3", "tid":102})"))).Times(1);

//     callback_data_t callbackData { callback, &wrapper };

//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
//     EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
// }

// TEST_F(DBSyncFimIntegrationTest, selectRowsDataAllFilterPidTid)
// {
//     CallbackMock wrapper;

//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const auto selectData
//     {
//         R"({"table":"processes",
//            "query":{"column_list":["*"],
//            "row_filter":"WHERE (pid>120 AND tid!=101) ",
//            "distinct_opt":false,
//            "order_by_opt":"tid",
//            "count_opt":100}})"
//     };

//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
//                                                                  {"pid":115,"name":"System2", "tid":101},
//                                                                  {"pid":120,"name":"System3", "tid":101},
//                                                                  {"pid":125,"name":"System3", "tid":102},
//                                                                  {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

//     const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":125,"name":"System3", "tid":102})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"pid":300,"name":"System5", "tid":102})"))).Times(1);

//     callback_data_t callbackData { callback, &wrapper };

//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
//     EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
// }

// TEST_F(DBSyncFimIntegrationTest, selectRowsDataNameOnlyFilterPidTid)
// {
//     CallbackMock wrapper;

//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const auto selectData
//     {
//         R"({"table":"processes",
//            "query":{"column_list":["name"],
//            "row_filter":"WHERE (pid>120 AND tid!=101) ",
//            "distinct_opt":false,
//            "order_by_opt":"tid",
//            "count_opt":100}})"
//     };

//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
//                                                                  {"pid":115,"name":"System2", "tid":101},
//                                                                  {"pid":120,"name":"System3", "tid":101},
//                                                                  {"pid":125,"name":"System3", "tid":102},
//                                                                  {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

//     const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System3"})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System5"})"))).Times(1);

//     callback_data_t callbackData { callback, &wrapper };

//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
//     EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
// }


// TEST_F(DBSyncFimIntegrationTest, selectRowsDataNameOnly)
// {
//     CallbackMock wrapper;

//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const auto selectData
//     {
//         R"({"table":"processes",
//            "query":{"column_list":["name"],
//            "row_filter":"",
//            "distinct_opt":false,
//            "order_by_opt":"tid",
//            "count_opt":100}})"
//     };

//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
//                                                                  {"pid":115,"name":"System2", "tid":101},
//                                                                  {"pid":120,"name":"System3", "tid":101},
//                                                                  {"pid":125,"name":"System3", "tid":102},
//                                                                  {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

//     const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System1"})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System2"})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System3"})"))).Times(2);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System5"})"))).Times(1);

//     callback_data_t callbackData { callback, &wrapper };

//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
//     EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
// }

// TEST_F(DBSyncFimIntegrationTest, selectRowsDataNameOnlyFilterPid)
// {
//     CallbackMock wrapper;

//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const auto selectData
//     {
//         R"({"table":"processes",
//            "query":{"column_list":["name"],
//            "row_filter":"WHERE pid<120",
//            "distinct_opt":false,
//            "order_by_opt":"tid",
//            "count_opt":100}})"
//     };

//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
//                                                                  {"pid":115,"name":"System2", "tid":101},
//                                                                  {"pid":120,"name":"System3", "tid":101},
//                                                                  {"pid":125,"name":"System3", "tid":102},
//                                                                  {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

//     const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System1"})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System2"})"))).Times(1);

//     callback_data_t callbackData { callback, &wrapper };

//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
//     EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
// }

// TEST_F(DBSyncFimIntegrationTest, selectRowsDataNameTidOnly)
// {
//     CallbackMock wrapper;

//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const auto selectData
//     {
//         R"({"table":"processes",
//            "query":{"column_list":["name","tid"],
//            "row_filter":"",
//            "distinct_opt":false,
//            "order_by_opt":"tid",
//            "count_opt":100}})"
//     };

//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
//                                                                  {"pid":115,"name":"System2", "tid":101},
//                                                                  {"pid":120,"name":"System3", "tid":101},
//                                                                  {"pid":125,"name":"System3", "tid":102},
//                                                                  {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

//     const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System1","tid":100})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System2","tid":101})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System3","tid":101})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System3","tid":102})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System5","tid":102})"))).Times(1);

//     callback_data_t callbackData { callback, &wrapper };

//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
//     EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
// }

// TEST_F(DBSyncFimIntegrationTest, selectRowsDataNameTidOnlyPid)
// {
//     CallbackMock wrapper;

//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     const auto selectData
//     {
//         R"({"table":"processes",
//            "query":{"column_list":["name","tid"],
//            "row_filter":"WHERE pid>100",
//            "distinct_opt":false,
//            "order_by_opt":"tid",
//            "count_opt":100}})"
//     };

//     const auto insertionSqlStmt{ R"({"table":"processes","data":[{"pid":4,"name":"System1", "tid":100},
//                                                                  {"pid":115,"name":"System2", "tid":101},
//                                                                  {"pid":120,"name":"System3", "tid":101},
//                                                                  {"pid":125,"name":"System3", "tid":102},
//                                                                  {"pid":300,"name":"System5", "tid":102}]})"}; // Insert

//     const std::unique_ptr<cJSON, smartDeleterJson> jsSelectData{ cJSON_Parse(selectData) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInsert{ cJSON_Parse(insertionSqlStmt) };

//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System2","tid":101})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System3","tid":101})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System3","tid":102})"))).Times(1);
//     EXPECT_CALL(wrapper, callbackMock(SELECTED, nlohmann::json::parse(R"({"name":"System5","tid":102})"))).Times(1);

//     callback_data_t callbackData { callback, &wrapper };

//     EXPECT_EQ(0, dbsync_insert_data(handle, jsInsert.get()));
//     EXPECT_EQ(0, dbsync_select_rows(handle, jsSelectData.get(), callbackData));
// }

// TEST_F(DBSyncFimIntegrationTest, deleteSingleAndComposedData)
// {
//     const auto sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, `tid` BIGINT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
//     const auto handle { dbsync_create(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql) };
//     ASSERT_NE(nullptr, handle);

//     CallbackMock wrapper;
//     EXPECT_CALL(wrapper, callbackMock(INSERTED,
//                 nlohmann::json::parse(R"([{"pid":4,"name":"System", "tid":100},
//                                           {"pid":5,"name":"System", "tid":101},
//                                           {"pid":6,"name":"System", "tid":102},
//                                           {"pid":7,"name":"System", "tid":103},
//                                           {"pid":8,"name":"System", "tid":104}])"))).Times(1);

//     const auto initialData{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":100},
//                                                             {"pid":5,"name":"System", "tid":101},
//                                                             {"pid":6,"name":"System", "tid":102},
//                                                             {"pid":7,"name":"System", "tid":103},
//                                                             {"pid":8,"name":"System", "tid":104}]})"};

//     const auto singleRowToDelete{ R"({"table":"processes","data":[{"pid":4,"name":"System", "tid":101}]})"};
//     const auto composedRowsToDelete{ R"({"table":"processes","data":[{"pid":5,"name":"Systemmm", "tid":105},
//                                                                      {"pid":7,"name":"Systemmm", "tid":105},
//                                                                      {"pid":8,"name":"Systemmm", "tid":105}]})"};
//     const auto unexistentRowToDelete{ R"({"table":"processes","data":[{"pid":9,"name":"Systemmm", "tid":101}]})"};

//     callback_data_t callbackData { callback, &wrapper };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsInitialData{ cJSON_Parse(initialData) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsSingleDeletion{ cJSON_Parse(singleRowToDelete) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsComposedDeletion{ cJSON_Parse(composedRowsToDelete) };
//     const std::unique_ptr<cJSON, smartDeleterJson> jsUnexistentDeletion{ cJSON_Parse(unexistentRowToDelete) };

//     EXPECT_EQ(0, dbsync_sync_row(handle, jsInitialData.get(), callbackData));  // Expect an insert event
//     EXPECT_EQ(0, dbsync_delete_rows(handle, jsSingleDeletion.get()));
//     EXPECT_EQ(0, dbsync_delete_rows(handle, jsComposedDeletion.get()));
//     EXPECT_EQ(0, dbsync_delete_rows(handle, jsUnexistentDeletion.get()));
// }