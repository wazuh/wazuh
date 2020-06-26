#include "dbsync_test.h"
#include "dbsync.h"

constexpr auto DATABASE_TEMP {"TEMP.db"};

void DBSyncTest::SetUp() {};

void DBSyncTest::TearDown() {};

TEST_F(DBSyncTest, Initialization) 
{
    const std::string sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    
    const auto handle { dbsync_initialize(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql.c_str()) };
    ASSERT_NE(nullptr, handle);

    EXPECT_NO_THROW(dbsync_teardown());
}

TEST_F(DBSyncTest, InitializationNullptr) 
{
    const auto handle_1 { dbsync_initialize(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, nullptr) };
    ASSERT_EQ(nullptr, handle_1);
    const auto handle_2 { dbsync_initialize(HostType::AGENT, DbEngineType::SQLITE3, nullptr, "valid") };
    ASSERT_EQ(nullptr, handle_2);
}

TEST_F(DBSyncTest, InsertData) 
{
    const std::string sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const std::string insert_sql{ "{\"table\":\"processes\",\"data\":[{\"pid\":4,\"name\":\"System\"}]}"};
    
    const auto handle { dbsync_initialize(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql.c_str()) };
    ASSERT_NE(nullptr, handle);

    cJSON * json_insert { cJSON_Parse(insert_sql.c_str()) };

    EXPECT_EQ(0, dbsync_insert_data(handle, json_insert));

    cJSON_Delete(json_insert);

    EXPECT_NO_THROW(dbsync_teardown());
}

TEST_F(DBSyncTest, InsertDataNullptr) 
{
    const std::string sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
   
    const auto handle { dbsync_initialize(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql.c_str()) };
    ASSERT_NE(nullptr, handle);

    EXPECT_NE(0, dbsync_insert_data(handle, nullptr));

    EXPECT_NO_THROW(dbsync_teardown());
}

TEST_F(DBSyncTest, InsertDataInvalidHandle) 
{
    const std::string sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const std::string insert_sql{ "{\"table\":\"processes\",\"data\":[{\"pid\":4,\"name\":\"System\"}]}"};
    
    const auto handle { dbsync_initialize(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql.c_str()) };
    ASSERT_NE(nullptr, handle);

    cJSON * json_insert { cJSON_Parse(insert_sql.c_str()) };
    EXPECT_NE(0, dbsync_insert_data(reinterpret_cast<void *>(0xffffffff), json_insert));

    cJSON_Delete(json_insert);

    EXPECT_NO_THROW(dbsync_teardown());
}

TEST_F(DBSyncTest, UpdateData) 
{
    const std::string sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const std::string insert_sql{ "{\"table\":\"processes\",\"data\":[{\"pid\":4,\"name\":\"System\"}]}"};
    
    const auto handle { dbsync_initialize(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql.c_str()) };
    ASSERT_NE(nullptr, handle);

    cJSON * json_insert { cJSON_Parse(insert_sql.c_str()) };

    cJSON * json_response { nullptr };
    
    EXPECT_EQ(0, dbsync_update_with_snapshot(handle, json_insert, &json_response));
    EXPECT_NE(nullptr, json_response);
    EXPECT_NO_THROW(dbsync_free_result(&json_response));

    cJSON_Delete(json_insert);

    EXPECT_NO_THROW(dbsync_teardown());
}

TEST_F(DBSyncTest, FreeNullptrResult) 
{
    const std::string sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    
    const auto handle { dbsync_initialize(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql.c_str()) };
    ASSERT_NE(nullptr, handle);

    cJSON* json_response { nullptr };

    EXPECT_NO_THROW(dbsync_free_result(&json_response));

    EXPECT_NO_THROW(dbsync_teardown());
}

TEST_F(DBSyncTest, UpdateDataWithLessFields) 
{
    const std::string sql{ "CREATE TABLE processes(`pid` BIGINT, `name` TEXT,`path` TEXT, PRIMARY KEY (`pid`)) WITHOUT ROWID;"};
    const std::string insert_sql{ "{\"table\":\"processes\",\"data\":[{\"pid\":4,\"name\":\"System\"}]}"};
    
    const auto handle { dbsync_initialize(HostType::AGENT, DbEngineType::SQLITE3, DATABASE_TEMP, sql.c_str()) };
    ASSERT_NE(nullptr, handle);

    cJSON * json_insert { cJSON_Parse(insert_sql.c_str()) };

    cJSON * json_response { nullptr };
    
    EXPECT_EQ(0, dbsync_update_with_snapshot(handle, json_insert, &json_response));
    EXPECT_NE(nullptr, json_response);
    EXPECT_NO_THROW(dbsync_free_result(&json_response));

    cJSON_Delete(json_insert);

    EXPECT_NO_THROW(dbsync_teardown());
}