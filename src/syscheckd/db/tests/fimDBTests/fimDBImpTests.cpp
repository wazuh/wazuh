#ifndef _FIMDB_CPP_UNIT_TEST
#define _FIMDB_CPP_UNIT_TEST

#include "fimDBImpTests.hpp"
#include <thread>

constexpr auto MOCK_DB_PATH {"temp_fimdb_ut.db"};
MockLoggingCall* mockLog;
MockSyncMsg* mockSync;

void mockLoggingFunction(const modules_log_level_t logLevel, const char* tag)
{
    mockLog->loggingFunction(logLevel, tag);
}

void mockSyncMessage(const char* log, const char* tag)
{
    mockSync->syncMsg(log, tag);
}
class FimDBFixture : public ::testing::Test
{
    protected:
        MockDBSyncHandler* mockDBSync;
        MockRSyncHandler* mockRSync;
        MockFIMDB fimDBMock;
        unsigned int mockIntervalSync;
        unsigned int mockMaxRowsFile;
        unsigned int mockMaxRowsReg;

        void SetUp() override
        {
            constexpr auto MOCK_SQL_STATEMENT
            {
                R"(CREATE TABLE mock_db (
                mock_text TEXT,
                PRIMARY KEY (mock_text))
                )"
            };

            mockIntervalSync = 1000;
            mockMaxRowsFile = 1000;
            mockMaxRowsReg = 1000;

            std::unique_ptr<DBSync> dbsyncHandler = std::make_unique<MockDBSyncHandler>(HostType::AGENT, DbEngineType::SQLITE3,
                                                                                        MOCK_DB_PATH, MOCK_SQL_STATEMENT);
            std::unique_ptr<RemoteSync> rsyncHandler = std::make_unique<MockRSyncHandler>();
            mockDBSync = (MockDBSyncHandler*) dbsyncHandler.get();
            mockRSync = (MockRSyncHandler*) rsyncHandler.get();
            mockLog = new MockLoggingCall();
            mockSync = new MockSyncMsg();
            EXPECT_CALL((*mockDBSync), setTableMaxRow("file_entry", mockMaxRowsFile));

#ifdef WIN32
            EXPECT_CALL((*mockDBSync), setTableMaxRow("registry_key", mockMaxRowsReg));
            EXPECT_CALL((*mockDBSync), setTableMaxRow("registry_data", mockMaxRowsReg));

            fimDBMock.init(mockIntervalSync, mockMaxRowsFile, mockMaxRowsReg,
                           mockSyncMessage,
                           mockLoggingFunction,
                           std::move(dbsyncHandler),
                           std::move(rsyncHandler));
#else

            fimDBMock.init(mockIntervalSync, mockMaxRowsFile,
                           mockSyncMessage,
                           mockLoggingFunction,
                           std::move(dbsyncHandler),
                           std::move(rsyncHandler));
#endif

        }

        void TearDown() override
        {
            std::remove(MOCK_DB_PATH);
            delete mockLog;
            delete mockSync;
        };
};

TEST_F(FimDBFixture, setFileLimitSuccess)
{
    EXPECT_CALL((*mockDBSync), setTableMaxRow("file_entry", mockMaxRowsFile));
    fimDBMock.setFileLimit();
}

TEST_F(FimDBFixture, setFileLimitNoTableData)
{
    EXPECT_CALL(*mockDBSync, setTableMaxRow("file_entry", mockMaxRowsFile)).
    WillOnce(testing::Throw(DbSync::dbsync_error(6, "dbEngine: Empty table metadata."))); // EMPTY_TABLE_METADATA
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, "dbEngine: Empty table metadata."));

    try
    {
        fimDBMock.setFileLimit();
    }
    catch (DbSync::dbsync_error& err)
    {
        ASSERT_EQ((std::string)(err.what()), "dbEngine: Empty table metadata.");
    }
}

#ifdef WIN32

TEST_F(FimDBFixture, setValueLimitSuccess)
{
    EXPECT_CALL(*mockDBSync, setTableMaxRow("registry_data", mockMaxRowsReg));
    fimDBMock.setValueLimit();
}

TEST_F(FimDBFixture, setValueLimitNoTableData)
{
    EXPECT_CALL(*mockDBSync, setTableMaxRow("registry_data", mockMaxRowsReg)).Times(1).
    WillOnce(testing::Throw(DbSync::dbsync_error(6, "dbEngine: Empty table metadata.")));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, "dbEngine: Empty table metadata."));

    try
    {
        fimDBMock.setValueLimit();
    }
    catch (DbSync::dbsync_error& err)
    {
        ASSERT_EQ((std::string)(err.what()), "dbEngine: Empty table metadata.");
    }
}

TEST_F(FimDBFixture, setRegistryLimitSuccess)
{
    EXPECT_CALL(*mockDBSync, setTableMaxRow("registry_key", mockMaxRowsReg));
    fimDBMock.setRegistryLimit();
}

TEST_F(FimDBFixture, setRegistryLimitNoTableData)
{

    EXPECT_CALL(*mockDBSync, setTableMaxRow("registry_key", mockMaxRowsReg)).
    WillOnce(testing::Throw(DbSync::dbsync_error(6, "dbEngine: Empty table metadata.")));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, "dbEngine: Empty table metadata."));

    try
    {
        fimDBMock.setRegistryLimit();
    }
    catch (DbSync::dbsync_error& err)
    {
        ASSERT_EQ((std::string)(err.what()), "dbEngine: Empty table metadata.");
    }
}

#endif

TEST_F(FimDBFixture, insertItemSuccess)
{
    nlohmann::json itemJson;
    EXPECT_CALL(*mockDBSync, insertData(itemJson));
    dbQueryResult expected_return = dbQueryResult::SUCCESS;
    dbQueryResult return_code =  fimDBMock.insertItem(itemJson);
    ASSERT_EQ(return_code, expected_return);
}

TEST_F(FimDBFixture, insertItemFailMaxRows)
{
    nlohmann::json itemJson;
    EXPECT_CALL(*mockDBSync, insertData(itemJson)).WillOnce(testing::Throw(DbSync::max_rows_error("Too many rows.")));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "Too many rows."));
    dbQueryResult expected_return = dbQueryResult::MAX_ROWS_ERROR;
    dbQueryResult return_code =  fimDBMock.insertItem(itemJson);
    ASSERT_EQ(return_code, expected_return);
}

TEST_F(FimDBFixture, insertItemFailException)
{
    nlohmann::json itemJson;
    EXPECT_CALL(*mockDBSync, insertData(itemJson)).WillOnce(testing::Throw(std::exception()));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, testing::_));
    dbQueryResult expected_return = dbQueryResult::DBSYNC_ERROR;
    dbQueryResult return_code =  fimDBMock.insertItem(itemJson);
    ASSERT_EQ(return_code, expected_return);
}

TEST_F(FimDBFixture, removeItemSuccess)
{
    nlohmann::json itemJson;
    EXPECT_CALL(*mockDBSync, deleteRows(itemJson));
    dbQueryResult expected_return = dbQueryResult::SUCCESS;
    dbQueryResult return_code =  fimDBMock.removeItem(itemJson);
    ASSERT_EQ(return_code, expected_return);
}

TEST_F(FimDBFixture, removeItemFailException)
{
    nlohmann::json itemJson;
    EXPECT_CALL(*mockDBSync, deleteRows(itemJson)).WillOnce(testing::Throw(std::exception()));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, testing::_));
    dbQueryResult expected_return = dbQueryResult::DBSYNC_ERROR;
    dbQueryResult return_code =  fimDBMock.removeItem(itemJson);
    ASSERT_EQ(return_code, expected_return);

}

TEST_F(FimDBFixture, updateItemSuccess)
{
    nlohmann::json itemJson;
    ResultCallbackData callback;
    EXPECT_CALL(*mockDBSync, syncRow(itemJson, testing::_));
    dbQueryResult expected_return = dbQueryResult::SUCCESS;
    dbQueryResult return_code =  fimDBMock.updateItem(itemJson, callback);
    ASSERT_EQ(return_code, expected_return);
}

TEST_F(FimDBFixture, updateItemFailMaxRows)
{
    nlohmann::json itemJson;
    ResultCallbackData callback;
    EXPECT_CALL(*mockDBSync, syncRow(itemJson, testing::_)).WillOnce(testing::Throw(DbSync::max_rows_error("Too many rows.")));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "Too many rows."));
    dbQueryResult expected_return = dbQueryResult::MAX_ROWS_ERROR;
    dbQueryResult return_code =  fimDBMock.updateItem(itemJson, callback);
    ASSERT_EQ(return_code, expected_return);
}

TEST_F(FimDBFixture, updateItemFailException)
{
    nlohmann::json itemJson;
    ResultCallbackData callback;
    EXPECT_CALL(*mockDBSync, syncRow(itemJson, testing::_)).WillOnce(testing::Throw(std::exception()));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, testing::_));
    dbQueryResult expected_return = dbQueryResult::DBSYNC_ERROR;
    dbQueryResult return_code =  fimDBMock.updateItem(itemJson, callback);
    ASSERT_EQ(return_code, expected_return);

}

TEST_F(FimDBFixture, registerSyncIDSuccess)
{

    EXPECT_CALL(*mockRSync, registerSyncID("fim_file_sync", mockDBSync->handle(), nlohmann::json::parse(FIM_FILE_SYNC_CONFIG_STATEMENT), testing::_));
#ifdef WIN32
    EXPECT_CALL(*mockRSync, registerSyncID("fim_registry_sync", mockDBSync->handle(), nlohmann::json::parse(FIM_REGISTRY_SYNC_CONFIG_STATEMENT), testing::_));
    EXPECT_CALL(*mockRSync, registerSyncID("fim_value_sync", mockDBSync->handle(), nlohmann::json::parse(FIM_VALUE_SYNC_CONFIG_STATEMENT), testing::_));
#endif

    fimDBMock.registerRSync();

}

TEST_F(FimDBFixture, registerSyncIDError)
{
    EXPECT_CALL(*mockRSync, registerSyncID("fim_file_sync", mockDBSync->handle(), nlohmann::json::parse(FIM_FILE_SYNC_CONFIG_STATEMENT), testing::_)).
    WillOnce(testing::Throw(std::exception()));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, testing::_));

    fimDBMock.registerRSync();

}

TEST_F(FimDBFixture, loopRSyncSuccess)
{
    nlohmann::json itemJson;
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "FIM sync module started."));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "Executing FIM sync."));
    EXPECT_CALL(*mockRSync, startSync(mockDBSync->handle(), nlohmann::json::parse(FIM_FILE_START_CONFIG_STATEMENT), testing::_));
#ifdef WIN32
    EXPECT_CALL(*mockRSync, startSync(mockDBSync->handle(), nlohmann::json::parse(FIM_REGISTRY_START_CONFIG_STATEMENT), testing::_));
    EXPECT_CALL(*mockRSync, startSync(mockDBSync->handle(), nlohmann::json::parse(FIM_VALUE_START_CONFIG_STATEMENT), testing::_));
#endif
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "Finished FIM sync."));

    std::unique_lock<std::mutex> lock{*(fimDBMock.getMutex())};
    std::thread syncThread(&FIMDB::loopRSync, &fimDBMock, std::ref(lock));

    fimDBMock.stopSync();

    syncThread.join();

}

TEST_F(FimDBFixture, loopRSyncStartSyncException)
{
    nlohmann::json itemJson;

    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "FIM sync module started."));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "Executing FIM sync."));
    EXPECT_CALL(*mockRSync, startSync(mockDBSync->handle(), nlohmann::json::parse(FIM_FILE_START_CONFIG_STATEMENT), testing::_)).WillOnce(testing::Throw(std::exception()));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, testing::_));

    std::unique_lock<std::mutex> lock{*(fimDBMock.getMutex())};
    std::thread syncThread(&FIMDB::loopRSync, &fimDBMock, std::ref(lock));

    fimDBMock.stopSync();

    syncThread.join();

}

TEST_F(FimDBFixture, executeQuerySuccess)
{
    nlohmann::json itemJson;
    ResultCallbackData callback;
    EXPECT_CALL(*mockDBSync, selectRows(itemJson, testing::_));
    dbQueryResult expected_return = dbQueryResult::SUCCESS;
    dbQueryResult return_code =  fimDBMock.executeQuery(itemJson, callback);
    ASSERT_EQ(return_code, expected_return);
}

TEST_F(FimDBFixture, executeQueryFailMaxRows)
{
    nlohmann::json itemJson;
    ResultCallbackData callback;
    EXPECT_CALL(*mockDBSync, selectRows(itemJson, testing::_)).WillOnce(testing::Throw(DbSync::max_rows_error("Too many rows.")));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_INFO, "Too many rows."));
    dbQueryResult expected_return = dbQueryResult::MAX_ROWS_ERROR;
    dbQueryResult return_code =  fimDBMock.executeQuery(itemJson, callback);
    ASSERT_EQ(return_code, expected_return);
}

TEST_F(FimDBFixture, executeQueryFailException)
{
    nlohmann::json itemJson;
    ResultCallbackData callback;
    EXPECT_CALL(*mockDBSync, selectRows(itemJson, testing::_)).WillOnce(testing::Throw(std::exception()));
    EXPECT_CALL(*mockLog, loggingFunction(LOG_ERROR, testing::_));
    dbQueryResult expected_return = dbQueryResult::DBSYNC_ERROR;
    dbQueryResult return_code =  fimDBMock.executeQuery(itemJson, callback);
    ASSERT_EQ(return_code, expected_return);

}

#endif
