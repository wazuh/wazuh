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
#include <string>
#include "abstractLocking.hpp"
#include "dbengine_test.h"
#include "sqlite_dbengine.h"
#include "../mocks/sqlitewrapper_mock.h"
#include "../mocks/sqlitefactory_mock.h"

using ::testing::_;
using ::testing::Return;
using ::testing::An;
using ::testing::ByMove;

static void initNoMetaDataMocks(std::unique_ptr<SQLiteDBEngine>& spEngine)
{
    const auto& mockFactory { std::make_shared<MockSQLiteFactory>() };
    const auto& mockConnection { std::make_shared<MockConnection>() };

    auto mockTransaction { std::make_unique<MockTransaction>() };

    EXPECT_CALL(*mockFactory, createTransaction(_))
    .WillOnce(Return(ByMove(std::move(mockTransaction))));

    EXPECT_CALL(*mockFactory, createConnection(_)).WillOnce(Return(mockConnection));

    auto mockStatement_1 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_1, step()).WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "NNN"))
    .WillOnce(Return(ByMove(std::move(mockStatement_1))));

    EXPECT_CALL(*mockConnection, execute("PRAGMA temp_store = memory;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA journal_mode = truncate;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA synchronous = OFF;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA user_version = 1;")).Times(1);

    EXPECT_NO_THROW(spEngine = std::make_unique<SQLiteDBEngine>(
                                   mockFactory,
                                   "1",
                                   "NNN"));

    auto mockStatement_2 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_2, step())
    .WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "PRAGMA table_info(dummy);"))
    .WillOnce(Return(ByMove(std::move(mockStatement_2))));
}

TEST_F(DBEngineTest, Initialization)
{
    const auto& mockFactory { std::make_shared<MockSQLiteFactory>() };
    const auto& mockConnection { std::make_shared<MockConnection>() };
    auto mockStatement { std::make_unique<MockStatement>() };
    auto mockTransaction { std::make_unique<MockTransaction>() };

    EXPECT_CALL(*mockFactory, createTransaction(_))
    .WillOnce(Return(ByMove(std::move(mockTransaction))));
    EXPECT_CALL(*mockFactory, createConnection(_))
    .WillOnce(Return(mockConnection));
    EXPECT_CALL(*mockStatement, step())
    .WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockFactory, createStatement(_, _))
    .WillOnce(Return(ByMove(std::move(mockStatement))));
    EXPECT_CALL(*mockConnection, execute("PRAGMA temp_store = memory;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA journal_mode = truncate;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA synchronous = OFF;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA user_version = 1;")).Times(1);

    EXPECT_NO_THROW(std::make_unique<SQLiteDBEngine>(
                        mockFactory,
                        "1",
                        "NNN"));
}

TEST_F(DBEngineTest, InitializationSQLError)
{
    const auto& mockFactory { std::make_shared<MockSQLiteFactory>() };
    const auto& mockConnection { std::make_shared<MockConnection>() };
    auto mockStatement { std::make_unique<MockStatement>() };

    EXPECT_CALL(*mockFactory, createConnection(_))
    .WillOnce(Return(mockConnection));
    EXPECT_CALL(*mockStatement, step())
    .WillOnce(Return(SQLITE_ERROR));
    EXPECT_CALL(*mockFactory, createStatement(_, _))
    .WillOnce(Return(ByMove(std::move(mockStatement))));
    EXPECT_CALL(*mockConnection, execute("PRAGMA temp_store = memory;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA journal_mode = truncate;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA synchronous = OFF;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA user_version = 1;")).Times(1);

    EXPECT_THROW(std::make_unique<SQLiteDBEngine>(
                     mockFactory,
                     "1",
                     "NNN"), dbengine_error);
}

TEST_F(DBEngineTest, InitializationEmptyQuery)
{
    const auto& mockFactory { std::make_shared<MockSQLiteFactory>() };
    const auto& mockConnection { std::make_shared<MockConnection>() };
    auto mockTransaction { std::make_unique<MockTransaction>() };

    EXPECT_CALL(*mockFactory, createTransaction(_))
    .WillOnce(Return(ByMove(std::move(mockTransaction))));
    EXPECT_CALL(*mockFactory, createConnection(_))
    .WillOnce(Return(mockConnection));
    EXPECT_CALL(*mockConnection, execute("PRAGMA temp_store = memory;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA journal_mode = truncate;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA synchronous = OFF;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA user_version = 1;")).Times(1);

    EXPECT_NO_THROW(std::make_unique<SQLiteDBEngine>(
                        mockFactory,
                        "1",
                        ""));
}

TEST_F(DBEngineTest, InitializationEmptyFileName)
{
    EXPECT_THROW(std::make_unique<SQLiteDBEngine>(
                     nullptr,
                     "",
                     "NNN"), dbengine_error);
}

TEST_F(DBEngineTest, InitializeStatusField)
{
    const auto& mockFactory { std::make_shared<MockSQLiteFactory>() };
    const auto& mockConnection { std::make_shared<MockConnection>() };

    auto mockTransaction { std::make_unique<MockTransaction>() };

    EXPECT_CALL(*mockFactory, createConnection(_))
    .WillOnce(Return(mockConnection));
    EXPECT_CALL(*mockFactory, createTransaction(_))
    .WillOnce(Return(ByMove(std::move(mockTransaction))));

    auto mockStatement_1 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_1, step()).WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "NNN"))
    .WillOnce(Return(ByMove(std::move(mockStatement_1))));


    EXPECT_CALL(*mockConnection, execute("PRAGMA temp_store = memory;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA journal_mode = truncate;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA synchronous = OFF;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA user_version = 1;")).Times(1);

    std::unique_ptr<SQLiteDBEngine> spEngine;
    EXPECT_NO_THROW(spEngine = std::make_unique<SQLiteDBEngine>(
                                   mockFactory,
                                   "1",
                                   "NNN"));

    auto mockColumn_1 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_1, value(An<const int32_t&>()))
    .WillOnce(Return(0));
    auto mockColumn_2 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_2, value(An<const std::string&>()))
    .WillOnce(Return("PID"));
    auto mockColumn_3 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_3, value(An<const std::string&>()))
    .WillOnce(Return("INTEGER"));
    auto mockColumn_4 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_4, value(An<const int32_t&>()))
    .WillOnce(Return(1));

    auto mockStatement_2 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_2, step())
    .WillOnce(Return(SQLITE_ROW))
    .WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockStatement_2, column(0))
    .WillOnce(Return(ByMove(std::move(mockColumn_1))));
    EXPECT_CALL(*mockStatement_2, column(1))
    .WillOnce(Return(ByMove(std::move(mockColumn_2))));
    EXPECT_CALL(*mockStatement_2, column(2))
    .WillOnce(Return(ByMove(std::move(mockColumn_3))));
    EXPECT_CALL(*mockStatement_2, column(5))
    .WillOnce(Return(ByMove(std::move(mockColumn_4))));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "PRAGMA table_info(dummy);"))
    .WillOnce(Return(ByMove(std::move(mockStatement_2))));

    auto mockStatement_3 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_3,
                step())
    .WillOnce(Return(0));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "ALTER TABLE dummy ADD COLUMN db_status_field_dm INTEGER DEFAULT 1;"))
    .WillOnce(Return(ByMove(std::move(mockStatement_3))));

    auto mockStatement_4 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_4,
                step())
    .WillOnce(Return(0));

    EXPECT_CALL(*mockFactory,
                createStatement(_, "UPDATE dummy SET db_status_field_dm=0;"))
    .WillOnce(Return(ByMove(std::move(mockStatement_4))));


    EXPECT_NO_THROW(spEngine->initializeStatusField(std::vector<std::string> {"dummy"}));
}

TEST_F(DBEngineTest, InitializeStatusFieldNoMetadata)
{
    const auto& mockFactory { std::make_shared<MockSQLiteFactory>() };
    const auto& mockConnection { std::make_shared<MockConnection>() };

    auto mockTransaction { std::make_unique<MockTransaction>() };

    EXPECT_CALL(*mockFactory, createConnection(_))
    .WillOnce(Return(mockConnection));
    EXPECT_CALL(*mockFactory, createTransaction(_))
    .WillOnce(Return(ByMove(std::move(mockTransaction))));

    auto mockStatement_1 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_1, step())
    .WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "NNN"))
    .WillOnce(Return(ByMove(std::move(mockStatement_1))));


    EXPECT_CALL(*mockConnection, execute("PRAGMA temp_store = memory;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA journal_mode = truncate;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA synchronous = OFF;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA user_version = 1;")).Times(1);

    std::unique_ptr<SQLiteDBEngine> spEngine;
    EXPECT_NO_THROW(spEngine = std::make_unique<SQLiteDBEngine>(
                                   mockFactory,
                                   "1",
                                   "NNN"));

    auto mockStatement_2 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_2, step())
    .WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "PRAGMA table_info(dummy);"))
    .WillOnce(Return(ByMove(std::move(mockStatement_2))));

    EXPECT_THROW(spEngine->initializeStatusField(std::vector<std::string> {"dummy"}), dbengine_error);
}

TEST_F(DBEngineTest, InitializeStatusFieldPreExistent)
{
    const auto& mockFactory { std::make_shared<MockSQLiteFactory>() };
    const auto& mockConnection { std::make_shared<MockConnection>() };

    auto mockTransaction { std::make_unique<MockTransaction>() };

    EXPECT_CALL(*mockFactory, createConnection(_))
    .WillOnce(Return(mockConnection));
    EXPECT_CALL(*mockFactory, createTransaction(_))
    .WillOnce(Return(ByMove(std::move(mockTransaction))));

    auto mockStatement_1 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_1, step())
    .WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "NNN"))
    .WillOnce(Return(ByMove(std::move(mockStatement_1))));


    EXPECT_CALL(*mockConnection, execute("PRAGMA temp_store = memory;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA journal_mode = truncate;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA synchronous = OFF;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA user_version = 1;")).Times(1);

    std::unique_ptr<SQLiteDBEngine> spEngine;
    EXPECT_NO_THROW(spEngine = std::make_unique<SQLiteDBEngine>(
                                   mockFactory,
                                   "1",
                                   "NNN"));

    auto mockColumn_1 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_1, value(An<const int32_t&>()))
    .WillOnce(Return(0));
    auto mockColumn_2 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_2, value(An<const std::string&>()))
    .WillOnce(Return("PID"));
    auto mockColumn_3 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_3, value(An<const std::string&>()))
    .WillOnce(Return("INTEGER"));
    auto mockColumn_4 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_4, value(An<const int32_t&>()))
    .WillOnce(Return(1));

    auto mockColumn_5 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_5, value(An<const int32_t&>()))
    .WillOnce(Return(0));
    auto mockColumn_6 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_6, value(An<const std::string&>()))
    .WillOnce(Return(STATUS_FIELD_NAME));
    auto mockColumn_7 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_7, value(An<const std::string&>()))
    .WillOnce(Return(STATUS_FIELD_TYPE));
    auto mockColumn_8 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_8, value(An<const int32_t&>()))
    .WillOnce(Return(1));

    auto mockStatement_2 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_2, step())
    .WillOnce(Return(SQLITE_ROW))
    .WillOnce(Return(SQLITE_ROW))
    .WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockStatement_2, column(0))
    .WillOnce(Return(ByMove(std::move(mockColumn_1))))
    .WillOnce(Return(ByMove(std::move(mockColumn_5))));
    EXPECT_CALL(*mockStatement_2, column(1))
    .WillOnce(Return(ByMove(std::move(mockColumn_2))))
    .WillOnce(Return(ByMove(std::move(mockColumn_6))));
    EXPECT_CALL(*mockStatement_2, column(2))
    .WillOnce(Return(ByMove(std::move(mockColumn_3))))
    .WillOnce(Return(ByMove(std::move(mockColumn_7))));
    EXPECT_CALL(*mockStatement_2, column(5))
    .WillOnce(Return(ByMove(std::move(mockColumn_4))))
    .WillOnce(Return(ByMove(std::move(mockColumn_8))));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "PRAGMA table_info(dummy);"))
    .WillOnce(Return(ByMove(std::move(mockStatement_2))));

    auto mockStatement_4 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_4,
                step())
    .WillOnce(Return(0));

    EXPECT_CALL(*mockFactory,
                createStatement(_, "UPDATE dummy SET db_status_field_dm=0;"))
    .WillOnce(Return(ByMove(std::move(mockStatement_4))));

    EXPECT_NO_THROW(spEngine->initializeStatusField(std::vector<std::string> {"dummy"}));
}

TEST_F(DBEngineTest, DeleteRowsByStatusField)
{
    const auto& mockFactory { std::make_shared<MockSQLiteFactory>() };
    const auto& mockConnection { std::make_shared<MockConnection>() };

    auto mockTransaction { std::make_unique<MockTransaction>() };

    EXPECT_CALL(*mockFactory, createConnection(_))
    .WillOnce(Return(mockConnection));
    EXPECT_CALL(*mockFactory, createTransaction(_))
    .WillOnce(Return(ByMove(std::move(mockTransaction))));

    auto mockStatement_1 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_1, step())
    .WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "NNN"))
    .WillOnce(Return(ByMove(std::move(mockStatement_1))));

    EXPECT_CALL(*mockConnection, execute("PRAGMA temp_store = memory;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA journal_mode = truncate;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA synchronous = OFF;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA user_version = 1;")).Times(1);

    EXPECT_CALL(*mockConnection, changes()).Times(1)
    .WillOnce(Return(1));

    std::unique_ptr<SQLiteDBEngine> spEngine;
    EXPECT_NO_THROW(spEngine = std::make_unique<SQLiteDBEngine>(
                                   mockFactory,
                                   "1",
                                   "NNN"));

    auto mockColumn_1 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_1, value(An<const int32_t&>()))
    .WillOnce(Return(0));
    auto mockColumn_2 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_2, value(An<const std::string&>()))
    .WillOnce(Return("PID"));
    auto mockColumn_3 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_3, value(An<const std::string&>()))
    .WillOnce(Return("INTEGER"));
    auto mockColumn_4 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_4, value(An<const int32_t&>()))
    .WillOnce(Return(1));

    auto mockColumn_5 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_5, value(An<const int32_t&>()))
    .WillOnce(Return(0));
    auto mockColumn_6 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_6, value(An<const std::string&>()))
    .WillOnce(Return(STATUS_FIELD_NAME));
    auto mockColumn_7 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_7, value(An<const std::string&>()))
    .WillOnce(Return(STATUS_FIELD_TYPE));
    auto mockColumn_8 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_8, value(An<const int32_t&>()))
    .WillOnce(Return(1));

    auto mockStatement_2 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_2, step())
    .WillOnce(Return(SQLITE_ROW))
    .WillOnce(Return(SQLITE_ROW))
    .WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockStatement_2, column(0))
    .WillOnce(Return(ByMove(std::move(mockColumn_1))))
    .WillOnce(Return(ByMove(std::move(mockColumn_5))));
    EXPECT_CALL(*mockStatement_2, column(1))
    .WillOnce(Return(ByMove(std::move(mockColumn_2))))
    .WillOnce(Return(ByMove(std::move(mockColumn_6))));
    EXPECT_CALL(*mockStatement_2, column(2))
    .WillOnce(Return(ByMove(std::move(mockColumn_3))))
    .WillOnce(Return(ByMove(std::move(mockColumn_7))));
    EXPECT_CALL(*mockStatement_2, column(5))
    .WillOnce(Return(ByMove(std::move(mockColumn_4))))
    .WillOnce(Return(ByMove(std::move(mockColumn_8))));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "PRAGMA table_info(dummy);"))
    .WillOnce(Return(ByMove(std::move(mockStatement_2))));

    auto mockStatement_3 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_3,
                step())
    .WillOnce(Return(0));

    EXPECT_CALL(*mockFactory,
                createStatement(_, "DELETE FROM dummy WHERE db_status_field_dm=0;"))
    .WillOnce(Return(ByMove(std::move(mockStatement_3))));

    EXPECT_NO_THROW(spEngine->deleteRowsByStatusField(std::vector<std::string> {"dummy"}));
}

TEST_F(DBEngineTest, DeleteRowsByStatusFieldNoMetadata)
{
    const auto& mockFactory { std::make_shared<MockSQLiteFactory>() };
    const auto& mockConnection { std::make_shared<MockConnection>() };

    auto mockTransaction { std::make_unique<MockTransaction>() };

    EXPECT_CALL(*mockFactory, createConnection(_))
    .WillOnce(Return(mockConnection));
    EXPECT_CALL(*mockFactory, createTransaction(_))
    .WillOnce(Return(ByMove(std::move(mockTransaction))));

    auto mockStatement_1 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_1, step()).WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "NNN"))
    .WillOnce(Return(ByMove(std::move(mockStatement_1))));

    EXPECT_CALL(*mockConnection, execute("PRAGMA temp_store = memory;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA journal_mode = truncate;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA synchronous = OFF;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA user_version = 1;")).Times(1);

    std::unique_ptr<SQLiteDBEngine> spEngine;
    EXPECT_NO_THROW(spEngine = std::make_unique<SQLiteDBEngine>(
                                   mockFactory,
                                   "1",
                                   "NNN"));

    auto mockStatement_2 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_2, step())
    .WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "PRAGMA table_info(dummy);"))
    .WillOnce(Return(ByMove(std::move(mockStatement_2))));

    EXPECT_THROW(spEngine->deleteRowsByStatusField(std::vector<std::string> {"dummy"}), dbengine_error);
}

TEST_F(DBEngineTest, GetRowsToBeDeletedByStatusFieldNoMetadata)
{
    const auto& mockFactory { std::make_shared<MockSQLiteFactory>() };
    const auto& mockConnection { std::make_shared<MockConnection>() };
    auto mockTransaction1 { std::make_unique<MockTransaction>() };
    auto mockTransaction2 { std::make_unique<MockTransaction>() };

    EXPECT_CALL(*mockFactory, createConnection(_))
    .WillOnce(Return(mockConnection));
    EXPECT_CALL(*mockTransaction1, commit()).Times(1);
    EXPECT_CALL(*mockFactory, createTransaction(_)).Times(2)
    .WillOnce(Return(ByMove(std::move(mockTransaction1))))
    .WillOnce(Return(ByMove(std::move(mockTransaction2))));

    auto mockStatement_1 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_1, step()).WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockFactory, createStatement(_, "NNN"))
    .WillOnce(Return(ByMove(std::move(mockStatement_1))));

    EXPECT_CALL(*mockConnection, execute("PRAGMA temp_store = memory;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA journal_mode = truncate;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA synchronous = OFF;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA user_version = 1;")).Times(1);

    std::unique_ptr<SQLiteDBEngine> spEngine;
    EXPECT_NO_THROW(spEngine = std::make_unique<SQLiteDBEngine>(
                                   mockFactory,
                                   "1",
                                   "NNN"));

    auto mockStatement_2 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_2, step())
    .WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockFactory, createStatement(_, "PRAGMA table_info(dummy);"))
    .WillOnce(Return(ByMove(std::move(mockStatement_2))));

    std::shared_timed_mutex mutex;
    std::unique_lock<std::shared_timed_mutex> lock(mutex);
    EXPECT_THROW(spEngine->returnRowsMarkedForDelete({"dummy"}, nullptr, lock), dbengine_error);
}

TEST_F(DBEngineTest, GetRowsToBeDeletedByStatusField)
{
    const auto& mockFactory { std::make_shared<MockSQLiteFactory>() };
    const auto& mockConnection { std::make_shared<MockConnection>() };

    // First transaction, during the initialization of the engine.
    auto mockTransaction1 { std::make_unique<MockTransaction>() };
    // Second transaction, created after the getDeletedRows call.
    auto mockTransaction2 { std::make_unique<MockTransaction>() };

    EXPECT_CALL(*mockFactory, createConnection(_)).WillOnce(Return(mockConnection));
    EXPECT_CALL(*mockTransaction1, commit()).Times(1);
    EXPECT_CALL(*mockFactory, createTransaction(_))
    .Times(2)
    .WillOnce(Return(ByMove(std::move(mockTransaction1))))
    .WillOnce(Return(ByMove(std::move(mockTransaction2))));

    auto mockStatement_1 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_1, step()).WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "NNN"))
    .WillOnce(Return(ByMove(std::move(mockStatement_1))));


    EXPECT_CALL(*mockConnection, execute("PRAGMA temp_store = memory;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA journal_mode = truncate;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA synchronous = OFF;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA user_version = 1;")).Times(1);

    std::unique_ptr<SQLiteDBEngine> spEngine;
    EXPECT_NO_THROW(spEngine = std::make_unique<SQLiteDBEngine>(
                                   mockFactory,
                                   "1",
                                   "NNN"));

    auto mockColumn_1 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_1, value(An<const int32_t&>()))
    .WillOnce(Return(0));
    auto mockColumn_2 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_2, value(An<const std::string&>()))
    .WillOnce(Return("PID"));
    auto mockColumn_3 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_3, value(An<const std::string&>()))
    .WillOnce(Return("INTEGER"));
    auto mockColumn_4 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_4, value(An<const int32_t&>()))
    .WillOnce(Return(1));

    auto mockColumn_5 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_5, value(An<const int32_t&>()))
    .WillOnce(Return(0));
    auto mockColumn_6 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_6, value(An<const std::string&>()))
    .WillOnce(Return(STATUS_FIELD_NAME));
    auto mockColumn_7 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_7, value(An<const std::string&>()))
    .WillOnce(Return(STATUS_FIELD_TYPE));
    auto mockColumn_8 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_8, value(An<const int32_t&>()))
    .WillOnce(Return(1));

    auto mockStatement_2 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_2, step())
    .WillOnce(Return(SQLITE_ROW))
    .WillOnce(Return(SQLITE_ROW))
    .WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockStatement_2, column(0))
    .WillOnce(Return(ByMove(std::move(mockColumn_1))))
    .WillOnce(Return(ByMove(std::move(mockColumn_5))));
    EXPECT_CALL(*mockStatement_2, column(1))
    .WillOnce(Return(ByMove(std::move(mockColumn_2))))
    .WillOnce(Return(ByMove(std::move(mockColumn_6))));
    EXPECT_CALL(*mockStatement_2, column(2))
    .WillOnce(Return(ByMove(std::move(mockColumn_3))))
    .WillOnce(Return(ByMove(std::move(mockColumn_7))));
    EXPECT_CALL(*mockStatement_2, column(5))
    .WillOnce(Return(ByMove(std::move(mockColumn_4))))
    .WillOnce(Return(ByMove(std::move(mockColumn_8))));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "PRAGMA table_info(dummy);"))
    .WillOnce(Return(ByMove(std::move(mockStatement_2))));

    auto mockStatement_3 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_3,
                step())
    .WillOnce(Return(SQLITE_ROW))
    .WillOnce(Return(SQLITE_DONE));

    auto mockColumn_9 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_9, value(An<const int64_t&>()))
    .WillOnce(Return(1));

    EXPECT_CALL(*mockStatement_3, column(0))
    .WillOnce(Return(ByMove(std::move(mockColumn_9))));

    EXPECT_CALL(*mockFactory,
                createStatement(_, "SELECT PID FROM dummy WHERE db_status_field_dm=0;"))
    .WillOnce(Return(ByMove(std::move(mockStatement_3))));

    std::shared_timed_mutex mutex;
    std::unique_lock<std::shared_timed_mutex> lock(mutex);
    EXPECT_NO_THROW(spEngine->returnRowsMarkedForDelete({"dummy"}, [](ReturnTypeCallback, const nlohmann::json&) {}, lock));
}

TEST_F(DBEngineTest, syncTableRowDataWithoutMetadataShouldThrow)
{
    std::unique_ptr<SQLiteDBEngine> spEngine;
    std::shared_timed_mutex mutex;
    Utils::ExclusiveLocking lock(mutex);

    initNoMetaDataMocks(spEngine);
    // Due to the no metadata this should throw
    EXPECT_THROW(spEngine->syncTableRowData({{"table", "dummy"}, {"data", {}}}, nullptr, false, lock), dbengine_error);
}

TEST_F(DBEngineTest, deleteTableRowsDataWithoutMetadataShouldThrow)
{
    std::unique_ptr<SQLiteDBEngine> spEngine;
    initNoMetaDataMocks(spEngine);

    // Due to the no metadata this should throw
    EXPECT_THROW(spEngine->deleteTableRowsData("dummy", {}), dbengine_error);
}

TEST_F(DBEngineTest, selectDataWithoutMetadataShouldThrow)
{
    std::unique_ptr<SQLiteDBEngine> spEngine;
    initNoMetaDataMocks(spEngine);

    // Due to the no metadata this should throw
    std::shared_timed_mutex mutex;
    std::unique_lock<std::shared_timed_mutex> lock(mutex);
    EXPECT_THROW(spEngine->selectData("dummy", {}, nullptr, lock), dbengine_error);
}

TEST_F(DBEngineTest, bulkInsertWithoutMetadataShouldThrow)
{
    std::unique_ptr<SQLiteDBEngine> spEngine;
    initNoMetaDataMocks(spEngine);

    // Due to the no metadata this should throw
    EXPECT_THROW(spEngine->bulkInsert("dummy", nullptr), dbengine_error);
}
TEST_F(DBEngineTest, AddTableRelationship)
{
    const auto& mockFactory { std::make_shared<MockSQLiteFactory>() };
    const auto& mockConnection { std::make_shared<MockConnection>() };
    const auto& relationshipJSON { nlohmann::json::parse(
                                       R"(
            {
                "base_table":"dummy",
                "relationed_tables":
                [
                    {
                        "table": "dummy_relationed_1",
                        "field_match":
                        {
                            "field_n_1": "field_m_1",
                            "field_n_2": "field_m_2"
                        }
                    },
                    {
                        "table": "dummy_relationed_2",
                        "field_match":
                        {
                            "field_n_1": "field_m_1",
                            "field_n_2": "field_m_2"
                        }
                    }
                ]
            }
        )"
                                   )};
    auto mockTransaction { std::make_unique<MockTransaction>() };

    EXPECT_CALL(*mockFactory, createTransaction(_))
    .WillOnce(Return(ByMove(std::move(mockTransaction))));
    EXPECT_CALL(*mockFactory, createConnection(_)).WillOnce(Return(mockConnection));

    auto mockStatement_1 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_1, step()).WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "NNN"))
    .WillOnce(Return(ByMove(std::move(mockStatement_1))));


    EXPECT_CALL(*mockConnection, execute("PRAGMA temp_store = memory;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA journal_mode = truncate;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA synchronous = OFF;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA user_version = 1;")).Times(1);

    std::unique_ptr<SQLiteDBEngine> spEngine;
    EXPECT_NO_THROW(spEngine = std::make_unique<SQLiteDBEngine>(
                                   mockFactory,
                                   "1",
                                   "NNN"));

    auto mockColumn_1 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_1, value(An<const int32_t&>()))
    .WillOnce(Return(0));
    auto mockColumn_2 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_2, value(An<const std::string&>()))
    .WillOnce(Return("PID"));
    auto mockColumn_3 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_3, value(An<const std::string&>()))
    .WillOnce(Return("INTEGER"));
    auto mockColumn_4 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_4, value(An<const int32_t&>()))
    .WillOnce(Return(1));

    auto mockColumn_5 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_5, value(An<const int32_t&>()))
    .WillOnce(Return(0));
    auto mockColumn_6 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_6, value(An<const std::string&>()))
    .WillOnce(Return(STATUS_FIELD_NAME));
    auto mockColumn_7 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_7, value(An<const std::string&>()))
    .WillOnce(Return(STATUS_FIELD_TYPE));
    auto mockColumn_8 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_8, value(An<const int32_t&>()))
    .WillOnce(Return(0));

    auto mockColumn_9 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_9, value(An<const int32_t&>()))
    .WillOnce(Return(0));
    auto mockColumn_10 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_10, value(An<const std::string&>()))
    .WillOnce(Return("path"));
    auto mockColumn_11 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_11, value(An<const std::string&>()))
    .WillOnce(Return("TEXT"));
    auto mockColumn_12 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_12, value(An<const int32_t&>()))
    .WillOnce(Return(1));

    auto mockStatement_2 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_2, step())
    .WillOnce(Return(SQLITE_ROW))
    .WillOnce(Return(SQLITE_ROW))
    .WillOnce(Return(SQLITE_ROW))
    .WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockStatement_2, column(0))
    .WillOnce(Return(ByMove(std::move(mockColumn_1))))
    .WillOnce(Return(ByMove(std::move(mockColumn_5))))
    .WillOnce(Return(ByMove(std::move(mockColumn_9))));
    EXPECT_CALL(*mockStatement_2, column(1))
    .WillOnce(Return(ByMove(std::move(mockColumn_2))))
    .WillOnce(Return(ByMove(std::move(mockColumn_6))))
    .WillOnce(Return(ByMove(std::move(mockColumn_10))));
    EXPECT_CALL(*mockStatement_2, column(2))
    .WillOnce(Return(ByMove(std::move(mockColumn_3))))
    .WillOnce(Return(ByMove(std::move(mockColumn_7))))
    .WillOnce(Return(ByMove(std::move(mockColumn_11))));
    EXPECT_CALL(*mockStatement_2, column(5))
    .WillOnce(Return(ByMove(std::move(mockColumn_4))))
    .WillOnce(Return(ByMove(std::move(mockColumn_8))))
    .WillOnce(Return(ByMove(std::move(mockColumn_12))));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "PRAGMA table_info(dummy);"))
    .WillOnce(Return(ByMove(std::move(mockStatement_2))));

    EXPECT_CALL(*mockConnection,
                execute("CREATE TRIGGER IF NOT EXISTS dummy_delete BEFORE DELETE ON dummy BEGIN DELETE FROM dummy_relationed_1 WHERE field_n_1 = OLD.field_m_1 AND field_n_2 = OLD.field_m_2;DELETE FROM dummy_relationed_2 WHERE field_n_1 = OLD.field_m_1 AND field_n_2 = OLD.field_m_2;END;")).Times(
                    1);
    EXPECT_CALL(*mockConnection,
                execute("CREATE TRIGGER IF NOT EXISTS dummy_update BEFORE UPDATE OF PID,path ON dummy BEGIN UPDATE dummy_relationed_1 SET field_n_1 = NEW.field_m_1,field_n_2 = NEW.field_m_2 WHERE field_n_1 = OLD.field_m_1 AND field_n_2 = OLD.field_m_2;UPDATE dummy_relationed_2 SET field_n_1 = NEW.field_m_1,field_n_2 = NEW.field_m_2 WHERE field_n_1 = OLD.field_m_1 AND field_n_2 = OLD.field_m_2;END;")).Times(
                    1);

    EXPECT_NO_THROW(spEngine->addTableRelationship(relationshipJSON));
}

TEST_F(DBEngineTest, AddTableRelationshipNoMetadata)
{
    const auto& mockFactory { std::make_shared<MockSQLiteFactory>() };
    const auto& mockConnection { std::make_shared<MockConnection>() };
    const auto& relationshipJSON { nlohmann::json::parse(
                                       R"(
            {
                "base_table":"dummy",
                "relationed_tables":
                [
                    {
                        "table": "dummy_relationed_1",
                        "field_match":
                        {
                            "field_n_1": "field_m_1",
                            "field_n_2": "field_m_2"
                        }
                    },
                    {
                        "table": "dummy_relationed_2",
                        "field_match":
                        {
                            "field_n_1": "field_m_1",
                            "field_n_2": "field_m_2"
                        }
                    }
                ]
            }
        )"
                                   )};
    auto mockTransaction { std::make_unique<MockTransaction>() };

    EXPECT_CALL(*mockFactory, createTransaction(_))
    .WillOnce(Return(ByMove(std::move(mockTransaction))));
    EXPECT_CALL(*mockFactory, createConnection(_))
    .WillOnce(Return(mockConnection));

    auto mockStatement_1 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_1, step())
    .WillOnce(Return(SQLITE_DONE));
    EXPECT_CALL(*mockFactory,
                createStatement(_, "NNN"))
    .WillOnce(Return(ByMove(std::move(mockStatement_1))));


    EXPECT_CALL(*mockConnection, execute("PRAGMA temp_store = memory;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA journal_mode = truncate;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA synchronous = OFF;")).Times(1);
    EXPECT_CALL(*mockConnection, execute("PRAGMA user_version = 1;")).Times(1);

    std::unique_ptr<SQLiteDBEngine> spEngine;
    EXPECT_NO_THROW(spEngine = std::make_unique<SQLiteDBEngine>(
                                   mockFactory,
                                   "1",
                                   "NNN"));

    auto mockStatement_2 { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement_2, step())
    .WillOnce(Return(SQLITE_DONE));

    EXPECT_CALL(*mockFactory,
                createStatement(_, "PRAGMA table_info(dummy);"))
    .WillOnce(Return(ByMove(std::move(mockStatement_2))));

    EXPECT_THROW(spEngine->addTableRelationship(relationshipJSON), dbengine_error);
}
