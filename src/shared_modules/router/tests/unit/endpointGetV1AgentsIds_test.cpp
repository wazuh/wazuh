/*
 * Wazuh router
 * Copyright (C) 2015, Wazuh Inc.
 * May 5, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared_modules/router/src/wazuh-db/endpointGetV1AgentsIds.hpp"
#include "shared_modules/utils/mocks/sqlite3WrapperMock.hpp"
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Runs unit tests for EndpointGetV1AgentIdsTest class
 */
class EndpointGetV1AgentIdsTest : public ::testing::Test
{
protected:
    EndpointGetV1AgentIdsTest() = default;
    ~EndpointGetV1AgentIdsTest() override = default;
};

TEST_F(EndpointGetV1AgentIdsTest, TestHappyCase)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    EXPECT_CALL(*stmt, step()).WillOnce(testing::Return(SQLITE_ROW)).WillOnce(testing::Return(SQLITE_DONE));

    EXPECT_CALL(*stmt, valueInt64(0)).WillOnce(testing::Return(1));

    TEndpointGetV1AgentsIds<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, "[1]");
    ASSERT_EQ(queries->size(), 1);
    EXPECT_EQ((*queries)[0], "SELECT id FROM agent WHERE id > 0");

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}

TEST_F(EndpointGetV1AgentIdsTest, TestHappyMultipleResultsCase)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    EXPECT_CALL(*stmt, step())
        .WillOnce(testing::Return(SQLITE_ROW))
        .WillOnce(testing::Return(SQLITE_ROW))
        .WillOnce(testing::Return(SQLITE_ROW))
        .WillOnce(testing::Return(SQLITE_DONE));

    EXPECT_CALL(*stmt, valueInt64(0))
        .WillOnce(testing::Return(1))
        .WillOnce(testing::Return(3))
        .WillOnce(testing::Return(4));

    TEndpointGetV1AgentsIds<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, "[1,3,4]");
    ASSERT_EQ(queries->size(), 1);
    EXPECT_EQ((*queries)[0], "SELECT id FROM agent WHERE id > 0");

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}

TEST_F(EndpointGetV1AgentIdsTest, TestNoResultsCase)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    EXPECT_CALL(*stmt, step()).WillOnce(testing::Return(SQLITE_DONE));

    TEndpointGetV1AgentsIds<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, "[]");
    ASSERT_EQ(queries->size(), 1);
    EXPECT_EQ((*queries)[0], "SELECT id FROM agent WHERE id > 0");

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}
