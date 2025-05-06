/*
 * Wazuh router - Subscriber tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared_modules/router/src/wazuh-db/endpointGetV1AgentsIdsGroups.hpp"
#include "shared_modules/utils/mocks/sqlite3WrapperMock.hpp"
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Runs unit tests for EndpointGetV1AgentIdsGroupsTest class
 */
class EndpointGetV1AgentIdsGroupsTest : public ::testing::Test
{
protected:
    EndpointGetV1AgentIdsGroupsTest() = default;
    ~EndpointGetV1AgentIdsGroupsTest() override = default;
};

TEST_F(EndpointGetV1AgentIdsGroupsTest, TestHappyCase)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    EXPECT_CALL(*stmt, step()).WillOnce(testing::Return(SQLITE_ROW)).WillOnce(testing::Return(SQLITE_DONE));

    EXPECT_CALL(*stmt, valueInt64(0)).WillOnce(testing::Return(1));
    EXPECT_CALL(*stmt, valueString(1)).WillOnce(testing::Return("test_group"));

    TEndpointGetV1AgentsIdsGroups<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"({"data":{"1":["test_group"]}})");
    ASSERT_EQ(queries->size(), 1);
    EXPECT_EQ((*queries)[0],
              "SELECT b.id_agent AS id_agent, g.name AS group_name FROM belongs b JOIN 'group' g ON "
              "b.id_group=g.id WHERE b.id_agent > 0;");

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}

TEST_F(EndpointGetV1AgentIdsGroupsTest, TestHappyMultipleResultsCase)
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
        .WillOnce(testing::Return(1))
        .WillOnce(testing::Return(4));

    EXPECT_CALL(*stmt, valueString(1))
        .WillOnce(testing::Return("test_group"))
        .WillOnce(testing::Return("test_group2"))
        .WillOnce(testing::Return("test_group3"));

    TEndpointGetV1AgentsIdsGroups<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"({"data":{"1":["test_group","test_group2"],"4":["test_group3"]}})");
    ASSERT_EQ(queries->size(), 1);
    EXPECT_EQ((*queries)[0],
              "SELECT b.id_agent AS id_agent, g.name AS group_name FROM belongs b JOIN 'group' g ON "
              "b.id_group=g.id WHERE b.id_agent > 0;");

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}

TEST_F(EndpointGetV1AgentIdsGroupsTest, TestNoResultsCase)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    EXPECT_CALL(*stmt, step()).WillOnce(testing::Return(SQLITE_DONE));

    TEndpointGetV1AgentsIdsGroups<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"({})");
    ASSERT_EQ(queries->size(), 1);
    EXPECT_EQ((*queries)[0],
              "SELECT b.id_agent AS id_agent, g.name AS group_name FROM belongs b JOIN 'group' g ON "
              "b.id_group=g.id WHERE b.id_agent > 0;");

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}
