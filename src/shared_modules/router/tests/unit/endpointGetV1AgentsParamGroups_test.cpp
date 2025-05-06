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

#include "shared_modules/router/src/wazuh-db/endpointGetV1AgentsParamGroups.hpp"
#include "shared_modules/utils/mocks/sqlite3WrapperMock.hpp"
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Runs unit tests for EndpointGetV1AgentParamGroupsTest class
 */
class EndpointGetV1AgentParamGroupsTest : public ::testing::Test
{
protected:
    EndpointGetV1AgentParamGroupsTest() = default;
    ~EndpointGetV1AgentParamGroupsTest() override = default;
};

TEST_F(EndpointGetV1AgentParamGroupsTest, TestHappyCase)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    req.path_params["agent_id"] = "1";

    EXPECT_CALL(*stmt, step()).WillOnce(testing::Return(SQLITE_ROW)).WillOnce(testing::Return(SQLITE_DONE));
    EXPECT_CALL(*stmt, bindInt32(1, 1)).Times(1);

    EXPECT_CALL(*stmt, valueString(0)).WillOnce(testing::Return("test_group"));

    TEndpointGetV1AgentsParamGroups<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"(["test_group"])");
    ASSERT_EQ(queries->size(), 1);
    EXPECT_EQ((*queries)[0],
              "SELECT name FROM belongs JOIN `group` ON id = id_group WHERE id_agent = ? order by priority");

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}

TEST_F(EndpointGetV1AgentParamGroupsTest, TestHappyMultipleResultsCase)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    req.path_params["agent_id"] = "1";

    EXPECT_CALL(*stmt, step())
        .WillOnce(testing::Return(SQLITE_ROW))
        .WillOnce(testing::Return(SQLITE_ROW))
        .WillOnce(testing::Return(SQLITE_ROW))
        .WillOnce(testing::Return(SQLITE_DONE));
    EXPECT_CALL(*stmt, bindInt32(1, 1)).Times(1);

    EXPECT_CALL(*stmt, valueString(0))
        .WillOnce(testing::Return("test_group"))
        .WillOnce(testing::Return("test_group2"))
        .WillOnce(testing::Return("test_group3"));

    TEndpointGetV1AgentsParamGroups<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"(["test_group","test_group2","test_group3"])");
    ASSERT_EQ(queries->size(), 1);
    EXPECT_EQ((*queries)[0],
              "SELECT name FROM belongs JOIN `group` ON id = id_group WHERE id_agent = ? order by priority");

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}

TEST_F(EndpointGetV1AgentParamGroupsTest, TestNoResultsCase)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    req.path_params["agent_id"] = "1";

    EXPECT_CALL(*stmt, step()).WillOnce(testing::Return(SQLITE_DONE));
    EXPECT_CALL(*stmt, bindInt32(1, 1)).Times(1);

    TEndpointGetV1AgentsParamGroups<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"([])");
    ASSERT_EQ(queries->size(), 1);
    EXPECT_EQ((*queries)[0],
              "SELECT name FROM belongs JOIN `group` ON id = id_group WHERE id_agent = ? order by priority");

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}

TEST_F(EndpointGetV1AgentParamGroupsTest, TestNoParam)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    TEndpointGetV1AgentsParamGroups<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"(Missing parameter: id)");
    ASSERT_EQ(queries->size(), 0);

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}

TEST_F(EndpointGetV1AgentParamGroupsTest, TestInvalidType)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    req.path_params["agent_id"] = "asdfgh";

    EXPECT_ANY_THROW(
        (TEndpointGetV1AgentsParamGroups<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res)));

    ASSERT_EQ(queries->size(), 1);
    EXPECT_EQ((*queries)[0],
              "SELECT name FROM belongs JOIN `group` ON id = id_group WHERE id_agent = ? order by priority");

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}
