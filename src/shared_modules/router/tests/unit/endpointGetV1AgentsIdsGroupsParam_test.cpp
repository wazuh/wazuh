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

#include "shared_modules/router/src/wazuh-db/endpointGetV1AgentsIdsGroupsParam.hpp"
#include "shared_modules/utils/mocks/sqlite3WrapperMock.hpp"
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Runs unit tests for EndpointGetV1AgentIdsGroupsParamTest class
 */
class EndpointGetV1AgentIdsGroupsParamTest : public ::testing::Test
{
protected:
    EndpointGetV1AgentIdsGroupsParamTest() = default;
    ~EndpointGetV1AgentIdsGroupsParamTest() override = default;
};

TEST_F(EndpointGetV1AgentIdsGroupsParamTest, TestHappyCase)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    req.path_params["name"] = "test_group";

    EXPECT_CALL(*stmt, step()).WillOnce(testing::Return(SQLITE_ROW)).WillOnce(testing::Return(SQLITE_DONE));

    EXPECT_CALL(*stmt, valueInt64(0)).WillOnce(testing::Return(1));

    EXPECT_CALL(*stmt, bindString(1, "test_group")).Times(1);

    TEndpointGetV1AgentsIdsGroupsParam<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"([1])");
    ASSERT_EQ(queries->size(), 1);
    EXPECT_EQ(
        (*queries)[0],
        "SELECT id_agent FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = ?) AND id_agent > 0;");

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}

TEST_F(EndpointGetV1AgentIdsGroupsParamTest, TestHappyMultipleResultsCase)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    req.path_params["name"] = "test_group";

    EXPECT_CALL(*stmt, step())
        .WillOnce(testing::Return(SQLITE_ROW))
        .WillOnce(testing::Return(SQLITE_ROW))
        .WillOnce(testing::Return(SQLITE_ROW))
        .WillOnce(testing::Return(SQLITE_DONE));

    EXPECT_CALL(*stmt, valueInt64(0))
        .WillOnce(testing::Return(1))
        .WillOnce(testing::Return(2))
        .WillOnce(testing::Return(4));

    EXPECT_CALL(*stmt, bindString(1, "test_group")).Times(1);

    TEndpointGetV1AgentsIdsGroupsParam<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"([1,2,4])");
    ASSERT_EQ(queries->size(), 1);
    EXPECT_EQ(
        (*queries)[0],
        "SELECT id_agent FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = ?) AND id_agent > 0;");

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}

TEST_F(EndpointGetV1AgentIdsGroupsParamTest, TestNoResultsCase)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    req.path_params["name"] = "test_group";

    EXPECT_CALL(*stmt, step()).WillOnce(testing::Return(SQLITE_DONE));

    EXPECT_CALL(*stmt, bindString(1, "test_group")).Times(1);

    TEndpointGetV1AgentsIdsGroupsParam<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"([])");
    ASSERT_EQ(queries->size(), 1);
    EXPECT_EQ(
        (*queries)[0],
        "SELECT id_agent FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = ?) AND id_agent > 0;");

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}

TEST_F(EndpointGetV1AgentIdsGroupsParamTest, TestNoParam)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    TEndpointGetV1AgentsIdsGroupsParam<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"(Missing parameter: name)");
    ASSERT_EQ(queries->size(), 0);

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}
