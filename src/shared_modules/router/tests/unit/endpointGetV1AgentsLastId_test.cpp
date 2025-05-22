/*
 * Wazuh router
 * Copyright (C) 2015, Wazuh Inc.
 * May 21, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared_modules/router/src/wazuh-db/endpointGetV1AgentsLastId.hpp"
#include "shared_modules/utils/mocks/sqlite3WrapperMock.hpp"
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Runs unit tests for EndpointGetV1AgentLastIdTest class
 */
class EndpointGetV1AgentLastIdTest : public ::testing::Test
{
protected:
    EndpointGetV1AgentLastIdTest() = default;
    ~EndpointGetV1AgentLastIdTest() override = default;
};

TEST_F(EndpointGetV1AgentLastIdTest, TestHappyCase)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    EXPECT_CALL(*stmt, step()).WillOnce(testing::Return(SQLITE_ROW));

    EXPECT_CALL(*stmt, valueInt64(0)).WillOnce(testing::Return(1));

    TEndpointGetV1AgentsLastId<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"({"last_id":1})");
    ASSERT_EQ(queries->size(), 1);
    EXPECT_EQ((*queries)[0], "SELECT id FROM agent WHERE id > 0 ORDER BY id DESC LIMIT 1");

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}

TEST_F(EndpointGetV1AgentLastIdTest, TestNoResultsCase)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    EXPECT_CALL(*stmt, step()).WillOnce(testing::Return(SQLITE_DONE));

    TEndpointGetV1AgentsLastId<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, "");
    EXPECT_EQ(res.status, 204);
    ASSERT_EQ(queries->size(), 1);
    EXPECT_EQ((*queries)[0], "SELECT id FROM agent WHERE id > 0 ORDER BY id DESC LIMIT 1");

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}
