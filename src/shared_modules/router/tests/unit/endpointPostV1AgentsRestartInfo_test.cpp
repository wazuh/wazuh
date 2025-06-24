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

#include "shared_modules/router/src/wazuh-db/endpointPostV1AgentsRestartInfo.hpp"
#include "shared_modules/utils/mocks/sqlite3WrapperMock.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::NiceMock;
using ::testing::Return;
using ::testing::Sequence;

/**
 * @brief Tests for the EndpointPostV1AgentsRestartInfo class.
 */
class EndpointPostV1AgentsRestartInfoTest : public ::testing::Test
{
public:
    std::shared_ptr<NiceMock<MockSQLiteStatement>> stmt; ///< SQLite statement mock
    std::shared_ptr<std::vector<std::string>> queries;   ///< SQLite queries mock

protected:
    /**
     * @brief Set up the test fixture.
     */
    void SetUp() override
    {
        stmt = std::make_shared<NiceMock<MockSQLiteStatement>>();
        queries = std::make_shared<std::vector<std::string>>();
        TrampolineSQLiteStatement::inject(stmt, queries);
    }

    /**
     * @brief Tear down the test fixture.
     */
    void TearDown() override
    {
        TrampolineSQLiteStatement::inject(nullptr, nullptr);
    }
};

TEST_F(EndpointPostV1AgentsRestartInfoTest, AllAgents)
{

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    req.body = "";

    Sequence s;

    EXPECT_CALL(*stmt, step())
        .InSequence(s)
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_DONE));

    EXPECT_CALL(*stmt, valueInt64(0))
        .WillOnce(testing::Return(1))
        .WillOnce(testing::Return(2))
        .WillOnce(testing::Return(3));

    EXPECT_CALL(*stmt, valueString(1))
        .WillOnce(testing::Return("v4.13.0"))
        .WillOnce(testing::Return("v4.12.0"))
        .WillOnce(testing::Return("v4.11.0"));

    EXPECT_CALL(*stmt, valueString(2))
        .WillOnce(testing::Return("active"))
        .WillOnce(testing::Return("disconnected"))
        .WillOnce(testing::Return("never_connected"));

    TEndpointPostV1AgentsRestartInfo<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(
        res.body,
        R"({"items":[{"id":1,"version":"v4.13.0","status":"active"},{"id":2,"version":"v4.12.0","status":"disconnected"},{"id":3,"version":"v4.11.0","status":"never_connected"}]})");

    ASSERT_EQ(queries->size(), 1);

    EXPECT_EQ((*queries)[0], "SELECT id, version, connection_status FROM agent;");
}

TEST_F(EndpointPostV1AgentsRestartInfoTest, SomeAgents)
{

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    req.body = R"(
    {
        "ids": [1,3],
        "negate": false
    })";

    Sequence s;

    EXPECT_CALL(*stmt, bindInt64(1, static_cast<int64_t>(1)));
    EXPECT_CALL(*stmt, bindInt64(2, static_cast<int64_t>(3)));

    EXPECT_CALL(*stmt, valueInt64(0)).WillOnce(testing::Return(1)).WillOnce(testing::Return(3));

    EXPECT_CALL(*stmt, valueString(1)).WillOnce(testing::Return("v4.13.0")).WillOnce(testing::Return("v4.11.0"));

    EXPECT_CALL(*stmt, valueString(2)).WillOnce(testing::Return("active")).WillOnce(testing::Return("never_connected"));

    EXPECT_CALL(*stmt, step())
        .InSequence(s)
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_DONE));

    TEndpointPostV1AgentsRestartInfo<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(
        res.body,
        R"({"items":[{"id":1,"version":"v4.13.0","status":"active"},{"id":3,"version":"v4.11.0","status":"never_connected"}]})");

    ASSERT_EQ(queries->size(), 1);

    EXPECT_EQ((*queries)[0], "SELECT id, version, connection_status FROM agent WHERE id IN (?,?);");
}

TEST_F(EndpointPostV1AgentsRestartInfoTest, SomeAgentsNegated)
{

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    req.body = R"(
    {
        "ids": [1,3],
        "negate": true
    })";

    Sequence s;

    EXPECT_CALL(*stmt, bindInt64(1, static_cast<int64_t>(1)));
    EXPECT_CALL(*stmt, bindInt64(2, static_cast<int64_t>(3)));

    EXPECT_CALL(*stmt, valueInt64(0)).WillOnce(testing::Return(2));

    EXPECT_CALL(*stmt, valueString(1)).WillOnce(testing::Return("v4.12.0"));

    EXPECT_CALL(*stmt, valueString(2)).WillOnce(testing::Return("disconnected"));

    EXPECT_CALL(*stmt, step()).InSequence(s).WillOnce(Return(SQLITE_ROW)).WillOnce(Return(SQLITE_DONE));

    TEndpointPostV1AgentsRestartInfo<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"({"items":[{"id":2,"version":"v4.12.0","status":"disconnected"}]})");

    ASSERT_EQ(queries->size(), 1);

    EXPECT_EQ((*queries)[0], "SELECT id, version, connection_status FROM agent WHERE id NOT IN (?,?);");
}

TEST_F(EndpointPostV1AgentsRestartInfoTest, NoAgents)
{

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    req.body = R"(
    {
        "ids": [1,2,3],
        "negate": true
    })";

    Sequence s;

    EXPECT_CALL(*stmt, bindInt64(1, static_cast<int64_t>(1)));
    EXPECT_CALL(*stmt, bindInt64(2, static_cast<int64_t>(2)));
    EXPECT_CALL(*stmt, bindInt64(3, static_cast<int64_t>(3)));

    EXPECT_CALL(*stmt, step()).InSequence(s).WillOnce(Return(SQLITE_DONE));

    TEndpointPostV1AgentsRestartInfo<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"({})");

    ASSERT_EQ(queries->size(), 1);

    EXPECT_EQ((*queries)[0], "SELECT id, version, connection_status FROM agent WHERE id NOT IN (?,?,?);");
}