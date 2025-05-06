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

#include "shared_modules/router/src/wazuh-db/endpointPostV1AgentsSync.hpp"
#include "shared_modules/utils/mocks/sqlite3WrapperMock.hpp"

#include <external/nlohmann/json.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::NiceMock;
using ::testing::Return;

static std::shared_ptr<NiceMock<MockSQLiteStatement>> mockStmt(std::shared_ptr<std::vector<std::string>> qs)
{
    auto s = std::make_shared<NiceMock<MockSQLiteStatement>>();
    TrampolineSQLiteStatement::inject(s, qs);

    ON_CALL(*s, bindString)
        .WillByDefault(
            [](int, const std::string&)
            {
                // Implement bindString logic here.
            });
    ON_CALL(*s, bindStringView)
        .WillByDefault(
            [](int, std::string_view)
            {
                // Implement bindStringView logic here.
            });
    ON_CALL(*s, bindInt64)
        .WillByDefault(
            [](int, int64_t)
            {
                // Implement bindInt32 logic here.
            });
    ON_CALL(*s, bindInt32)
        .WillByDefault(
            [](int, int32_t)
            {
                // Implement bindInt32 logic here.
            });
    ON_CALL(*s, reset).WillByDefault(
        []
        {
            // Implement reset logic here.
        });
    ON_CALL(*s, step).WillByDefault(Return(SQLITE_DONE));
    return s;
}

class EpPostSync : public ::testing::Test
{
public:
    void TearDown() override
    {
        TrampolineSQLiteStatement::inject(nullptr, nullptr);
    }

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;
    std::shared_ptr<std::vector<std::string>> qdump = std::make_shared<std::vector<std::string>>();
};

TEST_F(EpPostSync, SyncReqTwoAgents)
{
    auto stmt = mockStmt(qdump);

    EXPECT_CALL(*stmt, bindStringView).Times(18 * 2);
    EXPECT_CALL(*stmt, bindInt64).Times(4 * 2);
    EXPECT_CALL(*stmt, step()).Times(2);
    EXPECT_CALL(*stmt, reset()).Times(2);

    nlohmann::json body = {
        {"syncreq",
         {{{"id", 1}, {"name", "Alice"}, {"version", "4.7.0"}, {"config_sum", "x"}, {"merged_sum", "y"}},
          {{"id", 2}, {"name", "Bob"}, {"version", "4.8.0"}, {"config_sum", "x2"}, {"merged_sum", "y2"}}}}};
    req.body = body.dump();

    TEndpointPostV1AgentsSync<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    ASSERT_EQ(qdump->size(), 1);
    EXPECT_TRUE((*qdump)[0].find("UPDATE agent SET config_sum") != std::string::npos);
}

TEST_F(EpPostSync, KeepAliveThreeAgents)
{
    auto stmt = mockStmt(qdump);

    EXPECT_CALL(*stmt, bindInt32).Times(3);
    EXPECT_CALL(*stmt, step()).Times(3);
    EXPECT_CALL(*stmt, reset()).Times(3);

    nlohmann::json body = {{"syncreq_keepalive", {{{"id", 10}}, {{"id", 11}}, {{"id", 12}}}}};
    req.body = body.dump();

    TEndpointPostV1AgentsSync<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    ASSERT_EQ(qdump->size(), 1);
    EXPECT_TRUE((*qdump)[0].find("last_keepalive") != std::string::npos);
}

TEST_F(EpPostSync, StatusSingleAgent)
{
    auto stmt = mockStmt(qdump);

    EXPECT_CALL(*stmt, bindStringView).Times(1); // connection_status
    EXPECT_CALL(*stmt, bindInt64).Times(2);      // disconnection_time + status_code
    EXPECT_CALL(*stmt, bindInt32).Times(1);      // id
    EXPECT_CALL(*stmt, step()).Times(1);

    nlohmann::json body = {
        {"syncreq_status",
         {{{"id", 99}, {"connection_status", "disconnected"}, {"disconnection_time", 12345}, {"status_code", 500}}}}};
    req.body = body.dump();

    TEndpointPostV1AgentsSync<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    ASSERT_EQ(qdump->size(), 1);
    EXPECT_TRUE((*qdump)[0].find("connection_status") != std::string::npos);
}
