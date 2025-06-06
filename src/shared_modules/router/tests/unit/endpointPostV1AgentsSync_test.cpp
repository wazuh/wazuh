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

/**
 * @brief Tests for the EndpointPostV1AgentsSync class.
 */
class EndpointPostV1AgentsSyncTest : public ::testing::Test
{
public:
    /**
     * @brief Set up the test fixture.
     */
    void TearDown() override
    {
        TrampolineSQLiteStatement::inject(nullptr, nullptr);
    }

    MockSQLiteConnection db; ///< SQLite connection mock
    httplib::Request req;    ///< HTTP request mock
    httplib::Response res;   ///< HTTP response mock
    std::shared_ptr<std::vector<std::string>> qdump =
        std::make_shared<std::vector<std::string>>(); ///< SQLite queries mock
};

TEST_F(EndpointPostV1AgentsSyncTest, SyncReqTwoAgents)
{
    auto stmt = mockStmt(qdump);

    EXPECT_CALL(*stmt, bindStringView).Times(18 * 2 + 2); // 18 fields * 2 agents + 2 ids
    EXPECT_CALL(*stmt, bindInt64).Times(4 * 2 + 2 + 1);   // 18 fields + 2 ids + 1 for labels
    EXPECT_CALL(*stmt, step()).Times(5);                  // 2 updates + 1 delete + 2 inserts
    EXPECT_CALL(*stmt, reset()).Times(5);                 // 2 updates + 1 delete + 2 inserts

    req.body = R"(
    {
        "syncreq": [
            {
            "config_sum": "x",
            "id": 1,
            "merged_sum": "y",
            "name": "Alice",
            "version": "4.7.0"
            },
            {
            "config_sum": "x2",
            "id": 2,
            "labels": [
                {
                "key": "env",
                "value": "test"
                }
            ],
            "merged_sum": "y2",
            "name": "Bob",
            "version": "4.8.0"
            }
        ]
    })";

    TEndpointPostV1AgentsSync<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    ASSERT_EQ(qdump->size(), 3);
    EXPECT_EQ((*qdump)[0],
              "UPDATE agent SET config_sum = ?, ip = ?, manager_host = ?, merged_sum = ?, name = ?, node_name = ?, "
              "os_arch = ?, os_build = ?, os_codename = ?, os_major = ?, os_minor = ?, os_name = ?, os_platform = ?, "
              "os_uname = ?, os_version = ?, version = ?, last_keepalive = ?, connection_status = ?, "
              "disconnection_time = ?, group_config_status = ?, status_code= ?, sync_status = 'synced' WHERE id = ?;");
    EXPECT_EQ((*qdump)[1], "DELETE FROM labels WHERE id = ?;");
    EXPECT_EQ((*qdump)[2], "INSERT INTO labels (id, key, value) VALUES (?, ?, ?);");
}

TEST_F(EndpointPostV1AgentsSyncTest, KeepAliveThreeAgents)
{
    auto stmt = mockStmt(qdump);

    EXPECT_CALL(*stmt, bindInt64).Times(3);
    EXPECT_CALL(*stmt, step()).Times(3);
    EXPECT_CALL(*stmt, reset()).Times(3);

    nlohmann::json body = R"({"syncreq_keepalive":[10,11,12]})"_json;
    req.body = body.dump();

    TEndpointPostV1AgentsSync<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    ASSERT_EQ(qdump->size(), 1);
    EXPECT_EQ((*qdump)[0],
              "UPDATE agent SET last_keepalive = STRFTIME('%s', 'NOW'),sync_status = 'synced',connection_status = "
              "'active',disconnection_time = 0,status_code = 0 WHERE id = ?;");
}

TEST_F(EndpointPostV1AgentsSyncTest, StatusSingleAgent)
{
    auto stmt = mockStmt(qdump);

    EXPECT_CALL(*stmt, bindStringView).Times(1); // connection_status
    EXPECT_CALL(*stmt, bindInt64).Times(3);      // disconnection_time + status_code + id
    EXPECT_CALL(*stmt, step()).Times(1);

    nlohmann::json body = {
        {"syncreq_status",
         {{{"id", 99}, {"connection_status", "disconnected"}, {"disconnection_time", 12345}, {"status_code", 500}}}}};
    req.body = body.dump();

    TEndpointPostV1AgentsSync<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    ASSERT_EQ(qdump->size(), 1);
    EXPECT_EQ((*qdump)[0],
              "UPDATE agent SET connection_status = ?, sync_status = 'synced', disconnection_time = ?, status_code = ? "
              "WHERE id = ?;");
}
