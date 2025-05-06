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

#include "shared_modules/router/src/wazuh-db/endpointGetV1AgentsSync.hpp"
#include "shared_modules/utils/mocks/sqlite3WrapperMock.hpp"
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Runs unit tests for EndpointGetV1AgentSyncTest class
 */
class EndpointGetV1AgentSyncTest : public ::testing::Test
{
protected:
    EndpointGetV1AgentSyncTest() = default;
    ~EndpointGetV1AgentSyncTest() override = default;
};

TEST_F(EndpointGetV1AgentSyncTest, TestHappyCase)
{
    auto stmt = std::make_shared<MockSQLiteStatement>();
    auto queries = std::make_shared<std::vector<std::string>>();
    TrampolineSQLiteStatement::inject(stmt, queries);

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    EXPECT_CALL(*stmt, bindString(1, "syncreq")).Times(1);
    EXPECT_CALL(*stmt, step()).WillOnce(testing::Return(SQLITE_ROW)).WillOnce(testing::Return(SQLITE_DONE));

    // Size to reserve for the vector
    EXPECT_CALL(*stmt, valueInt64(0)).WillOnce(testing::Return(1));

    EXPECT_CALL(*stmt, step()).WillOnce(testing::Return(SQLITE_ROW)).WillOnce(testing::Return(SQLITE_DONE));

    EXPECT_CALL(*stmt, valueString(0)).WillOnce(testing::Return("test_group"));

    TEndpointGetV1AgentsSync<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"(["test_group"])");
    ASSERT_EQ(queries->size(), 2);
    EXPECT_EQ((*queries)[0], "SELECT COUNT(*) FROM agent WHERE id > 0 AND sync_status = ?;");
    EXPECT_EQ((*queries)[1],
              "SELECT id, name, ip, os_name, os_version, os_major, os_minor, os_codename, os_build, os_platform, "
              "os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, last_keepalive, "
              "connection_status, disconnection_time, group_config_status, status_code FROM agent WHERE id > 0 AND "
              "sync_status = 'syncreq';");

    TrampolineSQLiteStatement::inject(nullptr, nullptr);
}

TEST_F(EndpointGetV1AgentSyncTest, TestNoResultsCase)
{
    // auto stmt = std::make_shared<MockSQLiteStatement>();
    // auto queries = std::make_shared<std::vector<std::string>>();
    // TrampolineSQLiteStatement::inject(stmt, queries);

    // MockSQLiteConnection db;
    // httplib::Request req;
    // httplib::Response res;

    // req.path_params["agent_id"] = "1";

    // EXPECT_CALL(*stmt, step()).WillOnce(testing::Return(SQLITE_DONE));
    // EXPECT_CALL(*stmt, bindInt32(1, 1)).Times(1);

    // TEndpointGetV1AgentsSync<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    // EXPECT_EQ(res.body, R"([])");
    // ASSERT_EQ(queries->size(), 1);
    // EXPECT_EQ((*queries)[0],
    //           "SELECT name FROM belongs JOIN `group` ON id = id_group WHERE id_agent = ? order by priority");

    // TrampolineSQLiteStatement::inject(nullptr, nullptr);
}
