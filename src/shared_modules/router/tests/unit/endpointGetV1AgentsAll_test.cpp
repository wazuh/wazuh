/*
 * Wazuh router
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared_modules/router/src/wazuh-db/endpointGetV1AgentsAll.hpp"
#include "shared_modules/utils/mocks/sqlite3WrapperMock.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::NiceMock;
using ::testing::Return;
using ::testing::Sequence;

/**
 * @brief Tests for the EndpointGetV1AgentsAll class.
 */
class EndpointGetV1AgentsAllTest : public ::testing::Test
{
protected:
    /**
     * @brief Set up the test fixture.
     */
    void SetUp() override
    {
        stmt = std::make_shared<NiceMock<MockSQLiteStatement>>();
        queries = std::make_shared<std::vector<std::string>>();
        TrampolineSQLiteStatement::inject(stmt, queries);

        ON_CALL(*stmt, bindStringView)
            .WillByDefault(
                [](int, std::string_view)
                {
                    // Implement bindStringView logic here.
                });
        ON_CALL(*stmt, bindString)
            .WillByDefault(
                [](int, const std::string&)
                {
                    // Implement bindString logic here.
                });
        ON_CALL(*stmt, bindInt64)
            .WillByDefault(
                [](int, int64_t)
                {
                    // Implement bindInt64 logic here.
                });
        ON_CALL(*stmt, reset)
            .WillByDefault(
                []
                {
                    // Implement reset logic here.
                });

        ON_CALL(*stmt, valueString).WillByDefault(Return("test_value"));
    }

    /**
     * @brief Tear down the test fixture.
     */
    void TearDown() override
    {
        TrampolineSQLiteStatement::inject(nullptr, nullptr);
    }

public:
    std::shared_ptr<NiceMock<MockSQLiteStatement>> stmt; ///< SQLite statement mock
    std::shared_ptr<std::vector<std::string>> queries;   ///< SQLite queries mock
};

TEST_F(EndpointGetV1AgentsAllTest, HappyPathSingleAgent)
{
    Sequence s;
    EXPECT_CALL(*stmt, step()).InSequence(s).WillOnce(Return(SQLITE_ROW)).WillOnce(Return(SQLITE_DONE));

    ON_CALL(*stmt, valueInt64).WillByDefault(Return(1));

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    TEndpointGetV1AgentsAll<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(
        res.body,
        R"([{"id":1,"name":"test_value","ip":"test_value","status":"test_value","os.name":"test_value","os.version":"test_value","os.type":"test_value","os.platform":"test_value","version":"test_value","dateAdd":"test_value","os.major":"test_value","os.minor":"test_value","os.arch":"test_value","node_name":"test_value","lastKeepAlive":"test_value","registerIP":"test_value","disconnection_time":"test_value","status_code":1}])");

    ASSERT_EQ(queries->size(), 1);
    EXPECT_EQ((*queries)[0],
              "SELECT id, name, coalesce(ip, register_ip) as ip, connection_status as status, "
              "os_name, os_version, os_type, os_platform, version, date_add, "
              "os_major, os_minor, os_arch, node_name, last_keepalive, register_ip, "
              "disconnection_time, status_code "
              "FROM agent WHERE id > 0 ORDER BY id ASC;");
}

TEST_F(EndpointGetV1AgentsAllTest, HappyPathMultipleAgents)
{
    Sequence s;
    EXPECT_CALL(*stmt, step())
        .InSequence(s)
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_DONE));

    EXPECT_CALL(*stmt, valueInt64)
        .WillOnce(Return(1))
        .WillOnce(Return(1))
        .WillOnce(Return(2))
        .WillOnce(Return(2))
        .WillOnce(Return(3))
        .WillOnce(Return(3));

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    TEndpointGetV1AgentsAll<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(
        res.body,
        R"([{"id":1,"name":"test_value","ip":"test_value","status":"test_value","os.name":"test_value","os.version":"test_value","os.type":"test_value","os.platform":"test_value","version":"test_value","dateAdd":"test_value","os.major":"test_value","os.minor":"test_value","os.arch":"test_value","node_name":"test_value","lastKeepAlive":"test_value","registerIP":"test_value","disconnection_time":"test_value","status_code":1},{"id":2,"name":"test_value","ip":"test_value","status":"test_value","os.name":"test_value","os.version":"test_value","os.type":"test_value","os.platform":"test_value","version":"test_value","dateAdd":"test_value","os.major":"test_value","os.minor":"test_value","os.arch":"test_value","node_name":"test_value","lastKeepAlive":"test_value","registerIP":"test_value","disconnection_time":"test_value","status_code":2},{"id":3,"name":"test_value","ip":"test_value","status":"test_value","os.name":"test_value","os.version":"test_value","os.type":"test_value","os.platform":"test_value","version":"test_value","dateAdd":"test_value","os.major":"test_value","os.minor":"test_value","os.arch":"test_value","node_name":"test_value","lastKeepAlive":"test_value","registerIP":"test_value","disconnection_time":"test_value","status_code":3}])");

    ASSERT_EQ(queries->size(), 1);
}

TEST_F(EndpointGetV1AgentsAllTest, NoAgents)
{
    EXPECT_CALL(*stmt, step()).WillOnce(Return(SQLITE_DONE));

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    TEndpointGetV1AgentsAll<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"([])");
    ASSERT_EQ(queries->size(), 1);
}
