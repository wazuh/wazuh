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

#include "shared_modules/router/src/wazuh-db/endpointPostV1AgentsSummary.hpp"
#include "shared_modules/utils/mocks/sqlite3WrapperMock.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::HasSubstr;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::Sequence;

/**
 * @brief Tests for the EndpointPostV1AgentsSummary class.
 */
class EndpointPostV1AgentsSummaryTest : public ::testing::Test
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

        ON_CALL(*stmt, bindStringView)
            .WillByDefault(
                [](int, std::string_view)
                {
                    // Implement bindStringView logic here.
                });
        ON_CALL(*stmt, reset)
            .WillByDefault(
                []
                {
                    // Implement reset logic here.
                });

        ON_CALL(*stmt, valueString).WillByDefault(Return("dummy"));
        ON_CALL(*stmt, valueInt64).WillByDefault(Return(1));
    }

    /**
     * @brief Tear down the test fixture.
     */
    void TearDown() override
    {
        TrampolineSQLiteStatement::inject(nullptr, nullptr);
    }
};

TEST_F(EndpointPostV1AgentsSummaryTest, NoFilterHappyCase)
{
    Sequence s;
    EXPECT_CALL(*stmt, step())
        .InSequence(s)
        // status
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_DONE))
        // groups
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_DONE))
        // os
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_DONE));

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    TEndpointPostV1AgentsSummary<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body,
              R"({"agents_by_status":{"dummy":1},"agents_by_groups":{"dummy":1},"agents_by_os":{"dummy":1}})");

    ASSERT_EQ(queries->size(), 3);

    EXPECT_EQ((*queries)[0],
              "SELECT COUNT(*) as quantity, connection_status AS status FROM agent WHERE id > 0 GROUP BY status ORDER "
              "BY status ASC limit 5;");
    EXPECT_EQ((*queries)[1],
              "SELECT COUNT(*) as q, g.name AS group_name FROM belongs b JOIN 'group' g ON b.id_group=g.id WHERE "
              "b.id_agent > 0 AND g.name IS NOT NULL AND g.name <> '' GROUP BY b.id_group ORDER BY q DESC LIMIT 5;");
    EXPECT_EQ((*queries)[2],
              "SELECT COUNT(*) as quantity, os_platform AS platform FROM agent WHERE id > 0 "
              "AND os_platform IS NOT NULL AND os_platform <> '' GROUP BY platform ORDER BY quantity DESC limit 5;");
}

TEST_F(EndpointPostV1AgentsSummaryTest, NoFilter_ShouldIgnoreNullAndEmptyGroups)
{
    Sequence s;
    EXPECT_CALL(*stmt, step())
        .InSequence(s)
        // status - Doesn't matter for this test
        .WillOnce(Return(SQLITE_DONE))
        // groups - The important part
        .WillOnce(Return(SQLITE_ROW))  // Group "prod"
        .WillOnce(Return(SQLITE_ROW))  // Group "dev"
        .WillOnce(Return(SQLITE_DONE)) // End of groups
        // os - Doesn't matter for this test
        .WillOnce(Return(SQLITE_DONE));

    // Define the return values for the groups query
    EXPECT_CALL(*stmt, valueInt64(0))
        .WillOnce(Return(10)) // 10 agents in "prod"
        .WillOnce(Return(5)); // 5 agents in "dev"
    EXPECT_CALL(*stmt, valueString(1)).WillOnce(Return("prod")).WillOnce(Return("dev"));

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    TEndpointPostV1AgentsSummary<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    // Verify that the query contains the new filter
    ASSERT_EQ(queries->size(), 3);
    EXPECT_THAT((*queries)[1], HasSubstr("g.name IS NOT NULL AND g.name <> ''"));

    // Verify that the response body is correct
    EXPECT_EQ(res.body, R"({"agents_by_groups":{"dev":5,"prod":10}})");
}

TEST_F(EndpointPostV1AgentsSummaryTest, Filtered_ShouldIgnoreNullAndEmptyGroups)
{
    Sequence s;
    EXPECT_CALL(*stmt, step())
        .InSequence(s)
        // connections - Doesn't matter for this test
        .WillOnce(Return(SQLITE_DONE))
        // groups - The important part
        .WillOnce(Return(SQLITE_ROW))  // Agent 1 in "prod"
        .WillOnce(Return(SQLITE_ROW))  // Agent 2 in "dev"
        .WillOnce(Return(SQLITE_DONE)) // End of groups
        // os - Doesn't matter for this test
        .WillOnce(Return(SQLITE_DONE));

    // Define the return values for the groups query
    EXPECT_CALL(*stmt, valueInt64(0))
        .WillOnce(Return(1))  // Agent ID 1
        .WillOnce(Return(2)); // Agent ID 2
    EXPECT_CALL(*stmt, valueString(1)).WillOnce(Return("prod")).WillOnce(Return("dev"));

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;
    // We request agents 1, 2, and 3. Agent 3 would be in a null/empty group and should be filtered out by the query.
    req.body = "1,2,3";

    TEndpointPostV1AgentsSummary<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    // Verify that the query contains the new filter
    ASSERT_EQ(queries->size(), 3);
    EXPECT_THAT((*queries)[1], HasSubstr("g.name IS NOT NULL AND g.name <> ''"));

    // Verify that the response body is correct, containing only the valid groups for the requested agents
    EXPECT_EQ(res.body, R"({"agents_by_groups":{"dev":1,"prod":1}})");
}

TEST_F(EndpointPostV1AgentsSummaryTest, NoFilter_ShouldIgnoreNullAndEmptyOsPlatform)
{
    Sequence s;
    EXPECT_CALL(*stmt, step())
        .InSequence(s)
        // status - Doesn't matter for this test
        .WillOnce(Return(SQLITE_DONE))
        // groups - Doesn't matter for this test
        .WillOnce(Return(SQLITE_DONE))
        // os - The important part
        .WillOnce(Return(SQLITE_ROW))   // Platform "linux"
        .WillOnce(Return(SQLITE_ROW))   // Platform "windows"
        .WillOnce(Return(SQLITE_DONE)); // End of platforms

    // Define the return values for the OS query
    EXPECT_CALL(*stmt, valueInt64(0))
        .WillOnce(Return(15)) // 15 agents with "linux"
        .WillOnce(Return(8)); // 8 agents with "windows"
    EXPECT_CALL(*stmt, valueString(1)).WillOnce(Return("linux")).WillOnce(Return("windows"));

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    TEndpointPostV1AgentsSummary<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    // Verify that the query contains the new filter
    ASSERT_EQ(queries->size(), 3);
    EXPECT_THAT((*queries)[2], HasSubstr("os_platform IS NOT NULL AND os_platform <> ''"));

    // Verify that the response body is correct
    EXPECT_EQ(res.body, R"({"agents_by_os":{"linux":15,"windows":8}})");
}

TEST_F(EndpointPostV1AgentsSummaryTest, Filtered_ShouldIgnoreNullAndEmptyOsPlatform)
{
    Sequence s;
    EXPECT_CALL(*stmt, step())
        .InSequence(s)
        // connections - Doesn't matter for this test
        .WillOnce(Return(SQLITE_DONE))
        // groups - Doesn't matter for this test
        .WillOnce(Return(SQLITE_DONE))
        // os - The important part
        .WillOnce(Return(SQLITE_ROW))   // Agent 1 with "linux"
        .WillOnce(Return(SQLITE_ROW))   // Agent 2 with "windows"
        .WillOnce(Return(SQLITE_DONE)); // End of platforms

    // Define the return values for the OS query
    EXPECT_CALL(*stmt, valueInt64(0))
        .WillOnce(Return(1))  // Agent ID 1
        .WillOnce(Return(2)); // Agent ID 2
    EXPECT_CALL(*stmt, valueString(1)).WillOnce(Return("linux")).WillOnce(Return("windows"));

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;
    // We request agents 1, 2, and 3. Agent 3 would have null/empty os_platform and should be filtered out by the query.
    req.body = "1,2,3";

    TEndpointPostV1AgentsSummary<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    // Verify that the query contains the new filter
    ASSERT_EQ(queries->size(), 3);
    EXPECT_THAT((*queries)[2], HasSubstr("os_platform IS NOT NULL AND os_platform <> ''"));

    // Verify that the response body is correct, containing only the valid OS platforms for the requested agents
    EXPECT_EQ(res.body, R"({"agents_by_os":{"linux":1,"windows":1}})");
}

TEST_F(EndpointPostV1AgentsSummaryTest, FilteredHappyCase)
{
    Sequence s;
    EXPECT_CALL(*stmt, step())
        .InSequence(s)
        // connections
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_DONE))
        // groups
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_DONE))
        // os
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_DONE));

    int idCounter = 0;
    ON_CALL(*stmt, valueInt64)
        .WillByDefault(
            [&idCounter](int)
            {
                std::array<int, 4> ids = {1, 99, 1, 1};
                return ids[idCounter++ % 4];
            });

    ON_CALL(*stmt, valueString).WillByDefault([](int) { return std::string("v"); });

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;
    req.body = "1,2,5";

    TEndpointPostV1AgentsSummary<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    EXPECT_EQ(res.body, R"({"agents_by_status":{"v":1},"agents_by_groups":{"v":1},"agents_by_os":{"v":1}})");

    ASSERT_EQ(queries->size(), 3);
    EXPECT_EQ((*queries)[0], "SELECT id, connection_status AS status FROM agent WHERE id > 0;");
    EXPECT_EQ((*queries)[1],
              "SELECT b.id_agent, g.name AS group_name FROM belongs b JOIN 'group' g ON b.id_group=g.id WHERE "
              "b.id_agent > 0 AND g.name IS NOT NULL AND g.name <> '';");
    EXPECT_EQ((*queries)[2],
              "SELECT id, os_platform AS platform FROM agent WHERE id > 0 AND os_platform IS NOT NULL AND os_platform "
              "<> '';");
}

TEST_F(EndpointPostV1AgentsSummaryTest, GroupSummaryFromQuery)
{
    Sequence s;
    EXPECT_CALL(*stmt, step())
        .InSequence(s)
        // status - empty
        .WillOnce(Return(SQLITE_DONE))
        // groups
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_ROW))
        .WillOnce(Return(SQLITE_DONE))
        // os - empty
        .WillOnce(Return(SQLITE_DONE));

    EXPECT_CALL(*stmt, valueInt64(0)).WillOnce(Return(10)).WillOnce(Return(5)).WillOnce(Return(5)).WillOnce(Return(4));

    EXPECT_CALL(*stmt, valueString(1))
        .WillOnce(Return("default"))
        .WillOnce(Return("group1"))
        .WillOnce(Return("group2"))
        .WillOnce(Return("group3"));

    MockSQLiteConnection db;
    httplib::Request req;
    httplib::Response res;

    TEndpointPostV1AgentsSummary<MockSQLiteConnection, TrampolineSQLiteStatement>::call(db, req, res);

    // Verify that the query contains the new filter
    ASSERT_EQ(queries->size(), 3);
    EXPECT_THAT((*queries)[1],
                "SELECT COUNT(*) as q, g.name AS group_name FROM belongs b JOIN 'group' g ON b.id_group=g.id WHERE "
                "b.id_agent > 0 AND g.name IS NOT NULL AND g.name <> '' GROUP BY b.id_group ORDER BY q DESC LIMIT 5;");

    // Verify that the response body is correct
    EXPECT_EQ(res.body, R"({"agents_by_groups":{"default":10,"group1":5,"group2":5,"group3":4}})");
}
