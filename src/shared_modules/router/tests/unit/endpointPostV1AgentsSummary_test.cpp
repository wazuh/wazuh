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
              "b.id_agent > 0  GROUP BY b.id_group ORDER BY q DESC LIMIT 5;");
    EXPECT_EQ((*queries)[2],
              "SELECT COUNT(*) as quantity, os_platform AS platform FROM agent WHERE id > 0 GROUP BY platform ORDER BY "
              "quantity DESC limit 5;");
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
              "b.id_agent > 0;");
    EXPECT_EQ((*queries)[2], "SELECT id, os_platform AS platform FROM agent WHERE id > 0;");
}
