/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * Unit tests for the wazuh-db HTTP-over-Unix-socket API endpoints
 * (src/wazuh_db/src/http/). Ported from httplib::Request/Response to
 * wazuh::uds_http::HttpRequest/HttpResponse when wazuh_db moved onto
 * shared_modules/uds_http_server -- that server's router is exact-match only,
 * so the agent_id that GET /v1/agents/:agent_id/groups used to carry as a path
 * parameter now travels in the X-Wazuh-Agent-Id header instead (the path
 * became GET /v1/agents/groups). See wdb_http.cpp.
 *
 * The endpoint classes (TEndpointGetV1AgentsParamGroups, TEndpointPostV1AgentsSync,
 * ...) are header-only and templated on DBConnection/DBStatement, defaulting to
 * SQLite3Wrapper::Connection/Statement but never requiring them: TEndpoint*::call()
 * only ever touches whatever type is substituted in, duck-typed. That is the seam
 * this file uses to exercise the endpoints' real request-handling logic (header
 * validation, JSON body parsing, response serialization) against a hand-fed fake
 * statement instead of a real SQLite database -- no wdb_lib linkage, no real
 * socket, no real transport server needed.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include <uds_http_server/IUdsHttpServer.hpp>

#include "endpointGetV1AgentsAll.hpp"
#include "endpointGetV1AgentsParamGroups.hpp"
#include "endpointGetV1AgentsSync.hpp"
#include "endpointPostV1AgentsSummary.hpp"
#include "endpointPostV1AgentsSync.hpp"

namespace Log
{
    // Storage for the `extern` declared in loggerHelper.h -- deliberately not
    // `inline` there (see its comment), so every binary that pulls the header in
    // (production DSOs and this test binary alike) must provide its own
    // definition. wdb_http.cpp provides it for the real wazuh-manager-db process;
    // this test never calls wdb_http_start(), so nothing ever assigns it, but the
    // symbol still needs to exist for the endpoint headers' logWarn()/logError()
    // calls to link. Left unassigned, isLevelEnabled() treats it as falsy and log
    // calls are silently skipped, which is fine here: this file doesn't test
    // logging output.
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
} // namespace Log

namespace
{
    /// Stands in for SQLite3Wrapper::Connection. TEndpoint*::call() only ever
    /// forwards this by const reference into DBStatement's constructor -- it never
    /// calls anything on it directly -- so it needs no behavior of its own.
    class MockConnection final
    {
    };

    /// Stands in for SQLite3Wrapper::Statement, replaying a canned set of rows
    /// instead of running SQL against a real database. Column values are stored as
    /// a variant so the same fake can back both the string columns
    /// TEndpointGetV1AgentsParamGroups reads and the int64/string mix other
    /// endpoints read, matching the real Statement::value<T>() template.
    ///
    /// NOTE: s_rowsToReturn is shared by every DBStatement constructed during one
    /// call() -- there is no per-query result set. Endpoints that run more than
    /// one query in a single call() (e.g. AgentsSummary, AgentsSync) therefore
    /// need either an empty result set (safe: step() returns SQLITE_DONE
    /// immediately, so no column is ever read) or rows whose shape happens to fit
    /// every query they run. The tests below stick to the empty case for the
    /// multi-query endpoints for exactly that reason.
    class MockStatement final
    {
    public:
        using ColumnValue = std::variant<std::int64_t, std::string>;
        using Row = std::vector<ColumnValue>;

        /// Rows returned by successive step() calls, and the last query text this
        /// statement was constructed with -- set by a test before it invokes
        /// Endpoint::call(), read back afterwards to check what was asked for.
        static std::vector<Row> s_rowsToReturn;
        static std::string s_lastQuery;
        static std::vector<std::int64_t> s_boundInts;
        static std::vector<std::string> s_boundStrings;

        static void resetTestState()
        {
            s_rowsToReturn.clear();
            s_lastQuery.clear();
            s_boundInts.clear();
            s_boundStrings.clear();
        }

        MockStatement(const MockConnection&, std::string_view query)
        {
            s_lastQuery = std::string(query);
        }

        void bind(std::int32_t, std::int32_t value)
        {
            s_boundInts.push_back(value);
        }
        void bind(std::int32_t, std::int64_t value)
        {
            s_boundInts.push_back(value);
        }
        void bind(std::int32_t, std::uint64_t value)
        {
            s_boundInts.push_back(static_cast<std::int64_t>(value));
        }
        void bind(std::int32_t, const std::string& value)
        {
            s_boundStrings.push_back(value);
        }
        void bind(std::int32_t, std::string_view value)
        {
            s_boundStrings.emplace_back(value);
        }
        void bind(std::int32_t, double) {}

        void reset()
        {
            m_rowIndex = 0;
        }

        std::int32_t step()
        {
            if (m_rowIndex < s_rowsToReturn.size())
            {
                m_currentRow = &s_rowsToReturn[m_rowIndex];
                ++m_rowIndex;
                return SQLITE_ROW;
            }
            m_currentRow = nullptr;
            return SQLITE_DONE;
        }

        template<typename T>
        T value(std::int32_t index) const
        {
            return std::get<T>((*m_currentRow)[static_cast<size_t>(index)]);
        }

    private:
        size_t m_rowIndex {0};
        const Row* m_currentRow {nullptr};
    };

    std::vector<MockStatement::Row> MockStatement::s_rowsToReturn;
    std::string MockStatement::s_lastQuery;
    std::vector<std::int64_t> MockStatement::s_boundInts;
    std::vector<std::string> MockStatement::s_boundStrings;

    using TestEndpointGetV1AgentsParamGroups = TEndpointGetV1AgentsParamGroups<MockConnection, MockStatement>;
    using TestEndpointGetV1AgentsAll = TEndpointGetV1AgentsAll<MockConnection, MockStatement>;
    using TestEndpointGetV1AgentsSync = TEndpointGetV1AgentsSync<MockConnection, MockStatement>;
    using TestEndpointPostV1AgentsSummary = TEndpointPostV1AgentsSummary<MockConnection, MockStatement>;
    using TestEndpointPostV1AgentsSync = TEndpointPostV1AgentsSync<MockConnection, MockStatement>;

    class WdbHttpEndpointsTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            MockStatement::resetTestState();
        }
    };
} // namespace

// Basic successful round-trip: GET /v1/agents/groups with a valid
// X-Wazuh-Agent-Id header should query the belongs/group tables (see
// endpointGetV1AgentsParamGroups.hpp's `call()`) and serialize whatever rows
// come back.
//
// The expected body is the bare array, not {"agent_groups": [...]} -- confirmed
// by actually running this test, not assumed from the REFLECTABLE field name.
// Response has exactly one reflected field, and reflectiveJson.hpp's single-arg
// serializeToJSON(obj) special-cases tuple_size==1 (line ~534): it serializes
// only that field's value, skipping the enclosing object and the field's own
// "agent_groups" key entirely. That shortcut is what call() actually uses
// (`HttpResponse::json(200, serializeToJSON(resObj))`), so the real wire
// response for this endpoint is just `["group1","group2"]`.
TEST_F(WdbHttpEndpointsTest, ParamGroupsReturnsGroupsForAgent)
{
    MockStatement::s_rowsToReturn = {
        {std::string("group1")},
        {std::string("group2")},
    };

    MockConnection db;
    wazuh::uds_http::HttpRequest req;
    req.headers["x-wazuh-agent-id"] = "42";

    const auto response = TestEndpointGetV1AgentsParamGroups::call(db, req);

    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(response.body, "[\"group1\",\"group2\"]");

    // The endpoint binds the parsed agent_id (not the raw string) as the query
    // parameter.
    ASSERT_EQ(MockStatement::s_boundInts.size(), 1u);
    EXPECT_EQ(MockStatement::s_boundInts[0], 42);
}

// Error-handling case: a request reaching this endpoint without the
// X-Wazuh-Agent-Id header (malformed/incomplete caller) must be rejected with
// 400 and must never touch the database -- see the
// `if (it == req.headers.end())` guard at the top of
// endpointGetV1AgentsParamGroups.hpp's `call()`, which returns before
// constructing any DBStatement.
TEST_F(WdbHttpEndpointsTest, ParamGroupsMissingAgentIdReturns400WithoutQuerying)
{
    MockConnection db;
    wazuh::uds_http::HttpRequest req; // no "x-wazuh-agent-id" header set

    const auto response = TestEndpointGetV1AgentsParamGroups::call(db, req);

    EXPECT_EQ(response.status, 400);
    EXPECT_EQ(response.body, "Missing header: X-Wazuh-Agent-Id");
    EXPECT_TRUE(MockStatement::s_lastQuery.empty()) << "should not have prepared any statement";
}

// Malformed-request case for the other side of the surface: POST bodies.
// TEndpointPostV1AgentsSync::call() parses the request body with
// nlohmann::json::parse(req.body) unconditionally and without a try/catch (see
// endpointPostV1AgentsSync.hpp) -- registerRoute() in wdb_http.cpp wraps the
// per-route handler in one instead, since uds_http_server has no process-wide
// exception-to-500 fallback of its own. So at the endpoint level an invalid
// JSON body is still expected to propagate out of call() as a real exception.
// This test pins that actual (if perhaps surprising) endpoint-level behavior
// rather than guessing a status code no code path here produces.
TEST_F(WdbHttpEndpointsTest, PostAgentsSyncMalformedJsonBodyThrows)
{
    MockConnection db;
    wazuh::uds_http::HttpRequest req;
    req.body = "{not-valid-json";

    EXPECT_THROW(TestEndpointPostV1AgentsSync::call(db, req), nlohmann::json::parse_error);
}

// GET /v1/agents/all against an empty table: no rows means the query loop never
// runs, so the response is an empty JSON array. Also pins the exact SQL text --
// this endpoint has no other behavior to distinguish a passing test from a
// silently-broken query.
TEST_F(WdbHttpEndpointsTest, GetAllAgentsEmptyDbReturnsEmptyArray)
{
    MockConnection db;
    wazuh::uds_http::HttpRequest req;

    const auto response = TestEndpointGetV1AgentsAll::call(db, req);

    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(response.body, "[]");
    EXPECT_EQ(MockStatement::s_lastQuery,
              "SELECT id, name, coalesce(ip, register_ip) as ip, connection_status as status, "
              "os_name, os_version, os_type, os_platform, version, date_add, "
              "os_major, os_minor, os_arch, last_keepalive, register_ip, "
              "disconnection_time, status_code "
              "FROM agent WHERE id > 0 ORDER BY id ASC;");
}

// GET /v1/agents/sync against an empty table: all three sync-status queries
// return no rows, so the response's three lists all stay empty and (per
// reflectiveJson's NOEMPTY default) are omitted entirely, leaving "{}". The
// final statement call() runs unconditionally is the mark-as-synced UPDATE --
// asserting it ran last confirms that side effect still happens even when there
// was nothing to report.
TEST_F(WdbHttpEndpointsTest, GetAgentsSyncEmptyDbReturnsEmptyObjectAndMarksSynced)
{
    MockConnection db;
    wazuh::uds_http::HttpRequest req;

    const auto response = TestEndpointGetV1AgentsSync::call(db, req);

    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(response.body, "{}");
    EXPECT_EQ(MockStatement::s_lastQuery, "UPDATE agent SET sync_status = 'synced' WHERE id > 0;");
}

// POST /v1/agents/summary with an empty body takes the no-filter branch (top-5
// aggregate queries, see endpointPostV1AgentsSummary.hpp). Against an empty
// table all three aggregates come back empty and are omitted, same NOEMPTY
// behavior as the sync endpoint above.
TEST_F(WdbHttpEndpointsTest, PostAgentsSummaryEmptyBodyEmptyDbReturnsEmptyObject)
{
    MockConnection db;
    wazuh::uds_http::HttpRequest req; // empty body -> no-filter aggregate branch

    const auto response = TestEndpointPostV1AgentsSummary::call(db, req);

    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(response.body, "{}");
    EXPECT_EQ(MockStatement::s_lastQuery,
              "SELECT COUNT(*) as quantity, os_platform AS platform FROM agent WHERE id > 0 "
              "AND os_platform IS NOT NULL AND os_platform <> '' GROUP BY platform ORDER BY quantity DESC limit 5;");
}
