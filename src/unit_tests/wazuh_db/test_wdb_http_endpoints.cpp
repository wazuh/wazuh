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
 * (src/wazuh_db/src/httpsrv/). Before this file, that directory had zero
 * test coverage anywhere in src/unit_tests/wazuh_db, despite being the
 * implementation behind the documented queue/sockets/wdb-http.sock API
 * (docs/ref/modules/wazuh_db/README.md).
 *
 * The endpoint classes (TEndpointGetV1AgentsParamGroups, TEndpointPostV1AgentsSync,
 * ...) are header-only and templated on DBConnection/DBStatement, defaulting to
 * SQLite3Wrapper::Connection/Statement but never requiring them: TEndpoint*::call()
 * only ever touches whatever type is substituted in, duck-typed. That is the seam
 * this file uses to exercise the endpoints' real request-handling logic (path
 * parameter validation, JSON body parsing, response serialization) against a
 * hand-fed fake statement instead of a real SQLite database -- no wdb_lib linkage,
 * no real socket, no real httpsrv::Server needed.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

#include <httplib.h>

#include "endpointGetV1AgentsParamGroups.hpp"
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

        void bind(std::int32_t, std::int32_t value) { s_boundInts.push_back(value); }
        void bind(std::int32_t, std::int64_t value) { s_boundInts.push_back(value); }
        void bind(std::int32_t, std::uint64_t value) { s_boundInts.push_back(static_cast<std::int64_t>(value)); }
        void bind(std::int32_t, const std::string& value) { s_boundStrings.push_back(value); }
        void bind(std::int32_t, std::string_view value) { s_boundStrings.emplace_back(value); }
        void bind(std::int32_t, double) { }

        void reset() { m_rowIndex = 0; }

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
    using TestEndpointPostV1AgentsSync = TEndpointPostV1AgentsSync<MockConnection, MockStatement>;

    class WdbHttpEndpointsTest : public ::testing::Test
    {
    protected:
        void SetUp() override { MockStatement::resetTestState(); }
    };
} // namespace

// Basic successful round-trip: GET /v1/agents/:agent_id/groups with a valid
// agent_id path parameter should query the belongs/group tables (see
// endpointGetV1AgentsParamGroups.hpp's `call()`) and serialize whatever rows
// come back.
//
// The expected body is the bare array, not {"agent_groups": [...]} -- confirmed
// by actually running this test, not assumed from the REFLECTABLE field name.
// Response has exactly one reflected field, and reflectiveJson.hpp's single-arg
// serializeToJSON(obj) special-cases tuple_size==1 (line ~534): it serializes
// only that field's value, skipping the enclosing object and the field's own
// "agent_groups" key entirely. That shortcut is what call() actually uses
// (`res.set_content(serializeToJSON(resObj), ...)`), so the real wire response
// for this endpoint is just `["group1","group2"]`.
TEST_F(WdbHttpEndpointsTest, ParamGroupsReturnsGroupsForAgent)
{
    MockStatement::s_rowsToReturn = {
        {std::string("group1")},
        {std::string("group2")},
    };

    MockConnection db;
    httplib::Request req;
    req.path_params["agent_id"] = "42";
    httplib::Response res;

    TestEndpointGetV1AgentsParamGroups::call(db, req, res);

    ASSERT_EQ(res.status, -1); // untouched on success: no error path taken
    EXPECT_EQ(res.body, "[\"group1\",\"group2\"]");

    // The endpoint binds the parsed agent_id (not the raw string) as the query
    // parameter.
    ASSERT_EQ(MockStatement::s_boundInts.size(), 1u);
    EXPECT_EQ(MockStatement::s_boundInts[0], 42);
}

// Error-handling case: a request reaching this endpoint without the agent_id
// path parameter (malformed/incomplete routing) must be rejected with 400 and
// must never touch the database -- see the `if (it == req.path_params.end())`
// guard at the top of endpointGetV1AgentsParamGroups.hpp's `call()`, which
// returns before constructing any DBStatement.
TEST_F(WdbHttpEndpointsTest, ParamGroupsMissingAgentIdReturns400WithoutQuerying)
{
    MockConnection db;
    httplib::Request req; // no "agent_id" path param set
    httplib::Response res;

    TestEndpointGetV1AgentsParamGroups::call(db, req, res);

    EXPECT_EQ(res.status, 400);
    EXPECT_EQ(res.body, "Missing parameter: id");
    EXPECT_TRUE(MockStatement::s_lastQuery.empty()) << "should not have prepared any statement";
}

// Malformed-request case for the other side of the surface: POST bodies.
// TEndpointPostV1AgentsSync::call() parses the request body with
// nlohmann::json::parse(req.body) unconditionally and without a try/catch (see
// endpointPostV1AgentsSync.hpp) -- registerRoute() in wdb_http.cpp doesn't wrap
// the per-route handler in one either, so an invalid JSON body is expected to
// propagate out of call() as a real exception, not to be swallowed into a 4xx
// response. This test pins that actual (if perhaps surprising) behavior rather
// than guessing a status code no code path here produces.
TEST_F(WdbHttpEndpointsTest, PostAgentsSyncMalformedJsonBodyThrows)
{
    MockConnection db;
    httplib::Request req;
    req.body = "{not-valid-json";
    httplib::Response res;

    EXPECT_THROW(TestEndpointPostV1AgentsSync::call(db, req, res), nlohmann::json::parse_error);
}
