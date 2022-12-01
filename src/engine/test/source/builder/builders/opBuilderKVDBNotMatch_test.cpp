/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <vector>

#include <gtest/gtest.h>

#include "opBuilderKVDB.hpp"
#include "testUtils.hpp"
#include <kvdb/kvdbManager.hpp>

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg){};

namespace
{
class opBuilderKVDBNotMatchTest : public ::testing::Test
{

protected:
    KVDBManager& kvdbManager = KVDBManager::get();

    virtual void SetUp()
    {
        kvdbManager.loadDb("TEST_DB");
    }

    virtual void TearDown()
    {
        kvdbManager.deleteDB("TEST_DB");
    }
};

// Build ok
TEST_F(opBuilderKVDBNotMatchTest, Builds)
{
    Document doc {R"({
        "check":
            {"field2match": "+kvdb_not_match/TEST_DB"}
    })"};
    ASSERT_NO_THROW(bld::opBuilderKVDBNotMatch(doc.get("/check"), tr));
}

// Build incorrect number of arguments
TEST_F(opBuilderKVDBNotMatchTest, Builds_incorrect_number_of_arguments)
{
    Document doc {R"({
        "check":
            {"field2match": "+kvdb_not_match"}
    })"};
    ASSERT_THROW(bld::opBuilderKVDBNotMatch(doc.get("/check"), tr),
                 std::runtime_error);
}

// Build invalid DB
TEST_F(opBuilderKVDBNotMatchTest, Builds_incorrect_invalid_db)
{
    Document doc {R"({
        "check":
            {"field2match": "+kvdb_not_match/INVALID_DB"}
    })"};
    ASSERT_THROW(bld::opBuilderKVDBNotMatch(doc.get("/check"), tr),
                 std::runtime_error);
}

// Test ok: static values
TEST_F(opBuilderKVDBNotMatchTest, Static_string_ok)
{
    // Set Up KVDB
    auto kvdb = kvdbManager.getDB("TEST_DB");
    kvdb->writeKeyOnly("KEY");

    Document doc {R"({
        "check":
            {"field2match": "+kvdb_match/TEST_DB"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field2match":"KEY"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field2match":"INEXISTENT_KEY"}
            )"));
            // Other fields will be ignored
            s.on_next(createSharedEvent(R"(
                {"otherfield":"KEY"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderKVDBNotMatch(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_STREQ(expected[0]->getEvent()->get("/field2match").GetString(),
                 "INEXISTENT_KEY");
    ASSERT_STREQ(expected[1]->getEvent()->get("/otherfield").GetString(), "KEY");
}

TEST_F(opBuilderKVDBNotMatchTest, Multilevel_target)
{
    auto kvdb = kvdbManager.getDB("TEST_DB");
    kvdb->writeKeyOnly("KEY");

    Document doc {R"({
        "check":
            {"a.b.field2match": "+kvdb_not_match/TEST_DB"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"a": {"b":{"field2match":"KEY"}}}
            )"));
            s.on_next(createSharedEvent(R"(
                {"a": {"b":{"field2match":"INEXISTENT_KEY"}}}
            )"));
            // Other fields will continue
            s.on_next(createSharedEvent(R"(
                {"a": {"b":{"otherfield":"KEY"}}}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderKVDBNotMatch(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_STREQ(expected[0]->getEvent()->get("/a/b/field2match").GetString(),
                 "INEXISTENT_KEY");
    ASSERT_STREQ(expected[1]->getEvent()->get("/a/b/otherfield").GetString(), "KEY");
}

} // namespace
