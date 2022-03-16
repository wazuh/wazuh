/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include "testUtils.hpp"
#include <vector>

#include "opBuilderHelperFilter.hpp"

using namespace builder::internals::builders;

// Build ok
TEST(opBuilderHelperStringLE, Builds)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_le/abcd"}
    })"};
    ASSERT_NO_THROW(opBuilderHelperStringLE(doc.get("/check")));
}

// Build incorrect number of arguments
TEST(opBuilderHelperStringLE, Builds_incorrect_number_of_arguments)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_le/test_value/test_value2"}
    })"};
    ASSERT_THROW(opBuilderHelperStringLE(doc.get("/check")), std::runtime_error);
}

// Test ok: static values
TEST(opBuilderHelperStringLE, Static_string_ok)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_le/ABCD"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // less
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"ABC"}
            )"));
            // Equal
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"ABCD"}
            )"));
            // Greater
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"ABCDE"}
            )"));
            // Greater with different case
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"BBBB"}
            )"));
            // Less with different case
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"AABCD"}
            )"));
            // lower case are greater
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"abc"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"abcd"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"abcde"}
            )"));
            // Other fields will be ignored
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":"abcd"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":"abcd"}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringLE(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STREQ(expected[0]->get("/field2check").GetString(), "ABC");
    ASSERT_STREQ(expected[1]->get("/field2check").GetString(), "ABCD");
    ASSERT_STREQ(expected[2]->get("/field2check").GetString(), "AABCD");
}

// Test ok: static values (numbers, compare as string)
TEST(opBuilderHelperStringLE, Static_number_ok)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_le/50"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // Less
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"499"}
            )"));
            // Equal
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"50"}
            )"));
            // Greater
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":"51"}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringLE(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
    ASSERT_STREQ(expected[0]->get("/field2check").GetString(), "499");
    ASSERT_STREQ(expected[1]->get("/field2check").GetString(), "50");
}

// Test ok: dynamic values (string)
TEST(opBuilderHelperStringLE, Dynamics_string_ok)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_le/$ref_key"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // Less
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field2check":"ABCD",
                    "ref_key":"abcd"
                }
            )"));
            // Equal
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field2check":"ABCD",
                    "ref_key":"ABCD"
                }
            )"));
            // GREATER
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "otherfield":"abcd",
                    "ref_key":"ABCD"
                }
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringLE(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
    ASSERT_STREQ(expected[0]->get("/field2check").GetString(), "ABCD");
    ASSERT_STREQ(expected[1]->get("/field2check").GetString(), "ABCD");
}
