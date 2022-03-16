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
TEST(opBuilderHelperStringGT, Builds)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_gt/abcd"}
    })"};
    ASSERT_NO_THROW(opBuilderHelperStringGT(doc.get("/check")));
}

// Build incorrect number of arguments
TEST(opBuilderHelperStringGT, Builds_incorrect_number_of_arguments)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_gt/test_value/test_value2"}
    })"};
    ASSERT_THROW(opBuilderHelperStringGT(doc.get("/check")), std::runtime_error);
}

// Test ok: static values
TEST(opBuilderHelperStringGT, Static_string_ok)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_gt/ABCD"}
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

    Lifter lift = opBuilderHelperStringGT(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 5);
    ASSERT_STREQ(expected[0]->get("/field2check").GetString(), "ABCDE");
    ASSERT_STREQ(expected[1]->get("/field2check").GetString(), "BBBB");
    ASSERT_STREQ(expected[2]->get("/field2check").GetString(), "abc");
    ASSERT_STREQ(expected[3]->get("/field2check").GetString(), "abcd");
    ASSERT_STREQ(expected[4]->get("/field2check").GetString(), "abcde");
}

// Test ok: static values (numbers, compare as string)
TEST(opBuilderHelperStringGT, Static_number_ok)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_gt/AA"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // Equal
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"AA"}
            )"));
            // Greater
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2check":"BB"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":"aa"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield": "bb"}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringGT(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->get("/field2check").GetString(), "BB");
}

// Test ok: dynamic values (string)
TEST(opBuilderHelperStringGT, Dynamics_string_ok)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_gt/$ref_key"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // Greater
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field2check":"abcd",
                    "ref_key":"ABCD"
                }
            )"));
            // Equal
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field2check":"ABCD",
                    "ref_key":"ABCD"
                }
            )"));
            // Less
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "otherfield":"AABCD",
                    "ref_key":"ABCD"
                }
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperStringGT(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->get("/field2check").GetString(), "abcd");
}
