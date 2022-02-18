/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#include <gtest/gtest.h>
#include <testUtils.hpp>
#include <vector>

#include "OpBuilderHelperFilter.hpp"

using namespace builder::internals::builders;

// Build ok
TEST(opBuilderHelperS_eq, Builds)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_eq/test_value"}
    })"};
    ASSERT_NO_THROW(opBuilderHelperS_eq(*doc.get("/check")));
}

// Build incorrect number of arguments
TEST(opBuilderHelperS_eq, BuildsIncorrectNumberOfArguments)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_eq/test_value/test_value2"}
    })"};
    ASSERT_THROW(opBuilderHelperS_eq(*doc.get("/check")), std::runtime_error);
}

// Test ok: static values
TEST(opBuilderHelperS_eq, BuildsOk)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_eq/test_value"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field2check":"not_test_value"}
            )"});
            s.on_next(Event{R"(
                {"field2check":"test_value"}
            )"});
            s.on_next(Event{R"(
                {"otherfield":"value"}
            )"});
            s.on_next(Event{R"(
                {"otherfield":"test_value"}
            )"});
            s.on_next(Event{R"(
                {"field2check":"test_value"}
            )"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperS_eq(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
    ASSERT_STREQ(expected[0].get("/field2check")->GetString(), "test_value");
    ASSERT_STREQ(expected[1].get("/field2check")->GetString(), "test_value");
}

// Test ok: static values (numbers, compare as string)
TEST(opBuilderHelperS_eq, BuildsOkNumbers)
{
    Document doc{R"({
        "check":
            {"field2check": "+s_eq/11"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field2check":"not_11"}
            )"});
            s.on_next(Event{R"(
                {"field2check":"11"}
            )"});
            s.on_next(Event{R"(
                {"otherfield":"11"}
            )"});
            s.on_next(Event{R"(
                {"otherfield":11}
            )"});
            s.on_next(Event{R"(
                {"field2check":"11"}
            )"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperS_eq(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
    ASSERT_STREQ(expected[0].get("/field2check")->GetString(), "11");
    ASSERT_STREQ(expected[1].get("/field2check")->GetString(), "11");
}

// Test ok: dynamic values (string)

// Test ok: dynamic values (numbers, compare as string)


