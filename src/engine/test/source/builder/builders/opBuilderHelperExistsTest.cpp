/* Copyright (C) 2015-2021, Wazuh Inc.
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

TEST(opBuilderHelperExists, Builds)
{
    Document doc{R"({
        "check":
            {"field": "+exists"}
    })"};
    ASSERT_NO_THROW(opBuilderHelperExists(*doc.get("/check")));
}

TEST(opBuilderHelperExists, BuildsOperatesString)
{
    Document doc{R"({
        "check":
            {"field": "+exists"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field":"value"}
            )"});
            s.on_next(Event{R"(
                {"fielda":"values"}
            )"});
            s.on_next(Event{R"(
                {"otherfield":"value"}
            )"});
            s.on_next(Event{R"(
                {"otherfield":1}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperExists(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_TRUE(expected[0].exists("/field"));
}

TEST(opBuilderHelperNotExists, Builds)
{
    Document doc{R"({
        "check":
            {"field": "+not_exists"}
    })"};
    ASSERT_NO_THROW(opBuilderHelperNotExists(*doc.get("/check")));
}

TEST(opBuilderHelperNotExists, BuildsOperatesString)
{
    Document doc{R"({
        "check":
            {"field": "+not_exists"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field":"value"}
            )"});
            s.on_next(Event{R"(
                {"fielda":"values"}
            )"});
            s.on_next(Event{R"(
                {"otherfield":"value"}
            )"});
            s.on_next(Event{R"(
                {"otherfield":1}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperNotExists(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    for (auto e : expected){
    ASSERT_FALSE(e.exists("/field"));
    }
}
