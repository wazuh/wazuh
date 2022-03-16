/* Copyright (C) 2015-2021, Wazuh Inc.
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

#include "opBuilderConditionReference.hpp"

using namespace builder::internals::builders;

TEST(opBuilderConditionReference, Builds)
{
    Document doc{R"({
        "check":
            {"field": "$reference"}
    })"};
    ASSERT_NO_THROW(opBuilderConditionReference(doc.get("/check")));
}

TEST(opBuilderConditionReference, BuildsOperatesString)
{
    Document doc{R"({
        "check":
            {"otherfield": "$field"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field":"value1",
                    "otherfield":"value1"
                }
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field":"value1",
                    "otherfield":"value2"
                }
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "otherfield":"value1"
                }
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {
                    "field":"value1"
                }
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderConditionReference(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->get("/field").GetString(), "value1");
    ASSERT_STREQ(expected[0]->get("/otherfield").GetString(), "value1");
}

// TODO: Add rest of use cases (int, bool, null)
