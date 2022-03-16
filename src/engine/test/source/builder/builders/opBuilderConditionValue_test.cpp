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

#include "opBuilderConditionValue.hpp"

using namespace builder::internals::builders;

TEST(opBuilderConditionValue, Builds)
{
    Document doc{R"({
        "check": [
            {"string": "value"},
            {"int": 1},
            {"bool": true}
        ]
    })"};
    const auto & arr = doc.begin()->value.GetArray();
    for (auto it = arr.Begin(); it != arr.end(); ++it)
    {
        ASSERT_NO_THROW(opBuilderConditionValue(*it));
    }
}

TEST(opBuilderConditionValue, BuildsOperatesString)
{
    Document doc{R"({
        "check":
            {"field": "value"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"values"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":"value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"otherfield":1}
            )"));
            s.on_completed();
        });
    Lifter lift = opBuilderConditionValue(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->get("/field").GetString(), doc.get("/check").MemberBegin()->value.GetString());
}

//TODO: Add rest of use cases (int, bool, null)
