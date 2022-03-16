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

#include "opBuilderMapValue.hpp"

using namespace builder::internals::builders;

TEST(opBuilderMapValue, Builds)
{
    Document doc{R"({
        "normalize":[
            {"mapped.string": "value"},
            {"mapped.int": 1},
            {"mapped.bool": true}
        ]
    })"};
    const auto & arr = doc.begin()->value.GetArray();
    for (auto it = arr.Begin(); it != arr.end(); ++it)
    {
        ASSERT_NO_THROW(opBuilderMapValue(*it));
    }
}

TEST(opBuilderMapValue, BuildsOperates)
{
    Document doc{R"({
        "normalize":[
            {"mapped.string": "value"},
            {"mapped.int": 1},
            {"mapped.bool": true}
        ]
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
    Lifter lift1 = opBuilderMapValue(doc.get("/normalize/0"));
    Lifter lift2 = opBuilderMapValue(doc.get("/normalize/1"));
    Lifter lift3 = opBuilderMapValue(doc.get("/normalize/2"));

    Observable output = lift3(lift2(lift1(input)));
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 4);
    for (auto got : expected)
    {
        ASSERT_STREQ(got->get("/mapped/string").GetString(), "value");
        ASSERT_EQ(got->get("/mapped/int").GetInt(), 1);
        ASSERT_TRUE(got->get("/mapped/bool").GetBool());
    }
}

// TODO: Add rest of use cases (int, bool, null)
