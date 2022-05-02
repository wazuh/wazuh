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

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg){};

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
        ASSERT_NO_THROW(bld::opBuilderMapValue(*it, tr));
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
            s.on_next(createSharedEvent(R"(
                {"field":"value"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"values"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"otherfield":"value"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"otherfield":1}
            )"));
            s.on_completed();
        });
    Lifter lift1 = bld::opBuilderMapValue(doc.get("/normalize/0"), tr);
    Lifter lift2 = bld::opBuilderMapValue(doc.get("/normalize/1"), tr);
    Lifter lift3 = bld::opBuilderMapValue(doc.get("/normalize/2"), tr);

    Observable output = lift3(lift2(lift1(input)));
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 4);
    for (auto got : expected)
    {
        ASSERT_STREQ(got->getEvent()->get("/mapped/string").GetString(), "value");
        ASSERT_EQ(got->getEvent()->get("/mapped/int").GetInt(), 1);
        ASSERT_TRUE(got->getEvent()->get("/mapped/bool").GetBool());
    }
}

// TODO: Add rest of use cases (int, bool, null)
