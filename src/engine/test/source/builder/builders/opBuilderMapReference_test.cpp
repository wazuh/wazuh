/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "testUtils.hpp"

#include <vector>

#include "opBuilderMapReference.hpp"

#include <gtest/gtest.h>

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg) {
};


TEST(opBuilderMapReference, Builds)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "field": "$other_field"
                }
            }
        ]
    })"};
    ASSERT_NO_THROW(bld::opBuilderMapReference(doc.get("/normalize/0/map"), tr));
}

TEST(opBuilderMapReference, BuildsOperates)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "field": "$other_field"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // TODO: Fix json to return false instead of throw
            s.on_next(createSharedEvent(R"(
                {"other_field":"referenced"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"value"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"values"}
            )"));
            s.on_completed();
        });
    Lifter lift1 = bld::opBuilderMapReference(doc.get("/normalize/0/map"), tr);

    Observable output = lift1(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STREQ(expected[0]->getEvent()->get("/field").GetString(), "referenced");
}
