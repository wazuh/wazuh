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

#include "opBuilderMapReference.hpp"

using namespace builder::internals::builders;

TEST(opBuilderMapReference, Builds)
{
    Document doc{R"({
        "normalize":
            {"field": "$other_field"}
    })"};
    ASSERT_NO_THROW(opBuilderMapReference(doc.get("/normalize")));
}

TEST(opBuilderMapReference, BuildsOperates)
{
    Document doc{R"({
        "normalize":
            {"field": "$other_field"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // TODO: Fix json to return false instead of throw
            s.on_next(std::make_shared<json::Document>(R"(
                {"other_field":"referenced"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"values"}
            )"));
            s.on_completed();
        });
    Lifter lift1 = opBuilderMapReference(doc.get("/normalize"));

    Observable output = lift1(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STREQ(expected[0]->get("/field").GetString(), "referenced");
}
