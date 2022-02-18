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

TEST(opBuilderHelperRegexNotMatch, Builds)
{
    Document doc{R"({
        "check":
            {"field": "+r_match/regexp"}
    })"};
    ASSERT_NO_THROW(opBuilderHelperRegexNotMatch(*doc.get("/check")));
}

TEST(opBuilderHelperRegexNotMatch, RegexNotMatch)
{
    Document doc{R"({
        "check":
            {"field": "+r_match/value"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field":"exp"}
            )"});
            s.on_next(Event{R"(
                {"field":"expregex"}
            )"});
            s.on_next(Event{R"(
                {"field":"this is a test exp"}
            )"});
            s.on_next(Event{R"(
                {"field":"value"}
            )"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperRegexNotMatch(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    ASSERT_FALSE(RE2::PartialMatch(expected[0].get("/field")->GetString(), "value"));
    ASSERT_FALSE(RE2::PartialMatch(expected[1].get("/field")->GetString(), "value"));
    ASSERT_FALSE(RE2::PartialMatch(expected[2].get("/field")->GetString(), "value"));
}
