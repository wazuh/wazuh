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

#include "OpBuilderHelperMap.hpp"

using namespace builder::internals::builders;

TEST(opBuilderHelperRegexExtract, Builds)
{
    Document doc{R"({
        "map":
            {"field": "+r_ext/_field/regexp/"}
    })"};
    ASSERT_NO_THROW(opBuilderHelperRegexExtract(*doc.get("/map")));
}

TEST(opBuilderHelperRegexExtract, NotEnoughArgumentsError)
{
    Document doc{R"({
        "map":
            {"field": "+r_ext/_field/"}
    })"};
    ASSERT_THROW(opBuilderHelperRegexExtract(*doc.get("/map")), std::invalid_argument);
}

TEST(opBuilderHelperRegexExtract, TooManyArgumentsError)
{
    Document doc{R"({
        "map":
            {"field": "+r_ext/_field/regexp/arg/"}
    })"};
    ASSERT_THROW(opBuilderHelperRegexExtract(*doc.get("/map")), std::invalid_argument);
}

TEST(opBuilderHelperRegexExtract, StringRegexMatch)
{
    Document doc{R"~~({
        "map":
            {"field": "+r_ext/_field/(exp)/"}
    })~~"};

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
            s.on_completed();
        });

    Lifter lift = opBuilderHelperRegexExtract(*doc.get("/map"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    ASSERT_TRUE(RE2::PartialMatch(expected[0].get("/_field")->GetString(), "exp"));
    ASSERT_TRUE(RE2::PartialMatch(expected[1].get("/_field")->GetString(), "exp"));
    ASSERT_TRUE(RE2::PartialMatch(expected[2].get("/_field")->GetString(), "exp"));
}

TEST(opBuilderHelperRegexExtract, NumericRegexMatch)
{
    Document doc{R"~~({
        "map":
            {"field": "+r_ext/_field/(123)/"}
    })~~"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field":"123"}
            )"});
            s.on_next(Event{R"(
                {"field":"123"}
            )"});
            s.on_next(Event{R"(
                {"field":"123"}
            )"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperRegexExtract(*doc.get("/map"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    ASSERT_TRUE(RE2::PartialMatch(expected[0].get("/_field")->GetString(), "123"));
    ASSERT_TRUE(RE2::PartialMatch(expected[1].get("/_field")->GetString(), "123"));
    ASSERT_TRUE(RE2::PartialMatch(expected[2].get("/_field")->GetString(), "123"));
}

TEST(opBuilderHelperRegexExtract, AdvancedRegexMatch)
{
    Document doc{R"~~({
        "map":
            {"field": "+r_ext/_field/(([^ @]+)@([^ @]+))"}
    })~~"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field":"client@wazuh.com"}
            )"});
            s.on_next(Event{R"(
                {"field":"engine@wazuh.com"}
            )"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperRegexExtract(*doc.get("/map"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
    ASSERT_TRUE(
        RE2::PartialMatch(expected[0].get("/_field")->GetString(), "client@wazuh.com"));
    ASSERT_TRUE(
        RE2::PartialMatch(expected[1].get("/_field")->GetString(), "engine@wazuh.com"));
}

TEST(opBuilderHelperRegexExtract, NestedFieldRegexMatch)
{
    Document doc{R"~~({
        "map":
            {"test/field": "+r_ext/_field/(exp)/"}
    })~~"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"~~({
            "test":
                {"field": "exp"}
            })~~"});
            s.on_next(Event{R"~~({
            "test":
                {"field": "this is a test exp"}
            })~~"});
            s.on_completed();
        });

    Lifter lift = opBuilderHelperRegexExtract(*doc.get("/map"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
    ASSERT_TRUE(RE2::PartialMatch(expected[0].get("/_field")->GetString(), "exp"));
    ASSERT_TRUE(RE2::PartialMatch(expected[1].get("/_field")->GetString(), "exp"));
}
