/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <vector>

#include <re2/re2.h>

#include <baseTypes.hpp>

#include "opBuilderHelperFilter.hpp"
#include "testUtils.hpp"


using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg){};

TEST(opBuilderHelperRegexNotMatch, Builds)
{
    Document doc{R"({
        "check":
            {"field": "+r_not_match/regexp"}
    })"};

    ASSERT_NO_THROW(bld::opBuilderHelperRegexNotMatch(doc.get("/check"), tr));
}

TEST(opBuilderHelperRegexNotMatch, NotEnoughArgumentsError)
{
    Document doc{R"({
        "check":
            {"field": "+r_not_match/"}
    })"};

    ASSERT_THROW(bld::opBuilderHelperRegexNotMatch(doc.get("/check"), tr), std::runtime_error);
}

TEST(opBuilderHelperRegexNotMatch, TooManyArgumentsError)
{
    Document doc{R"({
        "check":
            {"field": "+r_not_match/regexp/regexp2"}
    })"};

    ASSERT_THROW(bld::opBuilderHelperRegexNotMatch(doc.get("/check"), tr), std::runtime_error);
}

TEST(opBuilderHelperRegexMatch, InvalidRegex)
{
    Document doc{R"({
        "check":
            {"field": "+r_match/(\\w{"}
    })"};

    ASSERT_THROW(bld::opBuilderHelperRegexMatch(doc.get("/check"), tr), std::runtime_error);
}


TEST(opBuilderHelperRegexNotMatch, InvalidSrcType)
{
    Document doc{R"({
        "check":
            {"fieldSrc": "+r_match/\\d+"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // Object
            s.on_next(createSharedEvent(R"(
                {"fieldSrc": { "fieldSrc" : "child value"} }
            )"));
            // Number
            s.on_next(createSharedEvent(R"(
                {"fieldSrc":55}
            )"));
            // Array
            s.on_next(createSharedEvent(R"(
                {"fieldSrc":[123]}
            )"));
            // Not existing field
            s.on_next(createSharedEvent(R"(
                {"field":"fieldSrc not exist"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperRegexNotMatch(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 0);
}

TEST(opBuilderHelperRegexNotMatch, StringRegexMatch)
{
    Document doc{R"({
        "check":
            {"field": "+r_not_match/exp"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field":"value"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"ex-president"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"this is a test exp"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"exp"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperRegexNotMatch(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_FALSE(RE2::PartialMatch(expected[0]->getEvent()->get("/field").GetString(), "exp"));
    ASSERT_FALSE(RE2::PartialMatch(expected[1]->getEvent()->get("/field").GetString(), "exp"));
}

TEST(opBuilderHelperRegexNotMatch, NumericRegexMatch)
{
    Document doc{R"({
        "check":
            {"field": "+r_not_match/123"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field":"1023"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"19"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"0.123"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperRegexNotMatch(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_FALSE(RE2::PartialMatch(expected[0]->getEvent()->get("/field").GetString(), "123"));
    ASSERT_FALSE(RE2::PartialMatch(expected[1]->getEvent()->get("/field").GetString(), "123"));
}

TEST(opBuilderHelperRegexNotMatch, AdvancedRegexMatch)
{
    Document doc{R"~~({
        "check":
            {"field": "+r_not_match/([^ @]+)@([^ @]+)"}
    })~~"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field":"wazuh.com"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"client@wazuh.com"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperRegexNotMatch(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 1);
    ASSERT_FALSE(RE2::PartialMatch(expected[0]->getEvent()->get("/field").GetString(),
                                   "([^ @]+)@([^ @]+)")
    );
}

TEST(opBuilderHelperRegexNotMatch, NestedFieldRegexMatch)
{
    Document doc{R"~~({
        "map":
            {"test/field": "+r_not_match/exp"}
    })~~"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"~~({
            "test":
                {"field": "value"}
            })~~"));
            s.on_next(createSharedEvent(R"~~({
            "test":
                {"field": "ex-president"}
            })~~"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperRegexNotMatch(doc.get("/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_FALSE(RE2::PartialMatch(expected[0]->getEvent()->get("/test/field").GetString(), "exp"));
    ASSERT_FALSE(RE2::PartialMatch(expected[1]->getEvent()->get("/test/field").GetString(), "exp"));
}

TEST(opBuilderHelperRegexNotMatch, FieldNotExistsRegexNotMatch)
{
    Document doc{R"({
        "check":
            {"field2": "+r_not_match/exp"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field2":"value"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"value"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperRegexNotMatch(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 1);
    ASSERT_TRUE(expected[0]->getEvent()->exists("/field2"));
}
