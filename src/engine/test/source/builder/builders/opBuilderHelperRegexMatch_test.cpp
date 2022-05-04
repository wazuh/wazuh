/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <re2/re2.h>
#include <vector>

#include <vector>

#include <baseTypes.hpp>

#include "opBuilderHelperFilter.hpp"
#include "testUtils.hpp"


using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg) {
};

TEST(opBuilderHelperRegexMatch, Builds)
{
    Document doc {R"({
        "check":
            {"field": "+r_match/regexp"}
    })"};
    ASSERT_NO_THROW(bld::opBuilderHelperRegexMatch(doc.get("/check"), tr));
}

TEST(opBuilderHelperRegexMatch, Not_enough_arguments_error)
{
    Document doc {R"({
        "check":
            {"field": "+r_match/"}
    })"};
    ASSERT_THROW(bld::opBuilderHelperRegexMatch(doc.get("/check"), tr), std::invalid_argument);
}

TEST(opBuilderHelperRegexMatch, Too_many_arguments_error)
{
    Document doc {R"({
        "check":
            {"field": "+r_match/regexp/regexp2"}
    })"};
    ASSERT_THROW(bld::opBuilderHelperRegexMatch(doc.get("/check"), tr), std::invalid_argument);
}

TEST(opBuilderHelperRegexMatch, Invalid_regex)
{
    Document doc {R"({
        "check":
            {"field": "+r_match/(\\w{"}
    })"};

    ASSERT_THROW(bld::opBuilderHelperRegexMatch(doc.get("/check"), tr), std::runtime_error);
}

TEST(opBuilderHelperRegexMatch, Invalid_src_type)
{
    Document doc {R"({
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

    Lifter lift = [=](Observable input)
    {
        return input.filter(bld::opBuilderHelperRegexMatch(doc.get("/check"), tr));
    };
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 0);
}

TEST(opBuilderHelperRegexMatch, String_regex_match)
{
    Document doc {R"({
        "check":
            {"field": "+r_match/exp"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field":"exp"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"expregex"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"this is a test exp"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"value"}
            )"));
            s.on_completed();
        });

    Lifter lift = [=](Observable input)
    {
        return input.filter(bld::opBuilderHelperRegexMatch(doc.get("/check"), tr));
    };
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 3);
    ASSERT_TRUE(RE2::PartialMatch(expected[0]->getEvent()->get("/field").GetString(), "exp"));
    ASSERT_TRUE(RE2::PartialMatch(expected[1]->getEvent()->get("/field").GetString(), "exp"));
    ASSERT_TRUE(RE2::PartialMatch(expected[2]->getEvent()->get("/field").GetString(), "exp"));
}

TEST(opBuilderHelperRegexMatch, Numeric_regex_match)
{
    Document doc {R"({
        "check":
            {"field": "+r_match/123"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field":"123"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"123.02"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"10123"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"234"}
            )"));
            s.on_completed();
        });

    Lifter lift = [=](Observable input)
    {
        return input.filter(bld::opBuilderHelperRegexMatch(doc.get("/check"), tr));
    };
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 3);
    ASSERT_TRUE(RE2::PartialMatch(expected[0]->getEvent()->get("/field").GetString(), "123"));
    ASSERT_TRUE(RE2::PartialMatch(expected[1]->getEvent()->get("/field").GetString(), "123"));
    ASSERT_TRUE(RE2::PartialMatch(expected[2]->getEvent()->get("/field").GetString(), "123"));
}

TEST(opBuilderHelperRegexMatch, Advanced_regex_match)
{
    Document doc {R"~~({
        "check":
            {"field": "+r_match/([^ @]+)@([^ @]+)"}
    })~~"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field":"client@wazuh.com"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"engine@wazuh.com"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"wazuh.com"}
            )"));
            s.on_completed();
        });

    Lifter lift = [=](Observable input)
    {
        return input.filter(bld::opBuilderHelperRegexMatch(doc.get("/check"), tr));
    };
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_TRUE(RE2::PartialMatch(expected[0]->getEvent()->get("/field").GetString(),
                                  "([^ @]+)@([^ @]+)"));
    ASSERT_TRUE(RE2::PartialMatch(expected[1]->getEvent()->get("/field").GetString(),
                                  "([^ @]+)@([^ @]+)"));
}

TEST(opBuilderHelperRegexMatch, Nested_field_regex_match)
{
    Document doc {R"~~({
        "check":
            {"test/field": "+r_match/exp"}
    })~~"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"~~({
            "test":
                {"field": "exp"}
            })~~"));
            s.on_next(createSharedEvent(R"~~({
            "test":
                {"field": "this is a test exp"}
            })~~"));
            s.on_completed();
        });

    Lifter lift = [=](Observable input)
    {
        return input.filter(bld::opBuilderHelperRegexMatch(doc.get("/check"), tr));
    };
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_TRUE(RE2::PartialMatch(expected[0]->getEvent()->get("/test/field").GetString(), "exp"));
    ASSERT_TRUE(RE2::PartialMatch(expected[1]->getEvent()->get("/test/field").GetString(), "exp"));
}

TEST(opBuilderHelperRegexMatch, Field_not_exists_regex_match)
{
    Document doc {R"({
        "check":
            {"field2": "+r_match/exp"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field2":"exp"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"exp"}
            )"));
            s.on_completed();
        });

    Lifter lift = [=](Observable input)
    {
        return input.filter(bld::opBuilderHelperRegexMatch(doc.get("/check"), tr));
    };
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 1);
    ASSERT_TRUE(expected[0]->getEvent()->exists("/field2"));
}
