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

#include "opBuilderHelperFilter.hpp"
#include "testUtils.hpp"

using namespace builder::internals::builders;

TEST(opBuilderHelperRegexMatch, Builds)
{
    Document doc{R"({
        "check":
            {"field": "+r_match/regexp"}
    })"};
    ASSERT_NO_THROW(opBuilderHelperRegexMatch(doc.get("/check")));
}

TEST(opBuilderHelperRegexMatch, Not_enough_arguments_error)
{
    Document doc{R"({
        "check":
            {"field": "+r_match/"}
    })"};
    ASSERT_THROW(opBuilderHelperRegexMatch(doc.get("/check")), std::invalid_argument);
}

TEST(opBuilderHelperRegexMatch, Too_many_arguments_error)
{
    Document doc{R"({
        "check":
            {"field": "+r_match/regexp/regexp2"}
    })"};
    ASSERT_THROW(opBuilderHelperRegexMatch(doc.get("/check")), std::invalid_argument);
}

TEST(opBuilderHelperRegexMatch, Invalid_regex)
{
    Document doc{R"({
        "check":
            {"field": "+r_match/(\\w{"}
    })"};

    ASSERT_THROW(opBuilderHelperRegexMatch(doc.get("/check")), std::runtime_error);
}

TEST(opBuilderHelperRegexMatch, Invalid_src_type)
{
    Document doc{R"({
        "check":
            {"fieldSrc": "+r_match/\\d+"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            // Object
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldSrc": { "fieldSrc" : "child value"} }
            )"));
            // Number
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldSrc":55}
            )"));
            // Array
            s.on_next(std::make_shared<json::Document>(R"(
                {"fieldSrc":[123]}
            )"));
            // Not existing field
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"fieldSrc not exist"}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperRegexMatch(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 0);
}

TEST(opBuilderHelperRegexMatch, String_regex_match)
{
    Document doc{R"({
        "check":
            {"field": "+r_match/exp"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"exp"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"expregex"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"this is a test exp"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"value"}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperRegexMatch(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 3);
    ASSERT_TRUE(RE2::PartialMatch(expected[0]->get("/field").GetString(), "exp"));
    ASSERT_TRUE(RE2::PartialMatch(expected[1]->get("/field").GetString(), "exp"));
    ASSERT_TRUE(RE2::PartialMatch(expected[2]->get("/field").GetString(), "exp"));
}

TEST(opBuilderHelperRegexMatch, Numeric_regex_match)
{
    Document doc{R"({
        "check":
            {"field": "+r_match/123"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"123"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"123.02"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"10123"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"234"}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperRegexMatch(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 3);
    ASSERT_TRUE(RE2::PartialMatch(expected[0]->get("/field").GetString(), "123"));
    ASSERT_TRUE(RE2::PartialMatch(expected[1]->get("/field").GetString(), "123"));
    ASSERT_TRUE(RE2::PartialMatch(expected[2]->get("/field").GetString(), "123"));
}

TEST(opBuilderHelperRegexMatch, Advanced_regex_match)
{
    Document doc{R"~~({
        "check":
            {"field": "+r_match/([^ @]+)@([^ @]+)"}
    })~~"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"client@wazuh.com"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"engine@wazuh.com"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"wazuh.com"}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperRegexMatch(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_TRUE(RE2::PartialMatch(expected[0]->get("/field").GetString(),
                                  "([^ @]+)@([^ @]+)"));
    ASSERT_TRUE(RE2::PartialMatch(expected[1]->get("/field").GetString(),
                                  "([^ @]+)@([^ @]+)"));
}

TEST(opBuilderHelperRegexMatch, Nested_field_regex_match)
{
    Document doc{R"~~({
        "map":
            {"test/field": "+r_match/exp"}
    })~~"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"~~({
            "test":
                {"field": "exp"}
            })~~"));
            s.on_next(std::make_shared<json::Document>(R"~~({
            "test":
                {"field": "this is a test exp"}
            })~~"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperRegexMatch(doc.get("/map"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_TRUE(RE2::PartialMatch(expected[0]->get("/test/field").GetString(), "exp"));
    ASSERT_TRUE(RE2::PartialMatch(expected[1]->get("/test/field").GetString(), "exp"));
}

TEST(opBuilderHelperRegexMatch, Field_not_exists_regex_match)
{
    Document doc{R"({
        "check":
            {"field2": "+r_match/exp"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field2":"exp"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"exp"}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperRegexMatch(doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 1);
    ASSERT_TRUE(expected[0]->exists("/field2"));
}
