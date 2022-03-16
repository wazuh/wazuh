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

#include "opBuilderHelperMap.hpp"
#include "testUtils.hpp"

using namespace builder::internals::builders;

TEST(opBuilderHelperRegexExtract, Builds)
{
    Document doc{R"({
        "map":
            {"field": "+r_ext/_field/regexp/"}
    })"};

    ASSERT_NO_THROW(opBuilderHelperRegexExtract(doc.get("/map")));
}

TEST(opBuilderHelperRegexExtract, Not_enough_arguments_error)
{
    Document doc{R"({
        "map":
            {"field": "+r_ext/_field/"}
    })"};

    ASSERT_THROW(opBuilderHelperRegexExtract(doc.get("/map")), std::runtime_error);
}

TEST(opBuilderHelperRegexExtract, Too_many_arguments_error)
{
    Document doc{R"({
        "map":
            {"field": "+r_ext/_field/regexp/arg/"}
    })"};

    ASSERT_THROW(opBuilderHelperRegexExtract(doc.get("/map")), std::runtime_error);
}

TEST(opBuilderHelperRegexExtract, String_regex_extract)
{
    Document doc{R"~~({
        "map":
            {"field": "+r_ext/_field/(exp)/"}
    })~~"};

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
            s.on_completed();
        });

    Lifter lift = opBuilderHelperRegexExtract(doc.get("/map"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 3);
    ASSERT_TRUE(RE2::PartialMatch(expected[0]->get("/_field").GetString(), "exp"));
    ASSERT_TRUE(RE2::PartialMatch(expected[1]->get("/_field").GetString(), "exp"));
    ASSERT_TRUE(RE2::PartialMatch(expected[2]->get("/_field").GetString(), "exp"));
}

TEST(opBuilderHelperRegexExtract, Numeric_regex_extract)
{
    Document doc{R"~~({
        "map":
            {"field": "+r_ext/_field/(123)/"}
    })~~"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"123"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"123"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"123"}
            )"));
            s.on_completed();
        });

    Lifter lift = opBuilderHelperRegexExtract(doc.get("/map"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 3);
    ASSERT_TRUE(RE2::PartialMatch(expected[0]->get("/_field").GetString(), "123"));
    ASSERT_TRUE(RE2::PartialMatch(expected[1]->get("/_field").GetString(), "123"));
    ASSERT_TRUE(RE2::PartialMatch(expected[2]->get("/_field").GetString(), "123"));
}

TEST(opBuilderHelperRegexExtract, Advanced_regex_extract)
{
    Document doc{R"~~({
        "map":
            {"field": "+r_ext/_field/(([^ @]+)@([^ @]+))"}
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
            s.on_completed();
        });

    Lifter lift = opBuilderHelperRegexExtract(doc.get("/map"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_TRUE(
        RE2::PartialMatch(expected[0]->get("/_field").GetString(), "client@wazuh.com"));
    ASSERT_TRUE(
        RE2::PartialMatch(expected[1]->get("/_field").GetString(), "engine@wazuh.com"));
}

TEST(opBuilderHelperRegexExtract, Nested_field_regex_extract)
{
    Document doc{R"~~({
        "map":
            {"test/field": "+r_ext/_field/(exp)/"}
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

    Lifter lift = opBuilderHelperRegexExtract(doc.get("/map"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_TRUE(RE2::PartialMatch(expected[0]->get("/_field").GetString(), "exp"));
    ASSERT_TRUE(RE2::PartialMatch(expected[1]->get("/_field").GetString(), "exp"));
}

TEST(opBuilderHelperRegexExtract, Field_not_exists_regex_extract)
{
    Document doc{R"~~({
        "map":
            {"field2": "+r_ext/_field/(exp)/"}
    })~~"};

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
            s.on_completed();
        });

    Lifter lift = opBuilderHelperRegexExtract(doc.get("/map"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 3);
    ASSERT_FALSE(expected[0]->exists("/_field"));
    ASSERT_FALSE(expected[1]->exists("/_field"));
    ASSERT_FALSE(expected[2]->exists("/_field"));
}

TEST(opBuilderHelperRegexExtract, Multilevel_field_regex_extract)
{
    Document doc{R"~~({
        "map":
            {"test.field": "+r_ext/_field/(exp)/"}
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

    Lifter lift = opBuilderHelperRegexExtract(doc.get("/map"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_TRUE(RE2::PartialMatch(expected[0]->get("/_field").GetString(), "exp"));
    ASSERT_TRUE(RE2::PartialMatch(expected[1]->get("/_field").GetString(), "exp"));
}

TEST(opBuilderHelperRegexExtract, Multilevel_field_dst_regex_extract)
{
    Document doc{R"~~({
        "map":
            {"test.field": "+r_ext/parent._field/(exp)/"}
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

    Lifter lift = opBuilderHelperRegexExtract(doc.get("/map"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_TRUE(RE2::PartialMatch(expected[0]->get("/parent/_field").GetString(), "exp"));
    ASSERT_TRUE(RE2::PartialMatch(expected[1]->get("/parent/_field").GetString(), "exp"));
}
